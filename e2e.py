import boto3
import tempfile
import os
import zipfile
import shutil
import logging
import hashlib
from s3encrypt.encryption.aws_encryption import AWSEncryptionServiceBuilder
from s3encrypt.encryption.base_encryption import EncryptionFactory
from s3encrypt.s3encrypt import encrypt_store

logger = logging.getLogger(__package__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    fmt="%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Z %Y-%m-%d %H:%M:%S",
)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)


def e2e():

    tmp_dir_path = tempfile.mkdtemp()
    tmp_subdir_path = tempfile.mkdtemp(dir=tmp_dir_path)
    _, tmp_file_path = tempfile.mkstemp(dir=tmp_subdir_path)

    # test directory structure
    # - DIR
    #   - SUBDIR
    #     - TMPFILE

    tmp_extract_dir_path = tempfile.mkdtemp()
    _, tmp_encrypted_file = tempfile.mkstemp()
    _, tmp_unencrypted_file = tempfile.mkstemp()

    key = "12345"
    bucket = "tdk-bd-keep.io"
    test_file_content = b"test content"

    session = boto3.session.Session()
    s3_client = session.client("s3")

    try:

        # compress, encrypt and store in S3
        write_file(test_file_content, tmp_file_path)
        logger.info(f"Created tmp file")
        # with ThreadPoolExecutor(max_workers=1) as executor:
        #    shutdown_event = asyncio.Event()
        #    loop = get_loop(shutdown_event, executor)
        #    await compress_encrypt_store(tmp_dir_path, key, bucket, loop, executor)
        encrypt_store([tmp_dir_path], "store", key, bucket)

        logger.info(f"Compressed, encrypted and uploaded to {bucket}")

        # verify the file
        s3_client.download_file(
            bucket, f"{os.path.basename(tmp_dir_path)}.zip.enc", tmp_encrypted_file
        )
        logger.info(f"Downloaded encrypted file from {bucket}")

        key_bytes = hashlib.sha256(bytes(key, "utf-8")).digest()
        encryption_factory = EncryptionFactory()
        encryption_factory.register_builder("aws", AWSEncryptionServiceBuilder())
        config = {
            "key_bytes": key_bytes,
            "input_file_path": tmp_encrypted_file,
            "output_file_path": tmp_unencrypted_file,
        }
        encryption = encryption_factory.create(key="aws", **config)

        encryption.decrypt_file()

        with zipfile.ZipFile(tmp_unencrypted_file, "r") as zip_ref:
            zip_ref.extractall(tmp_extract_dir_path)

        logger.info(f"Decrypted and unzipped file")

        assert test_file_content == read_file_content(
            f"{tmp_extract_dir_path}{os.sep}{tmp_subdir_path}{os.sep}"
            f"{os.path.basename(tmp_file_path)}"
        )
        logger.info(f"Original contents match")

        logger.info(f"e2e test completed")

    finally:
        os.remove(tmp_file_path)
        shutil.rmtree(tmp_dir_path)
        shutil.rmtree(tmp_extract_dir_path)
        os.remove(tmp_encrypted_file)
        os.remove(tmp_unencrypted_file)

        # remove the file from S3
        s3_client.delete_object(
            Bucket=bucket, Key=f"{os.path.basename(tmp_dir_path)}.zip.enc"
        )


def write_file(content: bytes, file_path: str):
    with open(file_path, "wb") as fo:
        fo.write(content)


def read_file_content(file_path: str) -> bytes:
    file_content = b""
    with open(file_path, "rb") as fo:
        file_content = fo.read()

    return file_content


if __name__ == "__main__":
    #asyncio.run(e2e())
    e2e()
