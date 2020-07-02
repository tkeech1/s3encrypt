import boto3
import tempfile
import os
import zipfile
import shutil
import logging
from s3encrypt.s3encrypt import (
    compress_encrypt_store,
    write_file,
    compress_directory,
    read_file_content,
    decrypt,
)

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
    tmp_extract_dir_path = tempfile.mkdtemp()
    _, tmp_file_path = tempfile.mkstemp(dir=tmp_dir_path)
    _, tmp_encrypted_file = tempfile.mkstemp()
    _, tmp_unencrypted_file = tempfile.mkstemp()

    key = "12345"
    salt = "mysalt"
    bucket = "tdk-bd-keep.io"
    test_file_content = b"test content"

    try:

        # compress, encrypt and store in S3
        write_file(test_file_content, tmp_file_path)
        logger.info(f"Created tmp file")
        compress_encrypt_store(tmp_dir_path, key, salt, bucket, True)
        logger.info(f"Compressed, encrypted and uploaded to {bucket}")

        # verify the file
        session = boto3.session.Session()
        s3_client = session.client("s3")
        s3_client.download_file(
            bucket, f"{os.path.basename(tmp_dir_path)}.zip.enc", tmp_encrypted_file
        )
        logger.info(f"Downloaded encrypted file from {bucket}")

        ciphertext = read_file_content(tmp_encrypted_file)
        plaintext = decrypt(ciphertext, key, bytes(salt, "utf-8"))
        write_file(plaintext, tmp_unencrypted_file)

        with zipfile.ZipFile(tmp_unencrypted_file, "r") as zip_ref:
            zip_ref.extractall(tmp_extract_dir_path)

        logger.info(f"Decrypted and unzipped file")

        assert test_file_content == read_file_content(
            f"{tmp_extract_dir_path}{os.sep}{os.path.basename(tmp_file_path)}"
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


if __name__ == "__main__":
    e2e()
