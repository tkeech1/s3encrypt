import typing
import logging
import asyncio
import os
import zipfile
import hashlib
import boto3
import botocore
from s3encrypt.encryption.aws_encryption import AWSEncryptionServiceBuilder
from s3encrypt.encryption.base_encryption import EncryptionFactory

from s3encrypt.temp_file import TempFile

logger = logging.getLogger(__name__)

encryption_factory = EncryptionFactory()
encryption_factory.register_builder("aws-local", AWSEncryptionServiceBuilder())


@profile
async def compress_encrypt_store(
    directory: str,
    password: str,
    s3_bucket: str,
    loop: typing.Any,
    executor: typing.Any,
) -> typing.Dict[str, str]:
    """Compresses, encrypts and stores a directory to S3

    Args:
            directory (str): the directory to compress, ecnrypt and strore

            password (str): the password used to generate the encryption key

            s3_bucket (str): the S3 bucket for upload

    Returns:
            Dict[str, str]: A dictionary of directory -> S3 object

    """

    try:
        directory = await loop.run_in_executor(executor, validate_directory, directory)
    except S3EncryptError:
        logger.info(f"{directory} is not a valid directory. Skipping.")
        return {}

    try:

        # create a tmpfile for the compressed file
        with TempFile() as compressed_file:
            compressed_file_path = compressed_file.temp_file_path
            logger.debug(
                f"Created tmp file {compressed_file_path} for compressed "
                + f"archive of {directory}"
            )

            # create a tmpfile for the encrypted compressed file
            with TempFile() as encrypted_file:
                encrypted_file_path = encrypted_file.temp_file_path
                logger.debug(
                    f"Created tmp file {encrypted_file_path} for encrypted "
                    + f"compressed archive of {directory}"
                )
                logger.debug(
                    f"Starting to create compressed file for {directory}"
                    + f" at {compressed_file_path}"
                )
                await loop.run_in_executor(
                    executor, compress_directory, directory, compressed_file_path
                )
                logger.debug(
                    f"Finished creating compressed file for {directory}"
                    + f" at {compressed_file_path}"
                )

                logger.debug(
                    f"Starting to create encrypted file for {directory} at "
                    + f"{encrypted_file_path}"
                )

                key_bytes = hashlib.sha256(bytes(password, "utf-8")).digest()

                config: typing.Dict[str, typing.Any] = {
                    "key_bytes": key_bytes,
                    "input_file_path": compressed_file_path,
                    "output_file_path": encrypted_file_path,
                }
                # object factory
                encryption = encryption_factory.create(key="aws-local", **config)
                await loop.run_in_executor(executor, encryption.encrypt_file)
                logger.info(
                    f"Finished creating encrypted file "
                    f"for {directory} at {encrypted_file_path}"
                )

                logger.debug(
                    f"Starting S3 upload of compressed/encrypted "
                    f"{directory} to {s3_bucket}",
                )
                s3_url = await loop.run_in_executor(
                    executor,
                    store_to_s3,
                    encrypted_file_path,
                    s3_bucket,
                    f"{os.path.basename(directory)}.zip.enc",
                )
                logger.info(
                    f"Finished S3 upload of compressed/encrypted "
                    f"{directory} to {s3_bucket}",
                )

        shutdown_event.set()
        return {directory: s3_url}

    except Exception as e:
        logger.error(e)
        logger.error(f"Args: directory={directory}, s3_bucket={s3_bucket}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)


@profile
def validate_directory(directory: str) -> str:
    # remove the directory separator if it's the last character
    # in the directory name
    directory = (
        directory[: len(directory) - 1]
        if os.sep in directory and directory.rindex(os.sep) == len(directory) - 1
        else directory
    )

    if not os.path.isdir(directory):
        raise S3EncryptError(f" {directory} is not a valid directory ")

    return directory


@profile
def compress_directory(directory: str, compressed_file_path: str) -> None:
    try:

        with zipfile.ZipFile(
            compressed_file_path, "w", zipfile.ZIP_DEFLATED
        ) as zipfile_handle:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    zipfile_handle.write(os.path.join(root, file))
                    logger.info(f"Finished creating compressed archive for {directory}")

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: directory={directory}, compressed_file_path={compressed_file_path}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


@profile
def store_to_s3(file_path: str, s3_bucket: str, s3_object_key: str) -> str:
    try:

        # TODO - check for existence of the file before overwriting
        # or make the file-name unique

        # must use a new session per thread
        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html#multithreading-multiprocessing
        session = boto3.session.Session()
        s3_client = session.client("s3")
        try:
            response = s3_client.upload_file(file_path, s3_bucket, s3_object_key)
            if response is None:
                return f"https://s3.amazonaws.com/{s3_bucket}/{s3_object_key}"
        except botocore.exceptions.ClientError as e:
            logging.error(e)
            raise e

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: encrypted_file_path={file_path}, s3_bucket={s3_bucket}"
            + ", s3_object_key={s3_object_key}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)

    raise S3EncryptError(
        " s3encrypt encountered an error ",
        Exception(
            f"Error: file path: {file_path}, bucket: {s3_bucket}, "
            + "s3_object_key: {s3_object_key}; S3 response was {response}"
        ),
    )


class S3EncryptError(Exception):
    """Generic exception for the s3encrypt module used to wrap
    exceptions generated by dependencies.
    """

    def __init__(self, msg: str, original_exception: Exception = Exception()):
        super(S3EncryptError, self).__init__(f"{msg}: {original_exception}")
        self.original_exception = original_exception


if __name__ == "__main__":

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Z %Y-%m-%d %H:%M:%S",
    )

    # log to console
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    import s3encrypt.async_helper as async_helper
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as executor:
        try:

            shutdown_event = asyncio.Event()
            loop = async_helper.get_loop(shutdown_event, executor)

            loop.create_task(async_helper.shutdown(shutdown_event, loop, executor))

            loop.create_task(
                compress_encrypt_store(
                    "testfiles/testzip", "12345", "tdk-bd-keep.io", loop, executor,
                )
            )

            loop.run_forever()

        finally:
            loop.close()

