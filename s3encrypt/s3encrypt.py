import typing
import logging
from concurrent.futures import ThreadPoolExecutor
import asyncio
import os
import zipfile
import tempfile
import hashlib
import boto3
import botocore
from s3encrypt.aws_encryption_provider import encrypt_file

# from memory_profiler import profile

logger = logging.getLogger(__name__)


def compress_encrypt_store(
    directory: str, password: str, s3_bucket: str, force: bool
) -> typing.Dict[str, str]:

    try:
        directory = validate_directory(directory)
    except S3EncryptError:
        logger.info(f"{directory} is not a valid directory. Skipping.")
        return {}

    try:
        # create a tmpfile for the compressed file
        _, compressed_file_path = tempfile.mkstemp()
        logger.debug(
            f"Created tmp file {compressed_file_path} for compressed "
            + "archive of {directory}"
        )
        # create a tmpfile for the encrypted compressed file
        _, encrypted_file_path = tempfile.mkstemp()
        logger.debug(
            f"Created tmp file {encrypted_file_path} for encrypted "
            + f"compressed archive of {directory}"
        )

        logger.debug(
            f"Starting to create compressed file for {directory}"
            + f" at {compressed_file_path}"
        )
        compress_directory(directory, compressed_file_path)
        logger.debug(
            f"Finished creating compressed file for {directory}"
            + f" at {compressed_file_path}"
        )

        logger.debug(
            f"Starting to create encrypted file for {directory} at "
            + f"{encrypted_file_path}"
        )

        key_bytes = hashlib.sha256(bytes(password, "utf-8")).digest()
        encrypt_file(key_bytes, compressed_file_path, encrypted_file_path)
        logger.info(
            f"Finished creating encrypted file for {directory} at {encrypted_file_path}"
        )

        logger.debug(
            f"Starting S3 upload of compressed/encrypted {directory} to {s3_bucket}"
        )
        s3_url = store_to_s3(
            encrypted_file_path, s3_bucket, f"{os.path.basename(directory)}.zip.enc",
        )
        logger.info(
            f"Finished S3 upload of compressed/encrypted {directory} to {s3_bucket}"
        )
        return {directory: s3_url}
    except Exception as e:
        logger.error(e)
        logger.error(f"Args: directory={directory}, s3_bucket={s3_bucket}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)
    finally:
        try:
            # remove the tmpfile
            os.remove(compressed_file_path)
            logger.debug(
                f"Removed tmp file for compressed archive: {compressed_file_path}"
            )
            os.remove(encrypted_file_path)
            logger.debug(
                "Removed tmp file for encrypted compressed archive: ",
                f"{encrypted_file_path}",
            )
        except Exception as e:
            logger.debug(f"An exception occurred removing a tmp file: {e}")
            raise S3EncryptError(" s3encrypt encountered an error ", e)


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


async def s3encrypt_async(
    directories: typing.List[str],
    password: str,
    s3_bucket: str,
    force: bool,
    timeout: int,
) -> typing.Dict[str, str]:
    """ Async entry point to compress, encrypt and store directories to S3

    Args:
            directories (List[str]): directories

            password (str): the password used to generate the encryption key.

            s3_bucket (str): the S3 bucket for upload

            force (bool): forces existing files to be overwritten in S3

            timeout (int): the timeout (seconds) for S3 uploads

    Returns:
            Dict[str, str]: A dictionary of directory -> S3 object

    """

    if len(directories) == 0 or not password:
        return {}

    final_dict: typing.Dict[str, str] = {}

    try:

        loop = asyncio.get_event_loop()
        blocking_tasks = []

        # uses a pool worker threads to execute calls asynchronously
        # each in a separate thread
        with ThreadPoolExecutor() as executor:
            for directory in directories:
                blocking_tasks.append(
                    loop.run_in_executor(
                        executor,
                        compress_encrypt_store,
                        directory,
                        password,
                        s3_bucket,
                        force,
                    )
                )
            results = await asyncio.gather(*blocking_tasks, return_exceptions=True)

        for r in results:
            for k, v in r.items():
                final_dict[k] = v

    except Exception as e:
        logger.error(e)
        logger.error(f"Args: directories={directories}, s3_bucket={s3_bucket}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)

    return final_dict


class S3EncryptError(Exception):
    """Generic exception for the s3encrypt module used to wrap
    exceptions generated by dependencies.
    """

    def __init__(self, msg: str, original_exception: Exception = None):
        super(S3EncryptError, self).__init__(f"{msg}: {original_exception}")
        self.original_exception = original_exception
