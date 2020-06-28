import typing
import logging
from concurrent.futures import ThreadPoolExecutor
import asyncio
import os
import zipfile
import tempfile
import base64
import boto3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from shutil import copyfile

# from memory_profiler import profile

logger = logging.getLogger(__name__)


def compress_encrypt_store(
    directory: str, key: str, s3_bucket: str, force: bool
) -> typing.Dict[str, str]:

    # remove the directory separator if it's the last character
    # in the directory name
    directory = (
        directory[: len(directory) - 1]
        if directory.rindex(os.sep) == len(directory) - 1
        else directory
    )

    if not os.path.isdir(directory):
        logger.info(f"{directory} is not a directory. Skipping.")
        return {}

    basename = os.path.basename(directory)

    # create a tmpfile for the zipfile
    _, zipfile_path = tempfile.mkstemp()
    logger.debug(f"Created tmp file {zipfile_path} for zip archive of {directory}")
    # create a tmpfile for the encrypted zipfile
    _, encrypted_file_path = tempfile.mkstemp()
    logger.debug(
        f"Created tmp file {encrypted_file_path} for encrypted "
        + f"zip archive of {directory}"
    )

    try:
        with zipfile.ZipFile(zipfile_path, "w", zipfile.ZIP_DEFLATED) as zipfile_handle:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    zipfile_handle.write(
                        os.path.join(root, file), file,
                    )
                    logger.info(f"Finished creating zip archive for {directory}")

        logger.debug(f"Starting to create encrypted zip file for {encrypted_file_path}")
        encrypt_file(zipfile_path, encrypted_file_path, key)
        logger.info(f"Finished creating encrypted zip file for {directory}")

        logger.debug(
            f"Starting S3 upload of zipped/encrypted {directory} to {s3_bucket}"
        )
        s3_url = store_to_s3(encrypted_file_path, s3_bucket, f"{basename}.zip")
        logger.info(
            f"Finished S3 upload of zipped/encrypted {directory} to {s3_bucket}"
        )

        return {directory: s3_url}
    except Exception as e:
        logger.error(e)
        logger.error(f"Args: directory={directory}, key={key}, s3_bucket={s3_bucket}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)
    finally:
        # remove the tmpfile
        os.remove(zipfile_path)
        logger.debug(f"Removed tmp file for zip archive: {zipfile_path}")
        os.remove(encrypted_file_path)
        logger.debug(
            f"Removed tmp file for encrypted zip archive: {encrypted_file_path}"
        )


def derive_encryption_key(password: str) -> bytes:
    try:
        # salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            # TODO fix salt
            salt=b"12345678912345",
            # salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(bytes(password, "utf-8")))
    except Exception as e:
        logger.error(e)
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def encrypt_file(file_path: str, encrypted_file_path: str, password: str) -> None:
    try:
        encryption_key = derive_encryption_key(password)
        f = Fernet(encryption_key)

        with open(file_path, "rb") as fo:
            plaintext = fo.read()
        enc = f.encrypt(plaintext)

        with open(encrypted_file_path, "wb") as fo:
            fo.write(enc)

        # debugging only
        # decrypt_file(encrypted_file_path, password)
    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: file_path={file_path}, encrypted_file_path={encrypted_file_path}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def decrypt_file(file_path: str, password: str) -> None:
    try:
        encryption_key = derive_encryption_key(password)
        f = Fernet(encryption_key)

        with open(file_path, "rb") as fo:
            ciphertext = fo.read()
        dec = f.decrypt(ciphertext)

        _, cleartext_file_path = tempfile.mkstemp()
        try:
            with open(cleartext_file_path, "wb") as fo:
                fo.write(dec)

            # for debugging only
            copyfile(
                cleartext_file_path, f"testfiles/{os.path.basename(file_path)}_unenc",
            )
        finally:
            # remove the tmpfile
            os.remove(cleartext_file_path)

    except Exception as e:
        logger.error(e)
        logger.error(f"Args: file_path={file_path}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def store_to_s3(encrypted_file_path: str, s3_bucket: str, s3_object_key: str):
    try:
        # TODO - check for existence of the file before overwriting
        # or make the file-name unique

        # need a new session per thread
        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html#multithreading-multiprocessing
        session = boto3.session.Session()
        s3_client = session.client("s3")
        try:
            response = s3_client.upload_file(
                encrypted_file_path, s3_bucket, s3_object_key
            )
            if response is None:
                return f"https://s3.amazonaws.com/{s3_bucket}/{s3_object_key}"
        except boto3.ClientError as e:
            logging.error(e)

        raise Exception("An error occurred during S3 upload.")
    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: encrypted_file_path={encrypted_file_path}, s3_bucket={s3_bucket}"
            + ", s3_object_key={s3_object_key}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


async def s3encrypt_async(
    directories: typing.List[str], key: str, s3_bucket: str, force: bool, timeout: int,
) -> typing.Dict[str, str]:
    """ Async entry point to compress, encrypt and store directories to S3

    Args:
            directories (List[str]): directories

            key (str): the encryption key.

            s3_bucket (str): the S3 bucket for upload

            force (bool): forces existing files to be overwritten in S3

            timeout (int): the timeout (seconds) for S3 uploads

    Returns:
            Dict[str, str]: A dictionary of directory -> S3 object

    """

    if len(directories) == 0 or not key:
        return {}

    final_dict: typing.Dict[str, str] = {}

    try:

        executor = ThreadPoolExecutor(max_workers=5)
        loop = asyncio.get_event_loop()
        blocking_tasks = []

        for directory in directories:

            blocking_tasks.append(
                loop.run_in_executor(
                    executor, compress_encrypt_store, directory, key, s3_bucket, force,
                )
            )

        completed, pending = await asyncio.wait(blocking_tasks, timeout=timeout)
        results = [t.result() for t in completed]
        for r in results:
            for k, v in r.items():
                final_dict[k] = v

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: directories={directories}, key={key}, s3_bucket={s3_bucket}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)

    return final_dict


class S3EncryptError(Exception):
    """Generic exception for the s3encrypt module used to wrap
    exceptions generated by dependencies.
    """

    def __init__(self, msg: str, original_exception: Exception):
        super(S3EncryptError, self).__init__(f"{msg}: {original_exception}")
        self.original_exception = original_exception
