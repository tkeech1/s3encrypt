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
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# from memory_profiler import profile

logger = logging.getLogger(__name__)


def compress_encrypt_store(
    directory: str, key: str, salt: str, s3_bucket: str, force: bool
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
        encrypt_file(
            compressed_file_path, encrypted_file_path, key, bytes(salt, "utf-8"),
        )
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
        # remove the tmpfile
        os.remove(compressed_file_path)
        logger.debug(f"Removed tmp file for compressed archive: {compressed_file_path}")
        os.remove(encrypted_file_path)
        logger.debug(
            f"Removed tmp file for encrypted compressed archive: {encrypted_file_path}"
        )


def validate_directory(directory: str) -> str:
    # remove the directory separator if it's the last character
    # in the directory name
    directory = (
        directory[: len(directory) - 1]
        if directory.rindex(os.sep) == len(directory) - 1
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
                    print(f"{file}\n")
                    zipfile_handle.write(
                        os.path.join(root, file), file,
                    )
                    logger.info(f"Finished creating compressed archive for {directory}")

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: directory={directory}, compressed_file_path={compressed_file_path}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def encrypt_file(file_path: str, encrypted_file_path: str, key: str, salt: bytes):
    try:
        plaintext = read_file_content(file_path)
        ciphertext = encrypt(plaintext, key, salt)
        write_file(ciphertext, encrypted_file_path)

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: file_path={file_path}, "
            + f"encrypted_file_path={encrypted_file_path}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def derive_encryption_key(
    password: str, salt: bytes = None
) -> typing.Tuple[bytes, bytes]:
    try:
        salt = os.urandom(16) if salt is None else salt

        kdf = pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return (
            base64.urlsafe_b64encode(kdf.derive(bytes(password, "utf-8"))),
            salt,
        )
    except Exception as e:
        logger.error(e)
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def read_file_content(file_path: str) -> bytes:
    try:
        file_content = b""
        with open(file_path, "rb") as fo:
            file_content = fo.read()

        return file_content
    except Exception as e:
        logger.error(e)
        logger.error(f"Args: file_path={file_path}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def write_file(content: bytes, file_path: str):
    try:
        with open(file_path, "wb") as fo:
            fo.write(content)

    except Exception as e:
        logger.error(e)
        logger.error(f"Args: file_path={file_path}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def encrypt(plaintext: bytes, password: str, salt: bytes) -> bytes:
    try:
        encryption_key, _ = derive_encryption_key(password, salt)
        f = Fernet(encryption_key)
        encrypted_content = f.encrypt(plaintext)

        return encrypted_content

    except Exception as e:
        logger.error(e)
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def decrypt(ciphertext: bytes, password: str, salt: bytes) -> bytes:
    try:
        encryption_key, _ = derive_encryption_key(password, salt)
        f = Fernet(encryption_key)
        decrypted_bytes = f.decrypt(ciphertext)

        return decrypted_bytes
    except Exception as e:
        logger.error(e)
        raise S3EncryptError(" s3encrypt encountered an error ", e)


def store_to_s3(file_path: str, s3_bucket: str, s3_object_key: str):
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
        except boto3.ClientError as e:
            logging.error(e)

        raise Exception("An error occurred during S3 upload.")
    except Exception as e:
        logger.error(e)
        logger.error(
            f"Args: encrypted_file_path={file_path}, s3_bucket={s3_bucket}"
            + ", s3_object_key={s3_object_key}"
        )
        raise S3EncryptError(" s3encrypt encountered an error ", e)


async def s3encrypt_async(
    directories: typing.List[str],
    key: str,
    salt: str,
    s3_bucket: str,
    force: bool,
    timeout: int,
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
                    executor,
                    compress_encrypt_store,
                    directory,
                    key,
                    salt,
                    s3_bucket,
                    force,
                )
            )

        completed, pending = await asyncio.wait(blocking_tasks, timeout=timeout)
        results = [t.result() for t in completed]
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
