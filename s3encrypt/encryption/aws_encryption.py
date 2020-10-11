# needed for annotations for StaticRandomMasterKeyProvider
from __future__ import annotations
import logging
import aws_encryption_sdk
import hashlib
import typing
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
from s3encrypt.encryption.base_encryption import EncryptionError, FileEncryptDecrypt

logger = logging.getLogger(__name__)


class StaticRandomMasterKeyProvider(RawMasterKeyProvider):  # type: ignore
    """Randomly and consistently generates 256-bit keys for each unique key ID."""

    provider_id: str = "static"

    def __init__(self: StaticRandomMasterKeyProvider) -> None:
        self._static_keys: typing.Dict[bytes, bytes] = {}

    def _get_raw_key(self: StaticRandomMasterKeyProvider, key_id: bytes) -> WrappingKey:
        try:
            static_key = self._static_keys[key_id]
        except KeyError:
            static_key = hashlib.sha256(key_id).digest()
            self._static_keys[key_id] = static_key

        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def get_master_key_provider(key_id: bytes) -> RawMasterKeyProvider:
    master_key_provider = StaticRandomMasterKeyProvider()
    master_key_provider.add_master_key(key_id)
    return master_key_provider


class AWSEncryptionService(FileEncryptDecrypt):
    def __init__(self, key: bytes, input_file_path: str, output_file_path: str):
        self.key = key
        self.input_file_path = input_file_path
        self.output_file_path = output_file_path

    def __encrypt_decrypt_file(self, mode: str) -> None:
        try:
            master_key_provider = get_master_key_provider(self.key)
            with open(self.input_file_path, "rb") as input_text, open(
                self.output_file_path, "wb"
            ) as output_text:
                with aws_encryption_sdk.stream(
                    mode=mode, source=input_text, key_provider=master_key_provider
                ) as encryptor_decryptor:
                    for index, chunk in enumerate(encryptor_decryptor):
                        output_text.write(chunk)
                        logger.debug(f"Wrote chunk {index}")

        except Exception as e:
            logger.error(e)
            logger.error(
                f"Args: input_file_path={self.input_file_path}, "
                + f"output_file_path={self.output_file_path}"
            )
            raise EncryptionError(" s3encrypt.encryption encountered an error ", e)

    def decrypt_file(self) -> None:
        self.__encrypt_decrypt_file("d")

    def encrypt_file(self) -> None:
        # logger.info("sleeping in encrypt_file for 500...")
        # time.sleep(500)
        # logger.info("done sleeping")
        self.__encrypt_decrypt_file("e")


class AWSEncryptionServiceBuilder:
    def __call__(
        self,
        key_bytes: bytes,
        input_file_path: str,
        output_file_path: str,
        **_ignore: typing.Dict[str, typing.Any],
    ) -> AWSEncryptionService:
        return AWSEncryptionService(key_bytes, input_file_path, output_file_path)
