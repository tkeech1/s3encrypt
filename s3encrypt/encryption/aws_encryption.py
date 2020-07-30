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


class AWSEncryption(FileEncryptDecrypt):
    def get_master_key_provider(self, key_id: bytes) -> RawMasterKeyProvider:
        master_key_provider = StaticRandomMasterKeyProvider()
        master_key_provider.add_master_key(key_id)
        return master_key_provider

    def encrypt_file(
        self, key: bytes, file_path: str, encrypted_file_path: str
    ) -> None:
        try:
            master_key_provider = self.get_master_key_provider(key)
            with open(file_path, "rb") as plaintext, open(
                encrypted_file_path, "wb"
            ) as ciphertext:
                with aws_encryption_sdk.stream(
                    mode="e", source=plaintext, key_provider=master_key_provider
                ) as encryptor:
                    for index, chunk in enumerate(encryptor):
                        ciphertext.write(chunk)
                        logger.info(f"Wrote chunk {index}")

        except Exception as e:
            logger.error(e)
            logger.error(
                f"Args: file_path={file_path}, "
                + f"encrypted_file_path={encrypted_file_path}"
            )
            raise EncryptionError(" s3encrypt.encryption encountered an error ", e)

    def decrypt_file(
        self, key: bytes, file_path: str, decrypted_file_path: str
    ) -> None:
        try:
            master_key_provider = self.get_master_key_provider(key)
            with open(file_path, "rb") as ciphertext, open(
                decrypted_file_path, "wb"
            ) as plaintext:
                with aws_encryption_sdk.stream(
                    mode="d", source=ciphertext, key_provider=master_key_provider
                ) as decryptor:
                    for chunk in decryptor:
                        plaintext.write(chunk)

        except Exception as e:
            logger.error(e)
            logger.error(
                f"Args: file_path={file_path}, "
                + f"decrypted_file_path={decrypted_file_path}"
            )
            raise EncryptionError(" s3encrypt.encryption encountered an error ", e)
