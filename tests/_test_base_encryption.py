import pytest
import typing


from s3encrypt.encryption.base_encryption import (
    FileEncryptDecrypt,
    EncryptionFactory,
)
from s3encrypt.encryption.aws_encryption import (
    AWSEncryptionService,
    AWSEncryptionServiceBuilder,
)


def test_aws_encryption() -> None:
    class TestBaseEncryption(FileEncryptDecrypt):
        def encrypt_file(self) -> None:
            super(TestBaseEncryption, self).encrypt_file()

        def decrypt_file(self) -> None:
            super(TestBaseEncryption, self).decrypt_file()

    tbe = TestBaseEncryption()

    with pytest.raises(NotImplementedError):
        tbe.encrypt_file()

    with pytest.raises(NotImplementedError):
        tbe.decrypt_file()


def test_object_factory() -> None:
    encryption_factory = EncryptionFactory()
    encryption_factory.register_builder("aws", AWSEncryptionServiceBuilder())
    config: typing.Dict[str, typing.Any] = {
        "key_bytes": b"",
        "input_file_path": "compressed_file_path",
        "output_file_path": "encrypted_file_path",
    }
    encryption = encryption_factory.create(key="aws", **config)
    assert isinstance(encryption, AWSEncryptionService)

    with pytest.raises(ValueError):
        encryption_factory.create("blah")
