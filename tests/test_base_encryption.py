import pytest

from s3encrypt.encryption.base_encryption import (
    FileEncryptDecrypt,
    FileEncryptDecryptFactory,
)
from s3encrypt.encryption.aws_encryption import AWSEncryption


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


def test_get_encryption() -> None:
    encryption_factory = FileEncryptDecryptFactory(b"", "", "")
    encryption_factory.register_encryption_method("aws", AWSEncryption)
    encryption = encryption_factory.get_encryption("aws")
    assert isinstance(encryption, AWSEncryption)

    with pytest.raises(ValueError):
        encryption_factory.get_encryption("blah")
