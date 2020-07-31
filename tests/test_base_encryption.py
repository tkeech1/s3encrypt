import pytest

from s3encrypt.encryption import aws_encryption
from s3encrypt.encryption.base_encryption import FileEncryptDecrypt

def test_aws_encryption():
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