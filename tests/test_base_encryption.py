import pytest

from s3encrypt.encryption import aws_encryption
from s3encrypt.encryption.base_encryption import FileEncryptDecrypt

def test_aws_encryption():
    class TestBaseEncryption(FileEncryptDecrypt):
        def encrypt_file(self, key: bytes, file_path: str, encrypted_file_path: str) -> None:
            super(TestBaseEncryption, self).encrypt_file(key, file_path, encrypted_file_path)

        def decrypt_file(self, key: bytes, file_path: str, encrypted_file_path: str) -> None:
            super(TestBaseEncryption, self).decrypt_file(key, file_path, encrypted_file_path)

    tbe = TestBaseEncryption()

    with pytest.raises(NotImplementedError):        
        tbe.encrypt_file(b'','','')
    
    with pytest.raises(NotImplementedError):        
        tbe.decrypt_file(b'','','')