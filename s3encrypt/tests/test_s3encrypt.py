""" Tests for s3encrypt """
from s3encrypt.s3encrypt import (
    derive_encryption_key,
    read_file_content,
    S3EncryptError,
    write_file,
    encrypt,
    decrypt,
    validate_directory,
)

# from unittest.mock import patch
from unittest import mock
import pytest


def test_validate_directory():
    with mock.patch("s3encrypt.s3encrypt.os") as mock_os:
        mock_os.sep = "-"
        mock_os.path.isdir.return_value = True
        assert "-somedir-somedir2" == validate_directory("-somedir-somedir2-")

        mock_os.path.isdir.return_value = False
        with pytest.raises(Exception) as exception_info:
            validate_directory("-somedir-somedir2-")
            assert isinstance(exception_info.value, S3EncryptError)


def test_derive_encryption_key():
    encryption_key, salt = derive_encryption_key("12345", b"12345678912345")
    assert b"pPn6MD9woGq6yuE7Q2pO2kVaBHpDMG8tUtC8NZSQdW8=" == encryption_key

    with mock.patch("s3encrypt.s3encrypt.os") as mock_os:
        mock_os.urandom.side_effect = Exception("exception")
        with pytest.raises(Exception) as exception_info:
            derive_encryption_key("12345")
            assert isinstance(exception_info.value, S3EncryptError)


def test_get_file_content():
    mock_open = mock.mock_open(read_data="data data data")
    with mock.patch("builtins.open", mock_open):
        result = read_file_content("filename")
    assert "data data data" == result

    mock_open.side_effect = Exception("exception")
    with mock.patch("builtins.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            result = read_file_content("filename")
            assert isinstance(exception_info.value, S3EncryptError)


def test_write_file():
    mock_open = mock.mock_open(read_data="data data data")
    with mock.patch("builtins.open", mock_open) as m:
        write_file(b"some file content", "some_file_path")
        m.assert_called_once_with("some_file_path", "wb")
        handle = m()
        handle.write.assert_called_with(b"some file content")

    mock_open.side_effect = Exception("exception")
    with mock.patch("builtins.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            write_file(b"some file content", "some_file_path")
            assert isinstance(exception_info.value, S3EncryptError)


def test_encrypt():
    content = b"12345"
    password = "password"
    salt = b"12345678912345"
    ciphertext = encrypt(content, password, salt)
    decrypted_content = decrypt(ciphertext, password, salt)
    assert content == decrypted_content

    with mock.patch("s3encrypt.s3encrypt.derive_encryption_key"):
        with pytest.raises(Exception) as exception_info:
            ciphertext = encrypt(content, password, salt)
            assert isinstance(exception_info.value, S3EncryptError)

    with mock.patch("s3encrypt.s3encrypt.derive_encryption_key"):
        with pytest.raises(Exception) as exception_info:
            ciphertext = decrypt(ciphertext, password, salt)
            assert isinstance(exception_info.value, S3EncryptError)
