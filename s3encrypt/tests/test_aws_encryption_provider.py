from s3encrypt.aws_encryption_provider import get_master_key_provider, EncrypterError
from unittest import mock
import pytest
import hashlib
from aws_encryption_sdk.internal.crypto import WrappingKey


@mock.patch("s3encrypt.s3encrypt.zipfile.ZipFile")
def test_get_master_key_provider(mock_zipfile):
    key_id = b"some_key___"
    master_key_provider = get_master_key_provider(key_id)
    raw_key = master_key_provider._get_raw_key(key_id)
    assert isinstance(raw_key, WrappingKey)
    assert len(raw_key._wrapping_key) == 32


@mock.patch("s3encrypt.s3encrypt.os.walk")
@mock.patch("s3encrypt.s3encrypt.zipfile.ZipFile")
def test_encrypt_file(mock_zipfile, mock_os_walk):
    pass


"""
def test_encrypt_file():
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
"""

