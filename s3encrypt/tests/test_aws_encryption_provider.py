from s3encrypt.aws_encryption_provider import (
    get_master_key_provider,
    EncrypterError,
    encrypt_file,
)
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


@mock.patch("s3encrypt.aws_encryption_provider.aws_encryption_sdk.stream")
def test_encrypt_file(mock_stream):
    mock_stream.return_value.__enter__.return_value = ["text to write"]
    mock_open = mock.mock_open()
    mock_write = mock.mock_open(read_data="Data2").return_value
    mock_open.side_effect = [
        mock.mock_open(read_data="Data1").return_value,
        mock_write,
    ]
    with mock.patch("builtins.open", mock_open) as m:
        encrypt_file(b"bytes", "somepath", "someotherpath")
        calls = [mock.call("somepath", "rb"), mock.call("someotherpath", "wb")]
        m.assert_has_calls(calls)
        mock_write.write.assert_called_once_with("text to write")

    mock_open.side_effect = Exception("exception")
    with mock.patch("builtins.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            encrypt_file(b"bytes", "somepath", "someotherpath")
            assert isinstance(exception_info.value, EncrypterError)


"""
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

