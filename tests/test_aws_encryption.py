from s3encrypt.encryption.aws_encryption import AWSEncryption
from s3encrypt.encryption.base_encryption import EncryptionError
from unittest import mock
import pytest  # type: ignore
from aws_encryption_sdk.internal.crypto import WrappingKey


@mock.patch("s3encrypt.s3encrypt.zipfile.ZipFile")
def test_get_master_key_provider(mock_zipfile: mock.Mock) -> None:
    aws_encryption = AWSEncryption()
    key_id = b"some_key___"
    master_key_provider = aws_encryption.get_master_key_provider(key_id)
    raw_key = master_key_provider._get_raw_key(key_id)
    assert isinstance(raw_key, WrappingKey)
    assert len(raw_key._wrapping_key) == 32


@mock.patch("s3encrypt.encryption.aws_encryption.aws_encryption_sdk.stream")
def test_encrypt_file(mock_stream: mock.Mock) -> None:
    aws_encryption = AWSEncryption()
    mock_stream.return_value.__enter__.return_value = ["text to write"]
    mock_open = mock.mock_open()
    mock_write = mock.mock_open(read_data="Data2").return_value
    mock_open.side_effect = [
        mock.mock_open(read_data="Data1").return_value,
        mock_write,
    ]
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open) as m:
        aws_encryption.encrypt_file(b"bytes", "somepath", "someotherpath")
        calls = [mock.call("somepath", "rb"), mock.call("someotherpath", "wb")]
        m.assert_has_calls(calls)
        mock_write.write.assert_called_once_with("text to write")

    mock_open.side_effect = Exception("exception")
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            aws_encryption.encrypt_file(b"bytes", "somepath", "someotherpath")
            assert isinstance(exception_info.value, EncrypterError)


@mock.patch("s3encrypt.encryption.aws_encryption.aws_encryption_sdk.stream")
def test_decrypt_file(mock_stream: mock.Mock) -> None:
    aws_encryption = AWSEncryption()
    mock_stream.return_value.__enter__.return_value = ["text to write"]
    mock_open = mock.mock_open()
    mock_write = mock.mock_open(read_data="Data2").return_value
    mock_open.side_effect = [
        mock.mock_open(read_data="Data1").return_value,
        mock_write,
    ]
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open) as m:
        aws_encryption.decrypt_file(b"bytes", "somepath", "someotherpath")
        calls = [mock.call("somepath", "rb"), mock.call("someotherpath", "wb")]
        m.assert_has_calls(calls)
        mock_write.write.assert_called_once_with("text to write")

    mock_open.side_effect = Exception("exception")
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            aws_encryption.decrypt_file(b"bytes", "somepath", "someotherpath")
            assert isinstance(exception_info.value, EncrypterError)
