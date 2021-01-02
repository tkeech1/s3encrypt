import typing
from s3encrypt.encryption.aws_encryption import (
    AWSEncryptionServiceBuilder,
    get_master_key_provider,
)
from s3encrypt.encryption.base_encryption import EncryptionError, EncryptionFactory
from unittest import mock
import pytest  # type: ignore
from aws_encryption_sdk.internal.crypto import WrappingKey


@mock.patch("s3encrypt.s3encrypt.zipfile.ZipFile")
def test_get_master_key_provider(mock_zipfile: mock.Mock) -> None:
    key_id = b"some_key___"
    master_key_provider = get_master_key_provider(key_id)
    raw_key = master_key_provider._get_raw_key(key_id)
    assert isinstance(raw_key, WrappingKey)
    assert len(raw_key._wrapping_key) == 32


@mock.patch(
    "s3encrypt.encryption.aws_encryption.aws_encryption_sdk.EncryptionSDKClient"
)
def test_encrypt_decrypt_file(mock_stream: mock.Mock) -> None:

    encryption_factory = EncryptionFactory()
    encryption_factory.register_builder("aws", AWSEncryptionServiceBuilder())
    config: typing.Dict[str, typing.Any] = {
        "key_bytes": b"bytes",
        "input_file_path": "somepath",
        "output_file_path": "someotherpath",
    }
    aws_encryption = encryption_factory.create(key="aws", **config)

    mock_stream.return_value.stream.return_value.__enter__.return_value = [
        "text to write"
    ]
    mock_open = mock.mock_open()
    mock_write = mock.mock_open(read_data="Data2").return_value
    mock_open.side_effect = [
        mock.mock_open(read_data="Data1").return_value,
        mock_write,
    ]
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open) as m:
        aws_encryption.encrypt_file()
        calls = [mock.call("somepath", "rb"), mock.call("someotherpath", "wb")]
        m.assert_has_calls(calls)
        mock_write.write.assert_called_once_with("text to write")

    mock_open.side_effect = Exception("exception")
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            aws_encryption.encrypt_file()
            assert isinstance(exception_info.value, EncryptionError)


@mock.patch(
    "s3encrypt.encryption.aws_encryption.aws_encryption_sdk.EncryptionSDKClient"
)
def test_decrypt_file(mock_stream: mock.Mock) -> None:
    encryption_factory = EncryptionFactory()
    encryption_factory.register_builder("aws", AWSEncryptionServiceBuilder())
    config: typing.Dict[str, typing.Any] = {
        "key_bytes": b"bytes",
        "input_file_path": "somepath",
        "output_file_path": "someotherpath",
    }

    aws_encryption = encryption_factory.create(key="aws", **config)
    mock_stream.return_value.stream.return_value.__enter__.return_value = [
        "text to write"
    ]
    mock_open = mock.mock_open()
    mock_write = mock.mock_open(read_data="Data2").return_value
    mock_open.side_effect = [
        mock.mock_open(read_data="Data1").return_value,
        mock_write,
    ]
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open) as m:
        aws_encryption.decrypt_file()
        calls = [mock.call("somepath", "rb"), mock.call("someotherpath", "wb")]
        m.assert_has_calls(calls)
        mock_write.write.assert_called_once_with("text to write")

    mock_open.side_effect = Exception("exception")
    with mock.patch("s3encrypt.encryption.aws_encryption.open", mock_open):
        with pytest.raises(Exception) as exception_info:
            aws_encryption.decrypt_file()
            assert isinstance(exception_info.value, EncryptionError)
