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

