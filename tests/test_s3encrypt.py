""" Tests for s3encrypt """
from s3encrypt.s3encrypt import (
    S3EncryptError,
    validate_directory,
    compress_directory,
    store_to_s3,
    compress_encrypt_store,
    s3encrypt_async,
)

from unittest import mock
import pytest
import botocore
import typing
import asyncio


def test_validate_directory() -> None:
    with mock.patch("s3encrypt.s3encrypt.os") as mock_os:
        mock_os.sep = "/"
        mock_os.path.isdir.return_value = True
        assert "/somedir/somedir2" == validate_directory("/somedir/somedir2/")
        assert "/somedir/somedir2" == validate_directory("/somedir/somedir2")

        mock_os.path.isdir.return_value = False
        with pytest.raises(S3EncryptError) as exception_info:
            validate_directory("dfgsdf")
            assert isinstance(exception_info.value, S3EncryptError)


@mock.patch("s3encrypt.s3encrypt.os.walk")
@mock.patch("s3encrypt.s3encrypt.zipfile.ZipFile")
def test_compress_directory(mock_zipfile: mock.Mock, mock_os_walk: mock.Mock) -> None:
    archive = mock.Mock()
    mocked_write = mock.Mock()
    archive.return_value.write = mocked_write
    mock_zipfile.return_value.__enter__ = archive
    mock_os_walk.return_value = [
        ("/dirpath", ("dir1",), ("file3",)),
        ("/dirpath/dir1", (), ("file1", "file2")),
    ]

    compress_directory("", "")

    calls = [
        mock.call("/dirpath/dir1/file2"),
        mock.call("/dirpath/dir1/file1"),
        mock.call("/dirpath/file3"),
    ]
    # test that zipfile.write was called for each file in the tree
    # returned by os.walk
    mocked_write.assert_has_calls(calls, any_order=True)

    mocked_write.side_effect = Exception("exception")
    with pytest.raises(Exception) as exception_info:
        compress_directory("", "")
        assert isinstance(exception_info.value, S3EncryptError)


@mock.patch("s3encrypt.s3encrypt.boto3.session.Session")
def test_store_to_s3(mock_boto3_session: mock.Mock) -> None:
    client = mock.Mock()
    client.upload_file.return_value = None
    sess = mock.Mock()
    sess.client.return_value = client
    mock_boto3_session.return_value = sess
    store_to_s3("filepath", "bucket", "obj_key")
    client.upload_file.assert_called_once_with("filepath", "bucket", "obj_key")

    with pytest.raises(Exception) as exception_info:
        client.upload_file.return_value = "not none"
        store_to_s3("filepath", "bucket", "obj_key")
        assert isinstance(exception_info.value, S3EncryptError)

    client.upload_file.side_effect = botocore.exceptions.ClientError({}, {})
    with pytest.raises(Exception) as exception_info:
        store_to_s3("filepath", "bucket", "obj_key")
        assert isinstance(exception_info.value, S3EncryptError)


"""
@mock.patch("s3encrypt.s3encrypt.os.remove")
@mock.patch("s3encrypt.temp_file.tempfile")
@mock.patch("s3encrypt.s3encrypt.validate_directory")
@mock.patch("s3encrypt.s3encrypt.compress_directory")
@mock.patch("s3encrypt.s3encrypt.EncryptionFactory.create")
@mock.patch("s3encrypt.s3encrypt.store_to_s3")
def test_compress_encrypt_store(
    mock_store_to_s3: mock.Mock,
    mock_EncryptionFactory: mock.Mock,
    mock_compress_directory: mock.Mock,
    mock_validate_directory: mock.Mock,
    mock_tempfile: mock.Mock,
    mock_os_remove: mock.Mock,
) -> None:

    # happy path
    directory = "/dir"
    password = "pass"
    s3bucket = "s3bucket"

    mock_tempfile.mkstemp.return_value = ("", "some_file")
    mock_validate_directory.return_value = directory
    mock_os_remove.return_value = None
    mock_encrypt_file = mock.Mock()
    mock_EncryptionFactory.return_value = mock_encrypt_file
    compress_encrypt_store(directory, password, s3bucket)
    mock_validate_directory.assert_called_once_with(directory)
    mock_compress_directory.assert_called_once_with(directory, "some_file")
    mock_encrypt_file.encrypt_file.assert_called_once_with()
    mock_store_to_s3.assert_called_once_with("some_file", s3bucket, "dir.zip.enc")

    # error removing tmp file
    mock_os_remove.side_effect = Exception("exception")
    with pytest.raises(S3EncryptError):
        compress_encrypt_store(directory, password, s3bucket)

    # error in encryption/upload
    mock_compress_directory.side_effect = Exception("exception")
    with pytest.raises(S3EncryptError):
        compress_encrypt_store(directory, password, s3bucket)

    # invalid directory
    mock_validate_directory.side_effect = S3EncryptError("", Exception("exception"))
    assert compress_encrypt_store("", "", "") == {}
    mock_validate_directory.reset_mock()
"""

"""
@pytest.mark.asyncio
@mock.patch("s3encrypt.s3encrypt.compress_encrypt_store")
async def test_s3encrypt_async(mock_compress_encrypt_store: mock.Mock) -> None:
    directories: typing.List[str] = []
    password = "pass"
    s3_bucket = "s3_bucket"

    # test empty director list
    assert await (s3encrypt_async(directories, password, s3_bucket)) == {}

    directories = ["somedir", "somedir2"]
    password = ""

    # test empty password
    assert await (s3encrypt_async(directories, password, s3_bucket)) == {}

    password = "pass"
    # return a different value for each call to the mock
    mock_compress_encrypt_store.side_effect = [
        {"file1": "url1"},
        {"file2": "url2"},
    ]
    result = await (s3encrypt_async(directories, password, s3_bucket))
    assert len(result) == 2
    assert result["file1"] == "url1"
    assert result["file2"] == "url2"

    # error in s3encrypt_async
    mock_compress_encrypt_store.side_effect = Exception("exception 123")
    res = await s3encrypt_async(directories, password, s3_bucket)
    assert "exception 123" in res.values()

    # error in s3encrypt_async
    with mock.patch("s3encrypt.s3encrypt.asyncio") as mock_asyncio:
        with pytest.raises(S3EncryptError):
            mock_asyncio.get_event_loop.side_effect = Exception("exception")
            await s3encrypt_async(directories, password, s3_bucket)
"""

