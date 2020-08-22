import unittest.mock as mock
from unittest.mock import call
import pytest

from s3encrypt.__main__ import main
from s3encrypt.s3encrypt import S3EncryptError


@mock.patch("s3encrypt.__main__.DirectoryWatcher")
@mock.patch("s3encrypt.__main__.sys")
@mock.patch("s3encrypt.__main__.s3encrypt_async")
@mock.patch("s3encrypt.__main__.validate_directory")
@mock.patch("s3encrypt.__main__.logger")
def test_main(
    mock_logger: mock.Mock,
    mock_validate_dir: mock.Mock,
    mock_s3encrypt: mock.Mock,
    mock_sys: mock.Mock,
    mock_directory_watcher: mock.Mock,
) -> None:

    with pytest.raises(SystemExit):
        main()

    # returns without error
    mock_sys.argv = [
        "cmd",
        "--log-level",
        "INFO",
        "--directories",
        "/test",
        "--s3_bucket",
        "test",
        "--password",
        "pass",
    ]
    mock_s3encrypt.return_value = None
    main()

    # logs an error because there are too many directories
    mock_sys.argv = [
        "cmd",
        "--log-level",
        "INFO",
        "--mode",
        "watch",
        "--directories",
        "/test",
        "/test",
        "/test",
        "/test",
        "/test",
        "/test",
        "--s3_bucket",
        "test",
        "--password",
        "pass",
    ]
    main()
    mock_logger.info.assert_called_with("Maximum number of watched directories is 5")

    # adds two watchers
    mock_sys.argv = [
        "cmd",
        "--mode",
        "watch",
        "--directories",
        "/test",
        "/test2",
        "--s3_bucket",
        "test",
        "--password",
        "pass",
    ]
    watcher_mock = mock.Mock()
    mock_directory_watcher.return_value = watcher_mock
    mock_validate_dir.side_effect = ["/test", "/test2"]
    main()
    watcher_mock.add_watched_directory.assert_has_calls(
        [call("/test", "pass", "test", False), call("/test2", "pass", "test", False)]
    )

    # adds no watchers
    mock_validate_dir.side_effect = S3EncryptError("exception")
    main()
    watcher_mock.asset_has_calls([])


def test_init() -> None:
    from s3encrypt import __main__

    with mock.patch.object(__main__, "main", return_value=42):
        with mock.patch.object(__main__, "__name__", "__main__"):
            with mock.patch.object(__main__.sys, "exit") as mock_exit:
                __main__.init()
                mock_exit.assert_called_with(42)
