import unittest.mock as mock
import pytest

from s3encrypt.__main__ import main


@mock.patch("s3encrypt.__main__.sys")
@mock.patch("s3encrypt.__main__.encrypt_store")
def test_main(mock_encrypt_store: mock.Mock, mock_sys: mock.Mock,) -> None:

    # no arguments results in an error
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

    mock_encrypt_store.return_value = 0
    assert main() == 0

    # logs an error because there are too many directories
    mock_sys.argv = [
        "cmd",
        "--log-level",
        "INFO",
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
    assert main() == 1


def test_init() -> None:
    from s3encrypt import __main__

    with mock.patch.object(__main__, "main", return_value=42):
        with mock.patch.object(__main__, "__name__", "__main__"):
            with mock.patch.object(__main__.sys, "exit") as mock_exit:
                __main__.init()
                mock_exit.assert_called_with(42)

