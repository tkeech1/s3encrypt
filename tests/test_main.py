import mock
import pytest

from s3encrypt.__main__ import get_args


@mock.patch("s3encrypt.__main__.sys")
def test_get_args(mock_sys: mock.Mock) -> None:
    mock_sys.argv = [
        "cmd",
        "--directories",
        "/",
        "--s3_bucket",
        "test",
        "--password",
        "pass",
    ]
    get_args()

    mock_sys.argv = [
        "cmd",
        "--directories",
        "/",
        "--s3_bucket",
        "test",
    ]
    with pytest.raises(SystemExit):
        get_args()

    mock_sys.argv = [
        "cmd",
        "--directories",
        "/",
        "--password",
        "pass",
    ]
    with pytest.raises(SystemExit):
        get_args()

    mock_sys.argv = [
        "cmd",
        "--s3_bucket",
        "test",
        "--password",
        "pass",
    ]
    with pytest.raises(SystemExit):
        get_args()
