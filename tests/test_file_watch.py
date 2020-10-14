from unittest import mock
from unittest.mock import call
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
)
from s3encrypt.file_watch import DirectoryWatcher, DirectoryChangeEventHandler
import pytest
from concurrent.futures import ThreadPoolExecutor
import asyncio
import s3encrypt.async_helper as async_helper


@pytest.fixture
def executor():
    return ThreadPoolExecutor()


@pytest.fixture
def shutdown_event():
    return asyncio.Event()


@pytest.fixture
def custom_event_loop(executor, shutdown_event):
    return async_helper.get_loop(shutdown_event, executor)


@pytest.mark.asyncio
@mock.patch("s3encrypt.file_watch.Observer")
@mock.patch("s3encrypt.file_watch.DirectoryChangeEventHandler")
@mock.patch("s3encrypt.file_watch.time")
def test_DirectoryWatcher(
    mock_time: mock.Mock,
    mock_dir_chg_evt: mock.Mock,
    mock_observer: mock.Mock,
    executor,
    custom_event_loop,
) -> None:
    mock_event_observer = mock.Mock()
    mock_observer.return_value = mock_event_observer
    dir_chg_mock = mock.Mock()
    mock_dir_chg_evt.return_value = dir_chg_mock
    dir_watcher: DirectoryWatcher = DirectoryWatcher(custom_event_loop, executor)
    dir_watcher.add_watched_directory("/a_test", "password", "bucket")

    mock_event_observer.schedule.assert_called_once_with(
        dir_chg_mock, "/a_test", recursive=True
    )
    mock_time.sleep.side_effect = KeyboardInterrupt()
    dir_watcher.run()

    mock_event_observer.start.assert_called_with()
    mock_event_observer.stop.assert_called_with()
    mock_event_observer.join.assert_called_with()


@pytest.mark.asyncio
@mock.patch("s3encrypt.file_watch.os.path.getsize")
@mock.patch("s3encrypt.file_watch.compress_encrypt_store")
def test_DirectoryChangeEventHandler(
    mock_ces: mock.Mock, mock_getsize: mock.Mock, executor, custom_event_loop,
) -> None:
    mock_getsize.return_value = 1
    dir_chg_handler: DirectoryChangeEventHandler = DirectoryChangeEventHandler(
        src_path="/a_test",
        password="password",
        s3_bucket="bucket",
        loop=custom_event_loop,
        executor=executor,
    )
    dir_chg_handler.on_any_event(FileCreatedEvent("/a_test"))
    dir_chg_handler.on_any_event(FileDeletedEvent("/a_test"))
    dir_chg_handler.on_any_event(FileModifiedEvent("/a_test"))

    calls = [call("/a_test", "password", "bucket", custom_event_loop, executor)] * 3
    mock_ces.assert_has_calls(calls)

