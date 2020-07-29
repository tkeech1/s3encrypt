from unittest import mock
from unittest.mock import call
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
)
from s3encrypt.file_watch import DirectoryWatcher, DirectoryChangeEventHandler


@mock.patch("s3encrypt.file_watch.Observer")
@mock.patch("s3encrypt.file_watch.DirectoryChangeEventHandler")
@mock.patch("s3encrypt.file_watch.time")
def test_DirectoryWatcher(
    mock_time: mock.Mock, mock_dir_chg_evt: mock.Mock, mock_observer: mock.Mock
) -> None:
    mock_event_observer = mock.Mock()
    mock_observer.return_value = mock_event_observer
    dir_chg_mock = mock.Mock()
    mock_dir_chg_evt.return_value = dir_chg_mock
    dir_watcher: DirectoryWatcher = DirectoryWatcher()
    dir_watcher.add_watched_directory("/a_test", "password", "bucket", True)

    mock_event_observer.schedule.assert_called_once_with(
        dir_chg_mock, "/a_test", recursive=True
    )
    mock_time.sleep.side_effect = KeyboardInterrupt()
    dir_watcher.run()

    mock_event_observer.start.assert_called_with()
    mock_event_observer.stop.assert_called_with()
    mock_event_observer.join.assert_called_with()


@mock.patch("s3encrypt.file_watch.time.sleep")
@mock.patch("s3encrypt.file_watch.os.path.getsize")
@mock.patch("s3encrypt.file_watch.compress_encrypt_store")
def test_DirectoryChangeEventHandler(
    mock_ces: mock.Mock, mock_getsize: mock.Mock, mock_sleep: mock.Mock
) -> None:
    mock_getsize.return_value = 1
    dir_chg_handler: DirectoryChangeEventHandler = DirectoryChangeEventHandler(
        src_path="/a_test", password="password", s3_bucket="bucket", force=True
    )
    dir_chg_handler.on_any_event(FileCreatedEvent("/a_test"))
    dir_chg_handler.on_any_event(FileDeletedEvent("/a_test"))
    dir_chg_handler.on_any_event(FileModifiedEvent("/a_test"))

    calls = [call("/a_test", "password", "bucket", True)] * 3
    mock_ces.assert_has_calls(calls)
