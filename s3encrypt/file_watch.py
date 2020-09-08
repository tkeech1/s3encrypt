from __future__ import annotations
import time
import os
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEvent,
)
from watchdog.observers import Observer
import logging

from s3encrypt.s3encrypt import compress_encrypt_store

logger = logging.getLogger(__name__)


class DirectoryWatcher(object):
    def __init__(self) -> None:
        self.__event_observer = Observer()

    def run(self) -> None:
        self.__start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.__stop()

    def __start(self) -> None:
        self.__event_observer.start()

    def __stop(self) -> None:
        self.__event_observer.stop()
        self.__event_observer.join()

    def add_watched_directory(
        self, src_path: str, password: str, s3_bucket: str, force: bool,
    ) -> None:
        event_handler = DirectoryChangeEventHandler(
            src_path, password, s3_bucket, force
        )
        self.__schedule(event_handler, src_path)

    def __schedule(
        self, event_handler: DirectoryChangeEventHandler, src_path: str,
    ) -> None:
        self.__event_observer.schedule(event_handler, src_path, recursive=True)


class DirectoryChangeEventHandler(FileSystemEventHandler):  # type: ignore
    def __init__(
        self, src_path: str, password: str, s3_bucket: str, force: bool,
    ) -> None:
        self.__src_path = src_path
        self.__password = password
        self.__s3_bucket = s3_bucket
        self.__force = force
        super().__init__()

    def on_any_event(self: DirectoryChangeEventHandler, event: FileSystemEvent) -> None:
        if (
            isinstance(event, FileCreatedEvent)
            or isinstance(event, FileModifiedEvent)
            or isinstance(event, FileDeletedEvent)
        ):
            self.process(event)

    def process(self: DirectoryChangeEventHandler, event: FileSystemEvent) -> None:
        # check to see if the file size is increasing - if the file is
        # not finished being copied, need to wait for it to finish
        if isinstance(event, FileCreatedEvent) or isinstance(event, FileModifiedEvent):
            file_size = -1
            while file_size != os.path.getsize(event.src_path):
                file_size = os.path.getsize(event.src_path)
                time.sleep(1)

        logger.debug(f"Filesystem event: {event}")
        compress_encrypt_store(
            self.__src_path, self.__password, self.__s3_bucket, self.__force,
        )
