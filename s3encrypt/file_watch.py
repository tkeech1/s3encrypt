import time
import os
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
)
from watchdog.observers import Observer
import logging

from s3encrypt.s3encrypt import compress_encrypt_store

logger = logging.getLogger(__name__)


class DirectoryWatcher:
    def __init__(self):
        self.__event_observer = Observer()

    def run(self):
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def start(self):
        self.__event_observer.start()

    def stop(self):
        self.__event_observer.stop()
        self.__event_observer.join()

    def add_watched_directory(self, src_path, key, salt, s3_bucket, force):
        event_handler = DirectoryChangeEventHandler(
            src_path, key, salt, s3_bucket, force
        )
        self.__schedule(event_handler, src_path)

    def __schedule(self, event_handler, src_path):
        self.__event_observer.schedule(event_handler, src_path, recursive=True)


# class DirectoryChangeEventHandler(RegexMatchingEventHandler):
class DirectoryChangeEventHandler(FileSystemEventHandler):

    # FILE_REGEX = [r".*"]

    def __init__(self, src_path, key, salt, s3_bucket, force):
        # super().__init__(self.FILE_REGEX)
        self.__src_path = src_path
        self.__key = key
        self.__salt = salt
        self.__s3_bucket = s3_bucket
        self.__force = force
        super().__init__()

    def on_any_event(self, event):
        if (
            isinstance(event, FileCreatedEvent)
            or isinstance(event, FileModifiedEvent)
            or isinstance(event, FileDeletedEvent)
        ):
            self.process(event)

    def process(self, event):
        # check to see if the file size is increasing - if the file is
        # not finished being copied, need to wait for it to finish
        if isinstance(event, FileCreatedEvent) or isinstance(
            event, FileModifiedEvent
        ):
            file_size = -1
            while file_size != os.path.getsize(event.src_path):
                file_size = os.path.getsize(event.src_path)
                time.sleep(1)

        logger.debug(f"Filesystem event: {event}")
        compress_encrypt_store(
            self.__src_path,
            self.__key,
            self.__salt,
            self.__s3_bucket,
            self.__force,
        )
