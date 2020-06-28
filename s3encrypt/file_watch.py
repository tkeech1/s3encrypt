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

logger = logging.getLogger(__name__)


class DirectoryWatcher:
    def __init__(self, src_path, key, s3_bucket, force):
        self.__src_path = src_path
        self.__key = key
        self.__s3_bucket = s3_bucket
        self.__force = force
        self.__event_handler = DirectoryChangeEventHandler()
        self.__event_observer = Observer()

    def run(self):
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def start(self):
        self.__schedule()
        self.__event_observer.start()

    def stop(self):
        self.__event_observer.stop()
        self.__event_observer.join()

    def __schedule(self):
        self.__event_observer.schedule(
            self.__event_handler, self.__src_path, recursive=True
        )


# class DirectoryChangeEventHandler(RegexMatchingEventHandler):
class DirectoryChangeEventHandler(FileSystemEventHandler):

    # FILE_REGEX = [r".*"]

    def __init__(self):
        # super().__init__(self.FILE_REGEX)
        super().__init__()

    def on_any_event(self, event):
        if (
            isinstance(event, FileCreatedEvent)
            or isinstance(event, FileModifiedEvent)
            or isinstance(event, FileDeletedEvent)
        ):
            self.process(event)

    def process(self, event):
        # check to see if the file size is increasing - the file is
        # not finished being copied

        if isinstance(event, FileCreatedEvent) or isinstance(event, FileModifiedEvent):
            file_size = -1
            while file_size != os.path.getsize(event.src_path):
                file_size = os.path.getsize(event.src_path)
                time.sleep(1)

        logger.debug(f"filsystem event! {event}")
