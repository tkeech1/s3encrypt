import tempfile
import logging
import os
import typing

logger = logging.getLogger(__name__)


class TempFile:
    def __init__(self) -> None:
        self.temp_file_path = ""

    def __enter__(self) -> typing.Any:
        _, self.temp_file_path = tempfile.mkstemp()
        return self

    def __exit__(
        self, exc_type: typing.Any, exc_value: typing.Any, exc_traceback: typing.Any
    ) -> None:
        try:
            # remove the tmpfile
            os.remove(self.temp_file_path)
            logger.debug(f"Removed tmp file {self.temp_file_path}")
        except Exception as e:
            logger.debug(f"An exception occurred removing a tmp file: {e}")
            raise Exception(" s3encrypt encountered an error ", e)
