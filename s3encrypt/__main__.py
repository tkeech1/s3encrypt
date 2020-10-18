"""

This module zips, encrypts and saves one or more directories to an S3 bucket.

Example:
    $ python -m s3encrypt --directories test test2 test3
        --s3_bucket MYBUCKET --password 12345

Attributes:
        __author__ = author of the module.

        __email__ = author's email address.

        __version__ = package version.

Todo:
    * Documentation

"""

import logging
import logging.config
import argparse
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor

from s3encrypt.s3encrypt import (
    S3EncryptError,
    s3encrypt_async,
    validate_directory,
)
from s3encrypt.file_watch import DirectoryWatcher
import s3encrypt.async_helper as async_helper

logger = logging.getLogger(__package__)


# TODO - use Typer
def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zip, encrypt and store a directory to S3."
    )

    parser.add_argument(
        "-v",
        "--log-level",
        help="set the log level for the application",
        action="store",
        nargs="?",
    )
    parser.add_argument(
        "--mode",
        type=str,
        action="store",
        choices=["store", "watch"],
        help="store - Zips, encrypts, and stores the directory contents to S3."
        + "watch - Watches a directory for changes and zips, encrypts, and "
        + "stores the directory to S3 upon change.",
        default="store",
    )
    parser.add_argument(
        "--directories",
        type=str,
        action="store",
        help="the directory or directories to zip, encrypt and store in S3",
        required=True,
        nargs="+",
    )
    parser.add_argument(
        "--s3_bucket",
        type=str,
        action="store",
        help="the path of the AWS bucket",
        required=True,
    )
    parser.add_argument(
        "--password",
        type=str,
        action="store",
        help="the password used to generate the encryption key",
        required=True,
    )

    args = parser.parse_args(sys.argv[1:])

    logger.debug(f"Args: directories={args.directories}, s3_bucket={args.s3_bucket}")

    return args


def main() -> int:

    args = get_args()

    logger.setLevel(logging.INFO)
    if args.log_level:
        logger.setLevel(args.log_level)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Z %Y-%m-%d %H:%M:%S",
    )

    # log to rotating file
    # ch = logging.handlers.RotatingFileHandler(
    #    filename=f"{__package__}.log",
    #    maxBytes=10485760,
    #    backupCount=20,
    #    encoding="utf8",
    # )

    # log to console
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    directory_limit = 5
    if len(args.directories) > directory_limit:
        logger.info(f"Maximum number of directories is {directory_limit}")
        return 1

    with ThreadPoolExecutor(max_workers=len(args.directories)) as executor:

        shutdown_event = asyncio.Event()
        loop = async_helper.get_loop(shutdown_event, executor)

        try:
            if args.mode == "watch":
                # watch mode
                logger.debug("Starting in WATCH mode")
                watcher = DirectoryWatcher(loop, executor)
                for directory in args.directories:
                    try:
                        directory = validate_directory(directory)
                    except S3EncryptError:
                        logger.info(f"{directory} is not a valid directory. Skipping.")
                        continue
                    logger.debug(f"Adding watch for {directory}")
                    watcher.add_watched_directory(
                        directory, args.password, args.s3_bucket
                    )
                logger.debug("Starting watch... ")
                # the shutdown task waits for the shutdown_event to be set
                # the shutdown_event can be set by:
                # 1) exception
                # 2) OS signal (ctrl-c)

                # TODO - shutdown via OS signal not working
                # loop.create_task(async_helper.shutdown(shutdown_event,
                # loop, executor))
                watcher.run()
            else:
                # store mode
                logger.debug("Starting in STORE mode")

                # the shutdown task waits for the shutdown_event to be set
                # the shutdown_event can be set by:
                # 1) successful completion of tasks
                # 2) exception
                # 3) OS signal (ctrl-c)
                # 4) timeout
                loop.create_task(async_helper.shutdown(shutdown_event, loop, executor))

                # when the main task completes, shutdown_event is set
                # #to trigger shutdown
                loop.create_task(
                    s3encrypt_async(
                        shutdown_event,
                        directories=args.directories,
                        password=args.password,
                        s3_bucket=args.s3_bucket,
                        loop=loop,
                        executor=executor,
                    )
                )

                # when the timeout expires, shutdown_event is set to trigger shutdown
                loop.create_task(async_helper.timeout(shutdown_event, timeout=2))
                loop.run_forever()

                logger.debug("Done")
        finally:
            loop.close()

    return 0


def init() -> None:
    if __name__ == "__main__":
        sys.exit(main())


init()
