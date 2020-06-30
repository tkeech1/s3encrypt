"""

This module zips, encrypts and saves the encrypted file to an S3 bucket.

Example:
    $ python -m s3encrypt store --directories test test2 test3
        --s3_bucket MYBUCKET --key 12345

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
import typing

from s3encrypt.s3encrypt import S3EncryptError, s3encrypt_async
from s3encrypt.file_watch import DirectoryWatcher

logger = logging.getLogger(__package__)


def get_args() -> argparse.Namespace:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
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
        "--key",
        type=str,
        action="store",
        help="the encryption key",
        required=True,
    )
    parser.add_argument(
        "--salt", type=str, action="store", help="the salt", required=True,
    )
    parser.add_argument(
        "--force",
        type=bool,
        action="store",
        help="force existing files to be overwritten",
        nargs="?",
        const=True,
        default=False,
    )

    args = parser.parse_args()

    logger.debug(
        f"Args: directories={args.directories}, s3_bucket={args.s3_bucket}, "
        + f"key={args.key}"
    )

    return args


async def main_async(args: argparse.Namespace) -> typing.Any:

    try:
        timeout = 40
        task = [
            asyncio.create_task(
                s3encrypt_async(
                    directories=args.directories,
                    key=args.key,
                    salt=args.salt,
                    s3_bucket=args.s3_bucket,
                    force=args.force,
                    timeout=timeout,
                )
            )
        ]
        await asyncio.wait(task, timeout=timeout)
        return task
    except S3EncryptError as e:
        logger.error(e)


def main():

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

    args = get_args()

    if args.mode == "watch":
        # watch mode
        logger.debug("Starting in WATCH mode")
        process_limit = 5
        if len(args.directories) > process_limit:
            logger.info(
                f"Maximum number of watched directories is {process_limit}"
            )
            return

        watcher = DirectoryWatcher()
        for directory in args.directories:
            logger.debug(f"Starting watch for {directory}")
            watcher.add_watched_directory(
                directory, args.key, args.salt, args.s3_bucket, args.force
            )
            logger.debug(f"Started watch for {directory}")
        watcher.run()
    else:
        # store mode
        logger.debug("Starting in STORE mode")
        try:
            task = asyncio.run(main_async(args))
            for t in task:
                logger.debug(f"done {t.result()}")
        except Exception as e:
            logger.error(e)


if __name__ == "__main__":
    main()
