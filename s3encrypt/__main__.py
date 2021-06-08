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
import sys
from s3encrypt.s3encrypt import encrypt_store

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

    return int(
        encrypt_store(args.directories, args.mode, args.password, args.s3_bucket)
    )


def init() -> None:
    if __name__ == "__main__":
        sys.exit(main())


init()
