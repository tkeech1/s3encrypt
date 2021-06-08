import typing
import logging
import asyncio

from s3encrypt.file_watch import DirectoryWatcher
import s3encrypt.async_helper as async_helper
from concurrent.futures import ThreadPoolExecutor
from s3encrypt.decorator import log_start_stop_time, async_log_start_stop_time
from s3encrypt.s3_helper import (
    compress_encrypt_store,
    validate_directory,
    S3EncryptError,
)

logger = logging.getLogger(__name__)


@async_log_start_stop_time
async def s3encrypt_async(
    shutdown_event: typing.Any,
    directories: typing.List[str],
    password: str,
    s3_bucket: str,
    loop: typing.Any,
    executor: typing.Any,
    thread_pool_limit: int = 5,
) -> typing.Dict[str, str]:
    """Async entry point to compress, encrypt and store directories to S3

    Args:
            directories (List[str]): directories

            password (str): the password used to generate the encryption key

            s3_bucket (str): the S3 bucket for upload

            timeout (int): the timeout (seconds) for S3 uploads

    Returns:
            Dict[str, str]: A dictionary of directory -> S3 object

    """

    if len(directories) == 0 or len(directories) > thread_pool_limit or not password:
        return {}

    tasks = []

    try:

        for directory in directories:
            tasks.append(
                asyncio.create_task(
                    compress_encrypt_store(
                        directory, password, s3_bucket, loop, executor
                    )
                )
            )

        done, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)

        logger.debug(f"{len(done)} completed tasks")
        logger.debug(f"{len(pending)} pending tasks")

        results_dict = {}

        for task in done:
            try:
                if task.exception():
                    # TODO - fix mypy issue
                    # results_dict[f"{task.get_name()}"] = str(task.exception())
                    results_dict["task"] = str(task.exception())
                else:
                    for k, v in task.result().items():
                        results_dict[k] = v
            except (asyncio.CancelledError, asyncio.InvalidStateError):
                logger.debug("Task cancelled or invalidated")

        shutdown_event.set()
        return results_dict

    except Exception as e:
        logger.error(e)
        logger.error(f"Args: directories={directories}, s3_bucket={s3_bucket}")
        raise S3EncryptError(" s3encrypt encountered an error ", e)


@log_start_stop_time
def encrypt_store(
    directories: typing.List[str], mode: str, password: str, s3_bucket: str
) -> int:

    with ThreadPoolExecutor(max_workers=len(directories)) as executor:

        shutdown_event = asyncio.Event()
        loop = async_helper.get_loop(shutdown_event, executor)

        try:
            if mode == "watch":
                # watch mode
                logger.debug("Starting in WATCH mode")
                watcher = DirectoryWatcher(loop, executor)
                for directory in directories:
                    try:
                        directory = validate_directory(directory)
                    except S3EncryptError:
                        logger.info(f"{directory} is not a valid directory. Skipping.")
                        continue
                    logger.debug(f"Adding watch for {directory}")
                    watcher.add_watched_directory(directory, password, s3_bucket)
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
                        directories=directories,
                        password=password,
                        s3_bucket=s3_bucket,
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
