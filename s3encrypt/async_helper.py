import typing
import logging
import asyncio
import signal
import functools

logger = logging.getLogger(__name__)


async def timeout(shutdown_event: asyncio.Event, timeout: int = 0) -> None:
    if timeout > 0:
        await asyncio.sleep(timeout)
        shutdown_event.set()


# TODO type annotations
def handle_exception(
    shutdown_event: asyncio.Event,
    executor: typing.Any,
    loop: typing.Any,
    context: typing.Any,
) -> None:
    msg = context.get("exception", context["message"])
    logger.error(f"Caught exception: {msg}")
    shutdown_event.set()


# TODO type annotations
def get_loop(shutdown_event: asyncio.Event, executor: typing.Any) -> typing.Any:
    loop = asyncio.get_event_loop()
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT, signal.SIGQUIT)
    for s in signals:
        # when an exception occurs, trigger a shutdown
        loop.add_signal_handler(s, lambda s=s: shutdown_event.set())
    handle_exc_func = functools.partial(handle_exception, shutdown_event, executor)
    loop.set_exception_handler(handle_exc_func)
    return loop


# TODO type annotations
async def shutdown(
    shutdown_event: asyncio.Event,
    loop: typing.Any,
    executor: typing.Any,
    signal: typing.Any = None,
) -> None:
    await shutdown_event.wait()

    logger.debug("Shutting down...")

    if signal:
        logger.debug(f"Received exit signal {signal.name}...")

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    logger.debug(f"Cancelling {len(tasks)} outstanding tasks")
    for t in tasks:
        logger.debug(f"Task name: {t.get_name()}")
        logger.debug(f"Task coroutine: {t.get_coro().__name__}")

    [task.cancel() for task in tasks]

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError as e:
        logger.debug(f"Task cancelled {e}")

    logger.debug("Shutting down executor")
    executor.shutdown(wait=False)

    logger.debug(f"Releasing {len(executor._threads)} thread(s) from executor")
    for thread in executor._threads:
        try:
            thread._tstate_lock.release()
        except Exception:
            pass

    logger.debug("Stopping event loop")
    loop.stop()
