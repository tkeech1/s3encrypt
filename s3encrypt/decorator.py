import typing
import functools
import logging
import time

logger = logging.getLogger(__name__)


def log_start_stop_time(
    func: typing.Callable[..., typing.Any]
) -> typing.Callable[..., typing.Any]:
    @functools.wraps(func)
    def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        start_time = time.perf_counter()
        logger.info(f"Entering {func.__name__}")
        return_value = func(*args, **kwargs)
        end_time = time.perf_counter()
        run_time = end_time - start_time
        logger.info(f"Exited {func.__name__} with runtime {run_time:.4f} seconds")
        return return_value

    return wrapper
