"""Rate limiting and retry utilities with exponential backoff."""
from __future__ import annotations

import logging
import random
import time
from functools import wraps
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 60.0  # seconds
DEFAULT_JITTER = 0.5  # 50% jitter


class RateLimitError(Exception):
    """Raised when rate limit is exceeded after all retries."""
    pass


class RetryableError(Exception):
    """Raised for errors that should trigger a retry."""
    pass


def exponential_backoff(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
    retryable_exceptions: tuple[type[Exception], ...] = (RetryableError,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for exponential backoff with jitter.
    
    Args:
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap in seconds.
        jitter: Jitter factor (0.5 = ±50% randomization).
        retryable_exceptions: Tuple of exception types that trigger retry.
        
    Returns:
        Decorated function with retry logic.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Exception | None = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    
                    if attempt >= max_retries:
                        logger.error(
                            "Max retries (%d) exceeded for %s: %s",
                            max_retries, func.__name__, str(e)
                        )
                        raise RateLimitError(
                            f"Max retries exceeded: {str(e)}"
                        ) from e
                    
                    # Calculate delay with exponential backoff
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    
                    # Add jitter
                    jitter_range = delay * jitter
                    delay = delay + random.uniform(-jitter_range, jitter_range)
                    delay = max(0.1, delay)  # Minimum 100ms
                    
                    logger.warning(
                        "Retry %d/%d for %s after %.2fs: %s",
                        attempt + 1, max_retries, func.__name__, delay, str(e)
                    )
                    time.sleep(delay)
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
            raise RuntimeError("Unexpected retry loop exit")
        
        return wrapper
    return decorator


def is_rate_limit_error(error: Exception) -> bool:
    """Check if an error indicates rate limiting.
    
    Args:
        error: The exception to check.
        
    Returns:
        True if this appears to be a rate limit error.
    """
    error_str = str(error).lower()
    rate_limit_indicators = [
        "rate limit",
        "rate_limit",
        "ratelimit",
        "too many requests",
        "429",
        "quota exceeded",
        "throttl",
    ]
    return any(indicator in error_str for indicator in rate_limit_indicators)


def is_transient_error(error: Exception) -> bool:
    """Check if an error is transient and should be retried.

    Args:
        error: The exception to check.

    Returns:
        True if this appears to be a transient error.
    """
    error_str = str(error).lower()
    transient_indicators = [
        "timeout",
        "timed out",
        "connection",
        "temporary",
        "503",
        "502",
        "504",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
    ]
    return any(indicator in error_str for indicator in transient_indicators)

