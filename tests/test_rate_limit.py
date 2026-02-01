"""Tests for rate limiting and retry utilities."""
from __future__ import annotations

import time
import pytest
from unittest.mock import patch

from agent_hub.rate_limit import (
    RateLimitError,
    RetryableError,
    exponential_backoff,
    is_rate_limit_error,
    is_transient_error,
)


class TestIsRateLimitError:
    """Tests for rate limit error detection."""

    def test_detects_rate_limit_message(self):
        """Should detect 'rate limit' in error message."""
        assert is_rate_limit_error(Exception("Rate limit exceeded"))
        assert is_rate_limit_error(Exception("rate_limit_error"))
        assert is_rate_limit_error(Exception("RateLimit hit"))

    def test_detects_429_status(self):
        """Should detect 429 status code."""
        assert is_rate_limit_error(Exception("HTTP 429: Too Many Requests"))

    def test_detects_quota_exceeded(self):
        """Should detect quota exceeded."""
        assert is_rate_limit_error(Exception("Quota exceeded for this API"))

    def test_detects_throttling(self):
        """Should detect throttling."""
        assert is_rate_limit_error(Exception("Request throttled"))

    def test_returns_false_for_other_errors(self):
        """Should return False for non-rate-limit errors."""
        assert not is_rate_limit_error(Exception("Connection refused"))
        assert not is_rate_limit_error(Exception("Invalid API key"))
        assert not is_rate_limit_error(Exception("Internal server error"))


class TestIsTransientError:
    """Tests for transient error detection."""

    def test_detects_timeout(self):
        """Should detect timeout errors."""
        assert is_transient_error(Exception("Connection timeout"))
        assert is_transient_error(Exception("Read timed out"))

    def test_detects_connection_errors(self):
        """Should detect connection errors."""
        assert is_transient_error(Exception("Connection refused"))
        assert is_transient_error(Exception("Connection reset"))

    def test_detects_5xx_errors(self):
        """Should detect 5xx status codes."""
        assert is_transient_error(Exception("HTTP 502: Bad Gateway"))
        assert is_transient_error(Exception("HTTP 503: Service Unavailable"))
        assert is_transient_error(Exception("HTTP 504: Gateway Timeout"))

    def test_returns_false_for_other_errors(self):
        """Should return False for non-transient errors."""
        assert not is_transient_error(Exception("Invalid API key"))
        assert not is_transient_error(Exception("HTTP 400: Bad Request"))
        assert not is_transient_error(Exception("HTTP 401: Unauthorized"))


class TestExponentialBackoff:
    """Tests for exponential backoff decorator."""

    def test_succeeds_on_first_try(self):
        """Should return immediately on success."""
        call_count = 0

        @exponential_backoff(max_retries=3, retryable_exceptions=(RetryableError,))
        def successful_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = successful_func()
        assert result == "success"
        assert call_count == 1

    def test_retries_on_retryable_error(self):
        """Should retry on retryable errors."""
        call_count = 0

        @exponential_backoff(max_retries=3, base_delay=0.01, retryable_exceptions=(RetryableError,))
        def failing_then_succeeding():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RetryableError("Temporary failure")
            return "success"

        result = failing_then_succeeding()
        assert result == "success"
        assert call_count == 3

    def test_raises_rate_limit_error_after_max_retries(self):
        """Should raise RateLimitError after max retries."""
        call_count = 0

        @exponential_backoff(max_retries=2, base_delay=0.01, retryable_exceptions=(RetryableError,))
        def always_failing():
            nonlocal call_count
            call_count += 1
            raise RetryableError("Always fails")

        with pytest.raises(RateLimitError):
            always_failing()
        
        assert call_count == 3  # Initial + 2 retries

    def test_does_not_retry_non_retryable_errors(self):
        """Should not retry non-retryable errors."""
        call_count = 0

        @exponential_backoff(max_retries=3, retryable_exceptions=(RetryableError,))
        def raises_value_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("Not retryable")

        with pytest.raises(ValueError):
            raises_value_error()
        
        assert call_count == 1

    @patch("agent_hub.rate_limit.time.sleep")
    def test_delay_increases_exponentially(self, mock_sleep):
        """Should increase delay exponentially."""
        call_count = 0

        @exponential_backoff(max_retries=3, base_delay=1.0, max_delay=60.0, jitter=0, retryable_exceptions=(RetryableError,))
        def always_failing():
            nonlocal call_count
            call_count += 1
            raise RetryableError("Always fails")

        with pytest.raises(RateLimitError):
            always_failing()

        # Check that sleep was called with increasing delays
        # With jitter=0: delays should be 1.0, 2.0, 4.0
        assert mock_sleep.call_count == 3
        delays = [call[0][0] for call in mock_sleep.call_args_list]
        assert delays[0] == pytest.approx(1.0, rel=0.1)
        assert delays[1] == pytest.approx(2.0, rel=0.1)
        assert delays[2] == pytest.approx(4.0, rel=0.1)

    @patch("agent_hub.rate_limit.time.sleep")
    def test_delay_capped_at_max(self, mock_sleep):
        """Should cap delay at max_delay."""
        call_count = 0

        @exponential_backoff(max_retries=5, base_delay=10.0, max_delay=15.0, jitter=0, retryable_exceptions=(RetryableError,))
        def always_failing():
            nonlocal call_count
            call_count += 1
            raise RetryableError("Always fails")

        with pytest.raises(RateLimitError):
            always_failing()

        delays = [call[0][0] for call in mock_sleep.call_args_list]
        # All delays should be <= max_delay
        for delay in delays:
            assert delay <= 15.0

