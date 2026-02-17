"""HTTP Executor with Retry Logic and Rate Limiting.

This module provides robust HTTP request execution with:
- Exponential backoff with jitter for retries
- Retry-After header support
- Adaptive retry strategies based on status codes
- Rate limiting with token bucket algorithm
- Comprehensive metrics and logging for rate limit events
"""

import asyncio
import logging
import time
import random
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategy types for different scenarios."""

    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    ADAPTIVE = "adaptive"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 5
    initial_backoff_ms: int = 100
    max_backoff_ms: int = 32000
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1  # Add randomness: 0-10% of backoff
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    retry_on_status_codes: List[int] = field(
        default_factory=lambda: [429, 500, 502, 503, 504]
    )
    respect_retry_after: bool = True
    timeout_ms: int = 30000


@dataclass
class RateLimitMetrics:
    """Metrics for rate limiting events."""

    total_requests: int = 0
    rate_limited_requests: int = 0
    retried_requests: int = 0
    successful_retries: int = 0
    failed_retries: int = 0
    total_backoff_time_ms: float = 0.0
    last_rate_limit_timestamp: Optional[float] = None
    rate_limit_headers_seen: Dict[str, int] = field(default_factory=dict)


class Executor:
    """HTTP executor with advanced retry capabilities."""

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        rate_limit: int = 10,
        auth_type: str = "none",
        auth_token: Optional[str] = None,
        retry_config: Optional[RetryConfig] = None,
    ) -> None:
        """Initialize the HTTP executor.

        Args:
            base_url: Base URL for all requests.
            timeout: Request timeout in seconds.
            rate_limit: Rate limit in requests per second.
            auth_type: Authentication type (none, bearer, basic).
            auth_token: Authentication token.
            retry_config: Retry configuration. Defaults to sensible values.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.auth_type = auth_type.lower()
        self.auth_token = auth_token
        self.retry_config = retry_config or RetryConfig()

        # Client and rate limiter (initialized in __aenter__)
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0.0
        self._metrics = RateLimitMetrics()

    async def __aenter__(self) -> "Executor":
        """Context manager entry - initialize client and rate limiter."""
        if not httpx:
            raise RuntimeError("httpx is not installed. Install with 'pip install httpx'.")

        self._client = httpx.AsyncClient(timeout=self.timeout)
        # Rate limiter: tokens represent requests per second
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        logger.debug(f"Executor initialized with rate limit of {self.rate_limit} req/s")
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - cleanup."""
        if self._client:
            await self._client.aclose()
        logger.debug("Executor cleaned up")

    def _build_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build request headers with authentication.

        Args:
            custom_headers: Additional custom headers to merge.

        Returns:
            Complete headers dictionary.
        """
        headers = {
            "User-Agent": "ChaosKitten/0.1.0",
        }

        # Add authentication
        if self.auth_type == "bearer" and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic" and self.auth_token:
            headers["Authorization"] = f"Basic {self.auth_token}"

        # Merge custom headers
        if custom_headers:
            headers.update(custom_headers)

        return headers

    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting using token bucket algorithm."""
        if not self._rate_limiter:
            return

        # Acquire a token
        async with self._rate_limiter:
            # Calculate time since last request
            current_time = time.time()
            time_since_last = current_time - self._last_request_time

            # Replenish tokens over time
            # If rate_limit is 10 req/s, each request should be ~0.1s apart
            min_interval = 1.0 / self.rate_limit

            if time_since_last < min_interval:
                wait_time = min_interval - time_since_last
                await asyncio.sleep(wait_time)

            self._last_request_time = time.time()

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate backoff time with jitter.

        Args:
            attempt: Current attempt number (0-based).

        Returns:
            Backoff time in seconds.
        """
        strategy = self.retry_config.strategy

        if strategy == RetryStrategy.FIXED:
            base_backoff = self.retry_config.initial_backoff_ms
        elif strategy == RetryStrategy.LINEAR:
            base_backoff = self.retry_config.initial_backoff_ms * (attempt + 1)
        elif strategy == RetryStrategy.ADAPTIVE:
            # Adaptive: uses exponential but caps earlier for common errors
            base_backoff = self.retry_config.initial_backoff_ms * (
                (attempt + 1) ** 1.5
            )  # Slower growth than exponential
        else:  # EXPONENTIAL (default)
            base_backoff = self.retry_config.initial_backoff_ms * (
                self.retry_config.backoff_multiplier ** attempt
            )

        # Cap the backoff
        base_backoff = min(base_backoff, self.retry_config.max_backoff_ms)

        # Add jitter: random value between 0 and jitter_factor% of base_backoff
        jitter_amount = base_backoff * self.retry_config.jitter_factor
        jitter = random.uniform(0, jitter_amount)

        return (base_backoff + jitter) / 1000.0  # Convert to seconds

    def _get_retry_after(self, headers: Dict[str, str]) -> Optional[float]:
        """Extract retry-after time from response headers.

        Args:
            headers: Response headers.

        Returns:
            Retry-after time in seconds, or None if not present.
        """
        if not self.retry_config.respect_retry_after:
            return None

        # Check for Retry-After header (can be seconds or HTTP date)
        retry_after = headers.get("retry-after")
        if not retry_after:
            return None

        try:
            # Try parsing as seconds first
            return float(retry_after)
        except ValueError:
            # If it's a date, we'd need to parse it - for now log and skip
            logger.debug(f"Retry-After header present but in date format: {retry_after}")
            return None

    def _should_retry(self, status_code: int, attempt: int) -> bool:
        """Determine if a request should be retried.

        Args:
            status_code: HTTP status code.
            attempt: Current attempt number (0-based).

        Returns:
            True if request should be retried.
        """
        # Don't retry if we've exhausted attempts
        if attempt >= self.retry_config.max_attempts - 1:
            return False

        # Retry on configured status codes
        return status_code in self.retry_config.retry_on_status_codes

    async def _log_rate_limit_event(
        self, status_code: int, headers: Dict[str, str], attempt: int
    ) -> None:
        """Log rate limit events with metrics.

        Args:
            status_code: HTTP status code.
            headers: Response headers.
            attempt: Current attempt number.
        """
        if status_code == 429:
            self._metrics.rate_limited_requests += 1
            self._metrics.last_rate_limit_timestamp = time.time()

            # Track Retry-After header
            retry_after = headers.get("retry-after")
            if retry_after:
                if retry_after not in self._metrics.rate_limit_headers_seen:
                    self._metrics.rate_limit_headers_seen[retry_after] = 0
                self._metrics.rate_limit_headers_seen[retry_after] += 1

                logger.warning(
                    f"Rate limited (429) - Retry-After: {retry_after}s (attempt {attempt + 1})"
                )
            else:
                logger.warning(f"Rate limited (429) without Retry-After (attempt {attempt + 1})")

    async def execute_attack(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an attack with automatic retry on rate limit.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            path: Request path (relative to base URL).
            payload: Request body/query parameters.
            headers: Custom headers to merge.

        Returns:
            Response dictionary with status_code, body, headers, elapsed_ms, error.
        """
        if not self._client:
            return {
                "status_code": 0,
                "body": "",
                "headers": {},
                "elapsed_ms": 0,
                "error": "Executor not initialized. Use 'async with Executor()' context manager.",
            }

        # Validate HTTP method
        method_upper = method.upper()
        valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if method_upper not in valid_methods:
            return {
                "status_code": 0,
                "body": "",
                "headers": {},
                "elapsed_ms": 0,
                "error": f"Unsupported HTTP method: {method}",
            }

        url = f"{self.base_url}{path}"
        self._metrics.total_requests += 1

        # Retry loop
        last_error = None
        last_response = None

        for attempt in range(self.retry_config.max_attempts):
            try:
                # Apply rate limiting
                await self._apply_rate_limit()

                # Prepare request
                request_headers = self._build_headers(headers)
                start_time = time.time()

                # Execute request
                if method_upper == "GET":
                    response = await self._client.get(url, params=payload, headers=request_headers)
                elif method_upper == "POST":
                    response = await self._client.post(url, json=payload, headers=request_headers)
                elif method_upper == "PUT":
                    response = await self._client.put(url, json=payload, headers=request_headers)
                elif method_upper == "PATCH":
                    response = await self._client.patch(url, json=payload, headers=request_headers)
                elif method_upper == "DELETE":
                    response = await self._client.delete(url, headers=request_headers)
                elif method_upper == "HEAD":
                    response = await self._client.head(url, headers=request_headers)
                elif method_upper == "OPTIONS":
                    response = await self._client.options(url, headers=request_headers)

                elapsed_ms = (time.time() - start_time) * 1000
                last_response = response
                response_headers_dict = dict(response.headers)

                # Check if we should retry
                if self._should_retry(response.status_code, attempt):
                    self._metrics.retried_requests += 1
                    await self._log_rate_limit_event(
                        response.status_code, response_headers_dict, attempt
                    )

                    # Calculate backoff
                    retry_after = self._get_retry_after(response_headers_dict)
                    if retry_after:
                        backoff_time = retry_after
                        logger.info(f"Using Retry-After value: {backoff_time}s")
                    else:
                        backoff_time = await self._calculate_backoff_async(attempt)

                    self._metrics.total_backoff_time_ms += backoff_time * 1000
                    logger.warning(
                        f"Retrying after {backoff_time:.2f}s (attempt {attempt + 1}/{self.retry_config.max_attempts})"
                    )

                    await asyncio.sleep(backoff_time)
                    continue

                # Success or non-retryable response
                if response.status_code < 400:
                    self._metrics.successful_retries += 1

                logger.debug(
                    f"{method_upper} {path} -> {response.status_code} ({elapsed_ms:.2f}ms)"
                )

                return {
                    "status_code": response.status_code,
                    "body": response.text,
                    "headers": response_headers_dict,
                    "elapsed_ms": elapsed_ms,
                    "error": None,
                }

            except httpx.TimeoutException as e:
                last_error = f"Request timeout after {self.timeout}s: {str(e)}"
                logger.error(last_error)

                # Don't retry timeouts beyond max attempts
                if attempt >= self.retry_config.max_attempts - 1:
                    break

                backoff_time = await self._calculate_backoff_async(attempt)
                self._metrics.total_backoff_time_ms += backoff_time * 1000
                await asyncio.sleep(backoff_time)

            except httpx.ConnectError as e:
                last_error = f"Connection error: {str(e)}"
                logger.error(last_error)

                # Don't retry connection errors beyond max attempts
                if attempt >= self.retry_config.max_attempts - 1:
                    break

                backoff_time = await self._calculate_backoff_async(attempt)
                self._metrics.total_backoff_time_ms += backoff_time * 1000
                await asyncio.sleep(backoff_time)

            except httpx.RequestError as e:
                last_error = f"Request error: {str(e)}"
                logger.error(last_error)
                break

            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                logger.error(last_error)
                break

        # All retries exhausted
        self._metrics.failed_retries += 1
        error_msg = last_error or "Unknown error - all retries exhausted"

        return {
            "status_code": last_response.status_code if last_response else 0,
            "body": last_response.text if last_response else "",
            "headers": dict(last_response.headers) if last_response else {},
            "elapsed_ms": 0,
            "error": error_msg,
        }

    async def _calculate_backoff_async(self, attempt: int) -> float:
        """Async wrapper for backoff calculation.

        Args:
            attempt: Current attempt number.

        Returns:
            Backoff time in seconds.
        """
        return self._calculate_backoff(attempt)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics for rate limiting and retry events.

        Returns:
            Dictionary containing metrics.
        """
        return {
            "total_requests": self._metrics.total_requests,
            "rate_limited_requests": self._metrics.rate_limited_requests,
            "retried_requests": self._metrics.retried_requests,
            "successful_retries": self._metrics.successful_retries,
            "failed_retries": self._metrics.failed_retries,
            "total_backoff_time_ms": self._metrics.total_backoff_time_ms,
            "rate_limit_rate": (
                self._metrics.rate_limited_requests / self._metrics.total_requests
                if self._metrics.total_requests > 0
                else 0.0
            ),
            "last_rate_limit_timestamp": self._metrics.last_rate_limit_timestamp,
            "retry_after_headers_seen": self._metrics.rate_limit_headers_seen,
        }

    def reset_metrics(self) -> None:
        """Reset all metrics counters."""
        self._metrics = RateLimitMetrics()
        logger.debug("Metrics reset")
