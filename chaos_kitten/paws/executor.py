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
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an attack with automatic retry on rate limit.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            files: Files to upload (for multipart/form-data)
                   Format: {'field_name': ('filename', content, 'content_type')}
            headers: Additional headers
            
        Returns:
            Response dictionary with status_code, body, headers, elapsed_ms, error.
        """
        if not self._client:
            return {
                "status_code": 0,
                "body": "",
                "elapsed_ms": 0.0,
                "error": "Client not initialized. Use 'async with Executor(...)' pattern.",
            }
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        # Merge additional headers
        request_headers = self._client.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Prepare request parameters
        method = method.upper()
        start_time = time.perf_counter()
        
        try:
            # Execute request based on method
            if method == "GET":
                response = await self._client.get(
                    path,
                    params=payload,
                    headers=request_headers,
                )
            elif method in ("POST", "PUT", "PATCH"):
                # Handle multipart/form-data vs json
                if files:
                    # If files are present, payload usually goes into 'data' form fields
                    # httpx handles boundary and content-type for files automatically
                    response = await self._client.request(
                        method,
                        path,
                        data=payload, # Form fields
                        files=files,  # File uploads
                        headers=request_headers,
                    )
                else:
                    response = await self._client.request(
                        method,
                        path,
                        json=payload,
                        headers=request_headers,
                    )
            elif method == "DELETE":
                response = await self._client.delete(
                    path,
                    headers=request_headers,
                )
            else:
                return {
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "elapsed_ms": 0.0,
                    "error": f"Unsupported HTTP method: {method}",
                }
            
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
                "elapsed_ms": elapsed_ms,
                "error": None,
            }
            
        except httpx.TimeoutException as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"Request timeout: {str(e)}"
            logger.warning(f"Timeout executing {method} {path}: {e}")
            return {
                "status_code": 0,
                "headers": {},
                "elapsed_ms": 0,
                "error": "Executor not initialized. Use 'async with Executor()' context manager.",
            }
            
        # ... (rest of exception handling remains similar, ensuring closing indent)
        except httpx.ConnectError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Connection error: {str(e)}"
             logger.warning(f"Connection error executing {method} {path}: {e}")
             return {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
        except httpx.HTTPError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"HTTP error: {str(e)}"
             logger.warning(f"HTTP error executing {method} {path}: {e}")
             return {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
        except Exception as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Unexpected error: {str(e)}"
             logger.warning(f"Unexpected error executing {method} {path}: {e}")
             return {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting using token bucket algorithm."""
        if not self._rate_limiter:
            return
        
        # Acquire semaphore token
        async with self._rate_limiter:
            # Calculate time since last request
            current_time = time.perf_counter()
            time_since_last = current_time - self._last_request_time
            
            # Minimum time between requests (in seconds)
            min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
            
            # Sleep if we're going too fast
            if time_since_last < min_interval:
                await asyncio.sleep(min_interval - time_since_last)
            
            # Update last request time
            self._last_request_time = time.perf_counter()
