"""HTTP Executor - Async HTTP client for executing attacks."""

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class Executor:
    """Async HTTP executor for attack requests.

    Features:
    - Async requests with httpx
    - Rate limiting
    - Timeout handling
    - Multiple auth methods
    - Response analysis
    """

    def __init__(
        self,
        base_url: str,
        auth_type: str = "none",
        auth_token: str | None = None,
        rate_limit: int = 10,
        timeout: int = 30,
    ) -> None:
        """Initialize the executor.

        Args:
            base_url: Base URL of the target API
            auth_type: Authentication type (bearer, basic, none)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds

        Raises:
            ValueError: If auth_type is not supported.
        """
        self.base_url = base_url.rstrip("/")

        if auth_type not in ["bearer", "basic", "none"]:
            raise ValueError(
                f"Unsupported auth_type: {auth_type}. Supported types: bearer, basic, none"
            )

        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._rate_limiter: asyncio.Semaphore | None = None
        self._last_request_time: float = 0.0

    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        # Initialize rate limiter semaphore
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Context manager exit."""
        if self._client:
            await self._client.aclose()

    def _build_headers(self) -> dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}

        if self.auth_type in ("bearer", "oauth") and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic" and self.auth_token:
            headers["Authorization"] = f"Basic {self.auth_token}"

        return headers

    async def execute_attack(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an attack request.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            files: Files to upload (for multipart/form-data)
                   Format: {'field_name': ('filename', content, 'content_type')}
            headers: Additional headers

        Returns:
            Response data including status, body, and timing
        """
        if not self._client:
            return {
                "status_code": 0,
                "headers": {},
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
                "body": "",
                "elapsed_ms": elapsed_ms,
                "error": error_msg,
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
