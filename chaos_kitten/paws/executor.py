"""HTTP executor for sending payloads to endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class Executor:
    """Execute HTTP requests with payloads and report results."""

    def __init__(
        self,
        base_url: str = "",
        auth_type: str = "none",
        auth_token: str = "",
        rate_limit: float = 0,
        timeout: int = 30,
    ) -> None:
        """Initialize the executor.

        Args:
            base_url: Base URL for the API
            auth_type: Authentication type (none, bearer, basic, api_key)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second (0 = no limit)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout

        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0

    async def __aenter__(self) -> "Executor":
        """Async context manager entry."""
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self._close()

    async def _ensure_client(self) -> None:
        """Ensure the HTTP client is initialized."""
        if self._client is None:
            headers = self._build_headers()
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
            if self.rate_limit > 0:
                self._rate_limiter = asyncio.Semaphore(int(self.rate_limit))

    async def _close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        headers = {}
        if self.auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.auth_token}"
        elif self.auth_type == "basic":
            headers["Authorization"] = f"Basic {self.auth_token}"
        elif self.auth_type == "api_key":
            headers["X-API-Key"] = self.auth_token
        return headers

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

    async def execute_attack(
        self,
        method: str,
        path: str,
        payload: Optional[dict[str, Any]] = None,
        location: str = "query",
        headers: Optional[dict[str, str]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute an attack request.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            location: Payload location (query, body, header, cookie)
            headers: Additional headers
            **kwargs: Additional arguments for httpx

        Returns:
            Response dict with status, body, headers, etc.
        """
        await self._ensure_client()
        await self._apply_rate_limit()

        if headers is None:
            headers = {}

        # Build request based on location
        request_kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "headers": headers,
            **kwargs,
        }

        url = path

        if method.upper() in ("GET", "HEAD", "DELETE"):
            if payload and location == "query":
                # Add payload to query string
                query_string = urlencode(payload)
                url = f"{path}?{query_string}" if "?" not in path else f"{path}&{query_string}"
        elif method.upper() in ("POST", "PUT", "PATCH"):
            if payload:
                if location == "body":
                    request_kwargs["json"] = payload
                elif location == "query":
                    query_string = urlencode(payload)
                    url = f"{path}?{query_string}" if "?" not in path else f"{path}&{query_string}"
                elif location == "header":
                    headers.update({k: str(v) for k, v in payload.items()})
                    request_kwargs["headers"] = headers
                elif location == "cookie":
                    request_kwargs["cookies"] = payload

        request_headers = request_kwargs.pop("headers", {})

        start_time = time.perf_counter()

        try:
            # Execute request based on method
            if method.upper() == "GET":
                response = await self._client.get(
                    url,
                    params=payload,
                    headers=request_headers,
                )
            elif method.upper() in ("POST", "PUT", "PATCH"):
                response = await self._client.request(
                    method.upper(),
                    url,
                    json=payload if location == "body" else None,
                    params=payload if location == "query" else None,
                    headers=request_headers,
                )
            elif method.upper() == "DELETE":
                response = await self._client.delete(
                    url,
                    headers=request_headers,
                )
            elif method.upper() == "HEAD":
                response = await self._client.head(
                    url,
                    params=payload,
                    headers=request_headers,
                )
            else:
                response = await self._client.request(
                    method.upper(),
                    url,
                    **request_kwargs,
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Try to parse JSON response
            body = response.text
            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError):
                pass

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body,
                "elapsed_ms": elapsed_ms,
                "error": None,
                "url": str(response.url),
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
