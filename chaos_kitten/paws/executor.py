"""HTTP executor for sending payloads to endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, Optional, Union
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
        enable_logging: bool = False,
        log_file: Optional[str] = None,
    ) -> None:
        """Initialize the executor.

        Args:
            base_url: Base URL for the API
            auth_type: Authentication type (none, bearer, basic, api_key)
            auth_token: Authentication token/credentials
            rate_limit: Maximum requests per second (0 = no limit)
            timeout: Request timeout in seconds
<<<<<<< 119
=======
            enable_logging: Enable request/response logging
            log_file: Optional file path to save logs
        
        Raises:
            ValueError: If auth_type is not supported.
>>>>>>> main
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout
<<<<<<< 119

        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0

    async def __aenter__(self) -> "Executor":
        """Async context manager entry."""
        await self._ensure_client()
=======
        self.enable_logging = enable_logging
        self.log_file = log_file
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0.0
        
        # Set up logging
        self._setup_logging()
    
    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
>>>>>>> main
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
<<<<<<< 119
            self._client = None

    def _build_headers(self) -> dict[str, str]:
        """Build authentication headers."""
        headers = {}
        if self.auth_type == "bearer":
=======
        
        # Close file handler to prevent resource leak
        if self.enable_logging and self.log_file:
            for handler in self._logger.handlers[:]:
                handler.close()
                self._logger.removeHandler(handler)
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}
        
        if self.auth_type in ("bearer", "oauth") and self.auth_token:
>>>>>>> main
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
<<<<<<< 119

=======
        
        # Log request (timestamp created inside if logging enabled)
        self._log_request(
            method=method,
            path=path,
            headers=request_headers,
            payload=payload or graphql_query,
        )
        
>>>>>>> main
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
<<<<<<< 119

            # Try to parse JSON response
            body = response.text
            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError):
                pass

            return {
=======
            
            result = {
>>>>>>> main
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body,
                "elapsed_ms": elapsed_ms,
                "error": None,
                "url": str(response.url),
            }
<<<<<<< 119

=======
            
            # Log response
            self._log_response(
                status_code=result["status_code"],
                headers=result["headers"],
                body=result["body"],
                elapsed_ms=result["elapsed_ms"],
                error=result["error"],
            )
            
            return result
            
>>>>>>> main
        except httpx.TimeoutException as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"Request timeout: {str(e)}"
            logger.warning(f"Timeout executing {method} {path}: {e}")
            
            result = {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed_ms": elapsed_ms,
                "error": error_msg,
            }
<<<<<<< 119

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
=======
            
            # Log error response
            self._log_response(
                status_code=result["status_code"],
                headers=result["headers"],
                body=result["body"],
                elapsed_ms=result["elapsed_ms"],
                error=result["error"],
            )
            
            return result
            
        # ... (rest of exception handling remains similar, ensuring closing indent)
        except httpx.ConnectError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Connection error: {str(e)}"
             logger.warning(f"Connection error executing {method} {path}: {e}")
             
             result = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log error response
             self._log_response(
                 status_code=result["status_code"],
                 headers=result["headers"],
                 body=result["body"],
                 elapsed_ms=result["elapsed_ms"],
                 error=result["error"],
             )
             
             return result
             
        except httpx.HTTPError as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"HTTP error: {str(e)}"
             logger.warning(f"HTTP error executing {method} {path}: {e}")
             
             result = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log error response
             self._log_response(
                 status_code=result["status_code"],
                 headers=result["headers"],
                 body=result["body"],
                 elapsed_ms=result["elapsed_ms"],
                 error=result["error"],
             )
             
             return result
             
        except Exception as e:
             elapsed_ms = (time.perf_counter() - start_time) * 1000
             error_msg = f"Unexpected error: {str(e)}"
             logger.warning(f"Unexpected error executing {method} {path}: {e}")
             
             result = {
                 "status_code": 0,
                 "headers": {},
                 "body": "",
                 "elapsed_ms": elapsed_ms,
                 "error": error_msg,
             }
             
             # Log error response
             self._log_response(
                 status_code=result["status_code"],
                 headers=result["headers"],
                 body=result["body"],
                 elapsed_ms=result["elapsed_ms"],
                 error=result["error"],
             )
             
             return result
    
    def _setup_logging(self) -> None:
        """Set up logging for the executor instance."""
        if not self.enable_logging:
            return
        
        # Use per-instance logger name to avoid handler corruption
        self._logger = logging.getLogger(f"{__name__}.executor.{id(self)}")
        self._logger.setLevel(logging.DEBUG)
        
        # Fresh logger has no handlers; no need to clear
        
        # Console handler for DEBUG and above
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self._logger.addHandler(console_handler)
        
        # File handler if log_file is specified
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file, mode='a')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(console_formatter)
            self._logger.addHandler(file_handler)
    
    def _redact_sensitive_data(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive information from headers.
        
        Args:
            headers: Dictionary of headers to redact
            
        Returns:
            Dictionary with redacted headers
        """
        redacted = headers.copy()
        sensitive_keys = [
            "authorization", "x-api-key", "api-key", "apikey",
            "x-auth-token", "auth-token", "cookie", "set-cookie"
        ]
        
        for key in redacted:
            if key.lower() in sensitive_keys:
                redacted[key] = "[REDACTED]"
        
        return redacted
    
    def _redact_query_params(self, url: str) -> str:
        """Redact sensitive query parameters from URL.
        
        Args:
            url: URL to redact
            
        Returns:
            URL with redacted sensitive query parameters
        """
        # Common patterns for API keys in query params
        patterns = [
            (r'([?&])(api[-_]?key|apikey)=([^&#]*)', r'\1\2=[REDACTED]'),
            (r'([?&])(token|access[-_]?token)=([^&#]*)', r'\1\2=[REDACTED]'),
            (r'([?&])(auth|authorization)=([^&#]*)', r'\1\2=[REDACTED]'),
            (r'([?&])(secret|password|pwd)=([^&#]*)', r'\1\2=[REDACTED]'),
        ]
        
        redacted_url = url
        for pattern, replacement in patterns:
            redacted_url = re.sub(pattern, replacement, redacted_url, flags=re.IGNORECASE)
        
        return redacted_url
    
    def _truncate_body(self, body: str, max_chars: int = 500) -> str:
        """Truncate body to max_chars, adding ellipsis if truncated.
        
        Args:
            body: Body content to truncate
            max_chars: Maximum characters to include
            
        Returns:
            Truncated body string
        """
        if len(body) <= max_chars:
            return body
        return body[:max_chars] + "... [truncated]"
    
    def _log_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        payload: Optional[Any] = None,
    ) -> None:
        """Log HTTP request details.
        
        Args:
            method: HTTP method
            path: Request path
            headers: Request headers
            payload: Request body/payload
        """
        if not self.enable_logging:
            return
        
        ts = datetime.now()
        full_url = f"{self.base_url}{path}"
        redacted_url = self._redact_query_params(full_url)
        redacted_headers = self._redact_sensitive_data(headers)
        
        self._logger.info(
            f"REQUEST [{ts.isoformat()}] {method} {redacted_url}"
        )
        self._logger.debug(f"Request Headers: {redacted_headers}")
        
        if payload:
            payload_str = str(payload)
            truncated_payload = self._truncate_body(payload_str, max_chars=500)
            self._logger.debug(f"Request Body: {truncated_payload}")
    
    def _log_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        elapsed_ms: float,
        error: Optional[str] = None,
    ) -> None:
        """Log HTTP response details.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            elapsed_ms: Response time in milliseconds
            error: Error message if request failed
        """
        if not self.enable_logging:
            return
        
        redacted_headers = self._redact_sensitive_data(headers)
        
        if error:
            self._logger.error(
                f"RESPONSE [ERROR] Status: {status_code}, Time: {elapsed_ms:.2f}ms, Error: {error}"
            )
            # Log full body for Python exceptions (if body exists)
            if body:
                self._logger.error(f"Response Body: {body}")
        else:
            log_level = logging.INFO if 200 <= status_code < 300 else logging.WARNING
            self._logger.log(
                log_level,
                f"RESPONSE Status: {status_code}, Time: {elapsed_ms:.2f}ms"
            )
            self._logger.debug(f"Response Headers: {redacted_headers}")
            
            # For 2xx: truncate body; for 4xx/5xx: log full body at WARNING
            if 200 <= status_code < 300:
                truncated_body = self._truncate_body(body, max_chars=500)
                self._logger.debug(f"Response Body: {truncated_body}")
            else:
                # Log full body for HTTP error responses (4xx/5xx)
                self._logger.log(log_level, f"Response Body: {body}")
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting using token bucket algorithm."""
        if not self._rate_limiter:
            return
        
        # Acquire semaphore token
        async with self._rate_limiter:
            # Calculate time since last request
            current_time = time.perf_counter()
            
            if self._last_request_time is not None:
                time_since_last = current_time - self._last_request_time
                
                # Minimum time between requests (in seconds)
                min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
                
                # Sleep if we're going too fast
                if time_since_last < min_interval:
                    await asyncio.sleep(min_interval - time_since_last)
            
            # Update last request time
            self._last_request_time = time.perf_counter()
>>>>>>> main
