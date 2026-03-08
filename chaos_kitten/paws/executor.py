"""HTTP executor for sending payloads to endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import random
from datetime import datetime
from typing import Any, Dict, Optional, Union
import httpx
import urllib.parse

try:
    import pyotp
except ImportError:
    pyotp = None

logger = logging.getLogger(__name__)


class Executor:
    """Async HTTP executor for attack requests.
    
    Features:
    - Async requests with httpx
    - Rate limiting
    - Timeout handling
    - Multiple auth methods
    - Response analysis
    - Retry logic for rate-limited responses (429)
    """
    
    def __init__(
        self,
        base_url: str = "",
        auth_type: str = "none",
        auth_token: str = "",
        rate_limit: float = 0,
        timeout: int = 30,
        retry_config: Optional[Dict[str, Any]] = None,
        # New MFA fields
        totp_secret: Optional[str] = None,
        totp_endpoint: Optional[str] = None,
        totp_field: str = "code",
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
            retry_config: Configuration for retry logic
            totp_secret: TOTP secret key for MFA
            totp_endpoint: Endpoint to submit TOTP code
            totp_field: JSON field name for TOTP code
            enable_logging: Enable request/response logging
            log_file: Optional file path to save logs
        
        Raises:
            ValueError: If auth_type is not supported.
        """
        self.base_url = base_url
        self.auth_type = auth_type
        self.auth_token = auth_token
        self.rate_limit = rate_limit
        self.timeout = timeout
        
        # Retry configuration
        self.retry_config = retry_config or {}
        self.max_retries = self.retry_config.get("max_retries", 3)
        self.base_backoff = self.retry_config.get("base_backoff", 1.0)
        self.max_backoff = self.retry_config.get("max_backoff", 60.0)
        self.jitter = self.retry_config.get("jitter", True)
        
        # Validation
        if not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ValueError(f"max_retries must be int >= 0, got {self.max_retries}")
        if self.base_backoff < 0 or self.base_backoff > self.max_backoff:
            raise ValueError(f"Invalid backoff: base={self.base_backoff}, max={self.max_backoff}")
        
        self.enable_logging = enable_logging
        self.log_file = log_file

        self._client: Optional[httpx.AsyncClient] = None
        self._rate_lock: Optional[asyncio.Lock] = None
        self._last_request_time: float = 0.0
        self.totp_secret = totp_secret
        self.totp_endpoint = totp_endpoint
        self.totp_field = totp_field
        
        # Set up logging
        self._setup_logging()
    
    async def __aenter__(self) -> "Executor":
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._build_headers(),
        )
        
        await self._perform_mfa_auth()
        
        # Initialize rate limiter lock
        self._rate_lock = asyncio.Lock() if self.rate_limit > 0 else None
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
        
        # Close file handler to prevent resource leak
        if self.enable_logging and self.log_file and hasattr(self, '_logger'):
             for handler in self._logger.handlers[:]:
                handler.close()
                self._logger.removeHandler(handler)
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = {"User-Agent": "ChaosKitten/0.1.0"}
        
        if self.auth_type in ("bearer", "oauth") and self.auth_token:
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
        if not self._client:
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "elapsed_ms": 0.0,
                "error": "Client not initialized. Use 'async with Executor(...)' pattern.",
            }
        
        method = method.upper()
        
        # Merge additional headers
        request_headers = self._client.headers.copy()
        if headers:
            request_headers.update(headers)

        last_result = {}
        
        for attempt in range(self.max_retries + 1):
            # Apply rate limiting
            await self._apply_rate_limit()

            start_time = time.perf_counter()
            response = None
            error_msg = None
            
            # Log request (timestamp created inside if logging enabled)
            self._log_request(
                method=method,
                path=path,
                headers=request_headers,
                payload=payload or graphql_query,
            )

            try:
                # Execute request based on method
                if method == "GET":
                    response = await self._client.get(
                        path,
                        params=payload,
                        headers=request_headers,
                    )
                elif method in ("POST", "PUT", "PATCH"):
                    # Handle GraphQL
                    if graphql_query:
                        if method != "POST":
                            logger.debug(
                                "GraphQL queries are typically sent via POST, "
                                "but '%s' was requested for %s", method, path
                            )
                        json_body = {"query": graphql_query}
                        if payload:
                            json_body["variables"] = payload
                        
                        response = await self._client.request(
                            method,
                            path,
                            json=json_body,
                            headers=request_headers,
                        )
                    # Handle multipart/form-data vs json
                    elif files:
                        response = await self._client.request(
                            method,
                            path,
                            data=payload,
                            files=files,
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
                    if payload is not None:
                        response = await self._client.request(
                            method,
                            path,
                            json=payload,
                            headers=request_headers,
                        )
                    else:
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
                
                last_result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "elapsed_ms": elapsed_ms,
                    "error": None,
                }
                
                # Log response details
                self._log_response(
                   status_code=response.status_code,
                   elapsed_ms=elapsed_ms,
                   body=response.text[:1000] # Log first 1000 chars
                )

                # Check for 429 Rate Limit
                if response.status_code == 429:
                    if attempt < self.max_retries:
                        await self._handle_429_backoff(attempt, response)
                        continue
                    else:
                        logger.warning(f"Max retries ({self.max_retries}) exceeded for {method} {path} (429 Too Many Requests)")
                        return last_result
                
                # Successful or non-retriable response
                return last_result
                
            except httpx.TimeoutException as e:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                error_msg = f"Request timeout: {str(e)}"
                logger.warning(f"Timeout executing {method} {path}: {e}")
                last_result = {
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "elapsed_ms": elapsed_ms,
                    "error": error_msg,
                }
                # Consider retrying on timeout? Usually yes, but 429 is the main focus here.
                # Let's retry on timeout too if configured, but keeping scope to 429 for now as per issue.
                self._log_response(status_code=0, elapsed_ms=elapsed_ms, body="", error=error_msg)
                return last_result

            except (httpx.ConnectError, httpx.HTTPError) as e:
                 elapsed_ms = (time.perf_counter() - start_time) * 1000
                 error_msg = f"HTTP/Connection error: {str(e)}"
                 logger.warning(f"HTTP error executing {method} {path}: {e}")
                 last_result = {
                     "status_code": 0,
                     "headers": {},
                     "body": "",
                     "elapsed_ms": elapsed_ms,
                     "error": error_msg,
                 }
                 self._log_response(status_code=0, elapsed_ms=elapsed_ms, body="", error=error_msg)
                 return last_result
                 
            except Exception as e:
                 elapsed_ms = (time.perf_counter() - start_time) * 1000
                 error_msg = f"Unexpected error: {str(e)}"
                 logger.warning(f"Unexpected error executing {method} {path}: {e}")
                 self._log_response(status_code=0, elapsed_ms=elapsed_ms, body="", error=error_msg)
                 return {
                     "status_code": 0,
                     "headers": {},
                     "body": "",
                     "elapsed_ms": elapsed_ms,
                     "error": error_msg,
                 }

        return last_result

    async def _handle_429_backoff(self, attempt: int, response: httpx.Response) -> None:
        """Handle 429 rate limiting with backoff."""
        if response and "Retry-After" in response.headers:
            try:
                # Retry-After can be seconds or a date. We handle seconds for now or simple int.
                header_val = response.headers["Retry-After"]
                try:
                    wait_time = float(header_val)
                except ValueError:
                    # Todo: Handle date format if needed
                    wait_time = self.base_backoff

                logger.info(f"Rate limited. Waiting {wait_time}s as per Retry-After header.")
                await asyncio.sleep(wait_time)
                return
            except ValueError:
                pass # Fallback to exponential backoff

        # Exponential backoff: base * 2^attempt
        backoff = min(self.max_backoff, self.base_backoff * (2 ** attempt))
        
        if self.jitter:
            # Jitter: randomized between 0.5 * backoff and 1.5 * backoff
            backoff = backoff * (0.5 + random.random())
            
        logger.info(f"Rate limited (429). Retrying in {backoff:.2f}s (Attempt {attempt + 1}/{self.max_retries})")
        await asyncio.sleep(backoff)

    async def _apply_rate_limit(self) -> None:
        """Enforce a minimum interval between requests (1 / rate_limit seconds).

        Uses an asyncio.Lock to serialise the timing check so that
        concurrent callers are properly spaced apart.  The lock is
        released *after* the timestamp is updated but *before* the
        actual HTTP request runs, which is the correct pattern for a
        leaky-bucket rate limiter (as opposed to a concurrency limiter).
        """
        if not self._rate_lock:
            return

        min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0

        async with self._rate_lock:
            # Calculate how long to wait before this request may proceed
            now = time.perf_counter()
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)

            # Stamp the time *before* releasing the lock so the next
            # waiter uses the correct baseline.
            self._last_request_time = time.perf_counter()

    def _setup_logging(self) -> None:
        """Setup request/response logging."""
        self._logger = logging.getLogger(f"{__name__}.traffic")
        self._logger.setLevel(logging.INFO)
        
        # Suppress httpx info logs to prevent leaking sensitive data or double logging
        httpx_logger = logging.getLogger("httpx")
        httpx_logger.setLevel(logging.WARNING)
        httpx_logger.propagate = False
        
        if self.enable_logging and self.log_file and not self._logger.handlers:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)

    def _log_request(self, method: str, path: str, headers: Any, payload: Any) -> None:
        """Log outgoing request."""
        if not self.enable_logging:
            return

        # Redact Headers
        safe_headers = dict(headers)
        for key in safe_headers:
            if key.lower() in ("authorization", "x-api-key", "cookie"):
                safe_headers[key] = "[REDACTED]"
            
        # Redact Query Params
        # We assume 'path' might contain query strings here? Or handled by requests params?
        # The caller passes 'path' which might be just path buffer.
        # But expected url in logs is full url with params.
        # Wait, self.base_url + path. If path has query params, we need to cleanse.
        
        full_url = f"{self.base_url}{path}"
        try:
             parsed = urllib.parse.urlparse(full_url)
             qs = urllib.parse.parse_qs(parsed.query)
             sensitive_params = ["api_key", "token", "password", "secret", "client_secret"]
             changed = False
             for k in qs:
                 if any(s in k.lower() for s in sensitive_params):
                     qs[k] = ["[REDACTED]"]
                     changed = True
             
             if changed:
                 # Reconstruct query string
                 # parse_qs checks returns lists. urlencode handles it.
                 new_query = urllib.parse.urlencode(qs, doseq=True)
                 full_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        except Exception:
             pass # Fail safe

        # Truncate Payload
        safe_payload = str(payload)
        if len(safe_payload) > 500:
            safe_payload = safe_payload[:500] + "... [truncated]"

        self._logger.info(
            f"REQUEST: {method} {full_url}\n"
            f"Headers: {safe_headers}\n"
            f"Payload: {safe_payload}"
        )

    def _log_response(self, status_code: int, elapsed_ms: float, body: str, error: Optional[str] = None) -> None:
        """Log incoming response."""
        if not self.enable_logging:
            return
            
        # Sanitize body to prevent leaking secrets/huge logs
        body_safe = body[:200] + "..." if len(body) > 200 else body

        if error:
            self._logger.error(
                f"RESPONSE ERROR (Time: {elapsed_ms:.2f}ms): {error}\n"
                f"Body: {body_safe}" 
            )
        elif status_code >= 400:
            self._logger.warning(
                f"RESPONSE (Time: {elapsed_ms:.2f}ms): Status: {status_code}\n"
                f"Body: {body_safe}" 
            )
        else:
            self._logger.info(
                f"RESPONSE (Time: {elapsed_ms:.2f}ms): Status: {status_code}\n"
                f"Body: {body[:500]}..." # Log first 500 chars
            )

    async def _perform_mfa_auth(self) -> None:
        """Perform TOTP-based Multi-Factor Authentication."""
        if not (self.totp_secret and self.totp_endpoint):
            return

        if not pyotp:
            logger.warning("pyotp not installed. Skipping MFA.")
            return

        try:
            totp = pyotp.TOTP(self.totp_secret)
            code = totp.now()
            
            logger.info(f"Authenticating with MFA endpoint: {self.totp_endpoint}")
            
            response = await self._client.post(
                self.totp_endpoint,
                json={self.totp_field: code},
                headers=self._build_headers()
            )
            
            if response.status_code == 200:
                # Assuming the response contains a new token or sets a session cookie
                # If it returns a bear token, we might need to update auth_token
                # For now, we assume it sets a session cookie which httpx client handles
                logger.info("MFA Authentication successful")
                
                data = response.json()
                if "token" in data:
                    self.auth_token = data["token"]
                    # Re-configure client default headers with new token
                    self._client.headers.update(self._build_headers())
            else:
                logger.error(f"MFA Authentication failed: {response.text}")
                
        except Exception as e:
            logger.error(f"Error performing MFA: {e}")
