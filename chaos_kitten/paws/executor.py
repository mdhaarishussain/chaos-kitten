"""HTTP executor for sending payloads to endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class Executor:
    """Execute HTTP requests with payloads and report results."""

    def __init__(self, timeout: int = 30) -> None:
        """Initialize the executor.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout

    async def execute(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        graphql_query: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an attack request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path
            payload: Request body/parameters
            files: Files to upload (for multipart/form-data)
            graphql_query: Raw GraphQL query string (will be wrapped in JSON)
            headers: Additional headers
            **kwargs: Additional arguments for httpx
            
        Returns:
            Response dict with status, body, headers, etc.
        """
        if headers is None:
            headers = {}

        # Build request based on location
        request_kwargs = {
            "timeout": self.timeout,
            "headers": headers,
            **kwargs,
        }

        if method.upper() in ("GET", "HEAD", "DELETE"):
            if payload and location == "query":
                # Add payload to query string
                query_string = urlencode(payload)
                url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"
        elif method.upper() in ("POST", "PUT", "PATCH"):
            if payload:
                if location == "body":
                    request_kwargs["json"] = payload
                elif location == "query":
                    query_string = urlencode(payload)
                    url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"
                elif location == "header":
                    headers.update({k: str(v) for k, v in payload.items()})
                    request_kwargs["headers"] = headers
                elif location == "cookie":
                    request_kwargs["cookies"] = payload

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
                    # GraphQL is typically POST-only; warn if a different method was requested
                    if method != "POST":
                        logger.debug(
                            "GraphQL queries are typically sent via POST, "
                            "but '%s' was requested for %s", method, path
                        )
                    # GraphQL usually expects {"query": "...", "variables": {...}}
                    # payload can be used for variables if provided
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
                    "status": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                    "elapsed": response.elapsed.total_seconds() if response.elapsed else 0,
                    "url": str(response.url),
                    "reason": response.reason_phrase,
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
