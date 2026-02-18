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
        url: str,
        payload: dict[str, Any] | None = None,
        location: str = "body",
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Execute an HTTP request with a payload.
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Target URL
            payload: Payload to send
            location: Where to place the payload (query, body, header, cookie, path)
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
            async with httpx.AsyncClient() as client:
                response = await client.request(method.upper(), url, **request_kwargs)

                return {
                    "status": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                    "elapsed": response.elapsed.total_seconds() if response.elapsed else 0,
                    "url": str(response.url),
                    "reason": response.reason_phrase,
                }
        except asyncio.TimeoutError:
            return {
                "status": 0,
                "body": "Request timeout",
                "headers": {},
                "elapsed": self.timeout,
                "url": url,
                "reason": "Timeout",
            }
        except Exception as exc:
            logger.error("Executor error: %s", exc)
            return {
                "status": 0,
                "body": str(exc),
                "headers": {},
                "elapsed": 0,
                "url": url,
                "reason": "Error",
            }
