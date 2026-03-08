"""Dynamic API Discovery (Spidering) for Chaos Kitten.

A recursive async crawler that discovers unlisted or hidden API endpoints
by parsing HTML pages, following internal links, and extracting API paths
from ``<script>`` sources, ``<form>`` actions, and inline JavaScript
fetch/XHR calls.
"""

from __future__ import annotations

import asyncio
import logging
import re
import warnings
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Link / endpoint extraction
# ---------------------------------------------------------------------------

# Patterns to catch fetch("/api/..."), axios.get("/api/..."), etc.
_JS_URL_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|XMLHttpRequest"""
    r"""|\.open|\.ajax|url\s*[:=])\s*\(?\s*['"`]([^'"`\s]{2,})['"`]""",
    re.IGNORECASE,
)

# Patterns for common API path shapes  /api/..., /v1/..., /graphql, etc.
_API_PATH_RE = re.compile(
    r"""['"`](\/(?:api|v\d+|graphql|rest|auth|admin|internal|webhook|ws)[^\s'"`<>]*)['"`]""",
    re.IGNORECASE,
)


class _LinkExtractor(HTMLParser):
    """Fast HTML parser that collects hrefs, form actions, and script srcs."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []
        self._in_script = False
        self._script_data: List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])
        elif tag == "form" and "action" in attr_dict:
            self.links.append(attr_dict["action"])
        elif tag == "script":
            src = attr_dict.get("src")
            if src:
                self.scripts.append(src)
            self._in_script = True
            self._script_data = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            inline = "".join(self._script_data)
            if inline:
                self.scripts.append(inline)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_data.append(data)

    def error(self, message: str) -> None:  # pragma: no cover
        pass


def extract_links(html: str, base_url: str) -> Set[str]:
    """Return absolute URLs found in *html* resolved against *base_url*."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        pass

    urls: Set[str] = set()
    for href in parser.links:
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        urls.add(urljoin(base_url, href))
    return urls


def extract_api_endpoints(html: str) -> Set[str]:
    """Extract API-style paths from inline/external JS and raw HTML."""
    endpoints: Set[str] = set()
    for match in _JS_URL_RE.finditer(html):
        path = match.group(1)
        if path.startswith("/"):
            endpoints.add(path)
    for match in _API_PATH_RE.finditer(html):
        endpoints.add(match.group(1))
    return endpoints


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

class Spider:
    """Async recursive spider for dynamic API endpoint discovery.

    Parameters
    ----------
    base_url : str
        The application root URL (e.g. ``http://localhost:8080``).
    max_depth : int
        Maximum crawl depth from the start URL.
    max_pages : int
        Maximum number of pages to visit (safety cap).
    concurrency : int
        Number of concurrent requests.
    timeout : float
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        concurrency: int = 5,
        timeout: float = 10.0,
    ) -> None:
        parsed = urlparse(base_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.base_netloc = parsed.netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout

        self.visited: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_links: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self) -> Dict[str, Any]:
        """Run the spider starting from *base_url*.

        Returns
        -------
        dict
            ``{"pages_visited": int, "endpoints": [...], "links": [...]}``
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put((self.base_url, 0))

        logger.warning(
            "TLS certificate verification is disabled for spidering. "
            "This is necessary for testing but exposes the spider to "
            "potential MITM attacks in production environments."
        )
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,  # Required for local/staging targets with self-signed certs
        ) as client:
            workers = [
                asyncio.create_task(self._worker(client, queue, semaphore))
                for _ in range(self.concurrency)
            ]
            # Wait for the queue to be fully processed
            await queue.join()

            # Signal workers to stop
            for _ in workers:
                await queue.put(None)  # type: ignore[arg-type]
            await asyncio.gather(*workers)

        logger.info(
            "Spider complete: visited %d pages, discovered %d endpoints",
            len(self.visited),
            len(self.discovered_endpoints),
        )

        return {
            "pages_visited": len(self.visited),
            "endpoints": sorted(self.discovered_endpoints),
            "links": sorted(self.discovered_links),
        }

    # ------------------------------------------------------------------
    # Internal workers
    # ------------------------------------------------------------------

    async def _worker(
        self,
        client: httpx.AsyncClient,
        queue: asyncio.Queue,
        semaphore: asyncio.Semaphore,
    ) -> None:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break
            url, depth = item
            try:
                await self._process_url(client, queue, semaphore, url, depth)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Spider error on %s: %s", url, exc)
            finally:
                queue.task_done()

    async def _process_url(
        self,
        client: httpx.AsyncClient,
        queue: asyncio.Queue,
        semaphore: asyncio.Semaphore,
        url: str,
        depth: int,
    ) -> None:
        # --- SSRF guard: only fetch URLs on our target host ---------------
        parsed_url = urlparse(url)
        if parsed_url.netloc != self.base_netloc:
            logger.warning("Skipping external URL (SSRF protection): %s", url)
            return

        # --- Atomic dedup & max-pages check --------------------------------
        # Check *and* add in one step so concurrent workers can't both pass
        # the ``if url in self.visited`` guard before either calls ``add``.
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        self.visited.add(url)  # Mark visited BEFORE the HTTP request

        async with semaphore:
            try:
                response = await client.get(url)
            except httpx.RequestError as exc:
                logger.debug("Request failed for %s: %s", url, exc)
                return

        # Skip non-HTML responses (images, JSON APIs, etc.)
        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return

        body = response.text

        # Extract links and API endpoints
        links = extract_links(body, url)
        api_endpoints = extract_api_endpoints(body)

        self.discovered_endpoints.update(api_endpoints)

        # Track all discovered internal links
        for link in links:
            parsed = urlparse(link)
            if parsed.netloc == self.base_netloc:
                self.discovered_links.add(link)
                # Only enqueue for further crawling within depth limit
                if depth < self.max_depth and link not in self.visited:
                    await queue.put((link, depth + 1))

    # ------------------------------------------------------------------
    # Utility: convert discoveries to endpoint dicts for AttackPlanner
    # ------------------------------------------------------------------

    def to_endpoint_dicts(self) -> List[Dict[str, Any]]:
        """Convert discovered endpoints into dicts compatible with the
        orchestrator's ``AgentState`` and ``AttackPlanner``.

        Each discovered path is returned as a ``GET`` endpoint with no
        parameters (since we don't know the schema).  The planner and
        chaos engine will still probe them for vulnerabilities.
        """
        endpoints: List[Dict[str, Any]] = []
        for path in sorted(self.discovered_endpoints):
            endpoints.append({
                "method": "GET",
                "path": path,
                "parameters": [],
                "requestBody": None,
                "source": "spider",
            })
        return endpoints
