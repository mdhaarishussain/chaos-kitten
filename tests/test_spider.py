"""Tests for the Dynamic API Discovery (Spider) module."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from chaos_kitten.brain.spider import (
    Spider,
    extract_links,
    extract_api_endpoints,
    _LinkExtractor,
)


# ── Unit tests: link extraction ────────────────────────────────────────


class TestExtractLinks:
    def test_extracts_hrefs(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        links = extract_links(html, "http://example.com")
        assert "http://example.com/about" in links
        assert "http://example.com/contact" in links

    def test_resolves_relative_urls(self):
        html = '<a href="page.html">Page</a>'
        links = extract_links(html, "http://example.com/dir/")
        assert "http://example.com/dir/page.html" in links

    def test_extracts_form_actions(self):
        html = '<form action="/login"><input type="submit"></form>'
        links = extract_links(html, "http://example.com")
        assert "http://example.com/login" in links

    def test_skips_javascript_and_anchors(self):
        html = '<a href="#">Top</a><a href="javascript:void(0)">JS</a>'
        links = extract_links(html, "http://example.com")
        assert len(links) == 0

    def test_skips_mailto(self):
        html = '<a href="mailto:test@test.com">Email</a>'
        links = extract_links(html, "http://example.com")
        assert len(links) == 0

    def test_handles_malformed_html(self):
        html = '<a href="/ok"><div>unclosed'
        links = extract_links(html, "http://example.com")
        assert "http://example.com/ok" in links


class TestExtractApiEndpoints:
    def test_finds_fetch_calls(self):
        js = 'fetch("/api/users").then(r => r.json())'
        endpoints = extract_api_endpoints(js)
        assert "/api/users" in endpoints

    def test_finds_axios_calls(self):
        js = 'axios.get("/api/v1/items")'
        endpoints = extract_api_endpoints(js)
        assert "/api/v1/items" in endpoints

    def test_finds_api_paths_in_strings(self):
        html = '<script>var url = "/api/v2/orders";</script>'
        endpoints = extract_api_endpoints(html)
        assert "/api/v2/orders" in endpoints

    def test_finds_admin_paths(self):
        html = 'const panel = "/admin/dashboard";'
        endpoints = extract_api_endpoints(html)
        assert "/admin/dashboard" in endpoints

    def test_finds_graphql(self):
        html = 'const gql = "/graphql";'
        endpoints = extract_api_endpoints(html)
        assert "/graphql" in endpoints

    def test_ignores_non_api_paths(self):
        html = 'const x = "/images/logo.png";'
        endpoints = extract_api_endpoints(html)
        assert len(endpoints) == 0


# ── Unit tests: LinkExtractor HTML parser ──────────────────────────────


class TestLinkExtractor:
    def test_collects_script_src(self):
        parser = _LinkExtractor()
        parser.feed('<script src="/js/app.js"></script>')
        assert "/js/app.js" in parser.scripts

    def test_collects_inline_script(self):
        parser = _LinkExtractor()
        parser.feed('<script>var a = 1;</script>')
        assert "var a = 1;" in parser.scripts


# ── Integration tests: Spider ──────────────────────────────────────────


class TestSpider:
    def test_init_parses_base_url(self):
        spider = Spider("http://example.com:8080/app")
        assert spider.base_url == "http://example.com:8080"
        assert spider.base_netloc == "example.com:8080"

    @pytest.mark.asyncio
    async def test_crawl_visits_pages(self):
        """Spider should visit the start page and follow internal links."""
        spider = Spider("http://example.com", max_depth=1, max_pages=10)

        page_html = {
            "http://example.com": (
                '<html><body>'
                '<a href="/about">About</a>'
                '<script>fetch("/api/users")</script>'
                '</body></html>'
            ),
            "http://example.com/about": (
                '<html><body><h1>About</h1></body></html>'
            ),
        }

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = page_html.get(str(url), "<html></html>")
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await spider.crawl()

        assert results["pages_visited"] >= 1
        assert "/api/users" in results["endpoints"]

    @pytest.mark.asyncio
    async def test_crawl_respects_max_pages(self):
        """Spider should stop after visiting max_pages."""
        spider = Spider("http://example.com", max_depth=10, max_pages=2)

        # Generate pages that link to each other (cycle)
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = '<a href="/page1">1</a><a href="/page2">2</a><a href="/page3">3</a>'
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await spider.crawl()

        assert results["pages_visited"] <= 2

    @pytest.mark.asyncio
    async def test_crawl_handles_request_errors(self):
        """Spider should handle connection errors gracefully."""
        import httpx as httpx_mod

        spider = Spider("http://example.com", max_depth=1)

        async def mock_get(url, **kwargs):
            raise httpx_mod.RequestError("Connection refused")

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await spider.crawl()

        # Should complete without raising, even though all requests failed
        assert results["pages_visited"] <= 1

    def test_to_endpoint_dicts(self):
        spider = Spider("http://example.com")
        spider.discovered_endpoints = {"/api/users", "/api/items", "/admin/panel"}

        dicts = spider.to_endpoint_dicts()

        assert len(dicts) == 3
        paths = {d["path"] for d in dicts}
        assert "/api/users" in paths
        assert "/api/items" in paths
        assert "/admin/panel" in paths
        # All should be GET with source=spider
        for d in dicts:
            assert d["method"] == "GET"
            assert d["source"] == "spider"

    def test_to_endpoint_dicts_empty(self):
        spider = Spider("http://example.com")
        dicts = spider.to_endpoint_dicts()
        assert dicts == []

    @pytest.mark.asyncio
    async def test_ssrf_external_url_blocked(self):
        """External URLs injected into the queue must not be fetched."""
        spider = Spider("http://example.com", max_depth=2)

        fetch_urls = []

        async def mock_get(url, **kwargs):
            fetch_urls.append(str(url))
            resp = MagicMock()
            # Page with a malicious external link (attacker-controlled HTML)
            resp.text = (
                '<a href="http://169.254.169.254/latest/meta-data/">AWS</a>'
                '<a href="http://localhost:6379/">Redis</a>'
                '<a href="/safe-page">Safe</a>'
            )
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            await spider.crawl()

        # None of the external URLs should have been fetched
        for url in fetch_urls:
            assert "169.254.169.254" not in url, f"SSRF: fetched cloud metadata URL {url}"
            assert "localhost:6379" not in url, f"SSRF: fetched internal service URL {url}"

    @pytest.mark.asyncio
    async def test_non_html_responses_skipped(self):
        """Non-HTML responses (JSON, images) should not be parsed for links."""
        spider = Spider("http://example.com", max_depth=2)

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if str(url) == "http://example.com":
                resp.text = '<a href="/api/data">API</a>'
                resp.headers = {"content-type": "text/html; charset=utf-8"}
            else:
                # /api/data returns JSON, NOT HTML
                resp.text = '{"links": ["/api/secret"]}'
                resp.headers = {"content-type": "application/json"}
            return resp

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await spider.crawl()

        # /api/secret should NOT be discovered since it was in a JSON response
        assert "/api/secret" not in results["endpoints"]

    @pytest.mark.asyncio
    async def test_visited_paths_not_added_as_endpoints(self):
        """Visited HTML page paths like /about should not appear as API endpoints."""
        spider = Spider("http://example.com", max_depth=1)

        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.text = '<a href="/about">About</a><script>fetch("/api/users")</script>'
            resp.headers = {"content-type": "text/html"}
            return resp

        mock_client = AsyncMock()
        mock_client.get = mock_get

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await spider.crawl()

        # /api/users should be found (from JS extraction)
        assert "/api/users" in results["endpoints"]
        # /about should NOT be in endpoints (it's just a page, not an API)
        assert "/about" not in results["endpoints"]

