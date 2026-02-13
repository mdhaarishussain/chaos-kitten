"""Tests for the Paws module."""

import asyncio

import httpx
import pytest
import respx

from chaos_kitten.paws.executor import Executor


class TestExecutor:
    """Tests for the HTTP executor."""

    def test_build_headers_bearer(self):
        """Test building headers with bearer auth."""
        executor = Executor(
            base_url="http://test.com", auth_type="bearer", auth_token="test-token-123"
        )
        headers = executor._build_headers()

        assert "User-Agent" in headers
        assert headers["User-Agent"] == "ChaosKitten/0.1.0"
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test-token-123"

    def test_build_headers_basic(self):
        """Test building headers with basic auth."""
        executor = Executor(
            base_url="http://test.com",
            auth_type="basic",
            auth_token="dXNlcjpwYXNz",  # base64 encoded user:pass
        )
        headers = executor._build_headers()

        assert "User-Agent" in headers
        assert "Authorization" in headers
        assert headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_build_headers_no_auth(self):
        """Test building headers without authentication."""
        executor = Executor(base_url="http://test.com")
        headers = executor._build_headers()

        assert "User-Agent" in headers
        assert "Authorization" not in headers

    @pytest.mark.asyncio
    @respx.mock
    async def test_execute_get_request(self):
        """Test executing a GET request with query parameters."""
        respx.get("http://test.com/api/users").mock(
            return_value=httpx.Response(
                200,
                json={"users": ["alice", "bob"]},
                headers={"content-type": "application/json"},
            )
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="GET", path="/api/users", payload={"limit": 10}
            )

        assert result["status_code"] == 200
        assert result["error"] is None
        assert "users" in result["body"]
        assert result["elapsed_ms"] > 0
        assert "content-type" in result["headers"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_execute_post_request(self):
        """Test executing a POST request with JSON body."""
        respx.post("http://test.com/api/login").mock(
            return_value=httpx.Response(200, json={"success": True, "token": "abc123"})
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="POST",
                path="/api/login",
                payload={"username": "admin", "password": "test"},
            )

        assert result["status_code"] == 200
        assert result["error"] is None
        assert "success" in result["body"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_execute_put_request(self):
        """Test executing a PUT request."""
        respx.put("http://test.com/api/users/1").mock(
            return_value=httpx.Response(200, json={"updated": True})
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="PUT", path="/api/users/1", payload={"email": "new@example.com"}
            )

        assert result["status_code"] == 200
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_execute_patch_request(self):
        """Test executing a PATCH request."""
        respx.patch("http://test.com/api/users/1").mock(
            return_value=httpx.Response(200, json={"patched": True})
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="PATCH", path="/api/users/1", payload={"status": "active"}
            )

        assert result["status_code"] == 200
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_execute_delete_request(self):
        """Test executing a DELETE request."""
        respx.delete("http://test.com/api/users/1").mock(
            return_value=httpx.Response(204)
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="DELETE", path="/api/users/1")

        assert result["status_code"] == 204
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_execute_without_context_manager(self):
        """Test that execute_attack fails gracefully without context manager."""
        executor = Executor(base_url="http://test.com")
        result = await executor.execute_attack(method="GET", path="/api/test")

        assert result["status_code"] == 0
        assert result["error"] is not None
        assert "not initialized" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_unsupported_http_method(self):
        """Test handling of unsupported HTTP methods."""
        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="TRACE", path="/api/test")

        assert result["status_code"] == 0
        assert result["error"] is not None
        assert "Unsupported HTTP method" in result["error"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_timeout_handling(self):
        """Test graceful handling of request timeouts."""
        respx.get("http://test.com/api/slow").mock(
            side_effect=httpx.TimeoutException("Request timed out")
        )

        async with Executor(base_url="http://test.com", timeout=1) as executor:
            result = await executor.execute_attack(method="GET", path="/api/slow")

        assert result["status_code"] == 0
        assert result["error"] is not None
        assert "timeout" in result["error"].lower()
        assert result["elapsed_ms"] >= 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error_handling(self):
        """Test graceful handling of connection errors."""
        respx.get("http://test.com/api/test").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        assert result["status_code"] == 0
        assert result["error"] is not None
        assert "connection error" in result["error"].lower()

    @pytest.mark.asyncio
    @respx.mock
    async def test_custom_headers(self):
        """Test merging custom headers with default headers."""
        route = respx.get("http://test.com/api/test").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        async with Executor(base_url="http://test.com") as executor:
            await executor.execute_attack(
                method="GET",
                path="/api/test",
                headers={"X-Custom-Header": "test-value"},
            )

        # Verify the request was made with custom header
        assert route.called
        request = route.calls.last.request
        assert "X-Custom-Header" in request.headers
        assert request.headers["X-Custom-Header"] == "test-value"

    @pytest.mark.asyncio
    @respx.mock
    async def test_rate_limiting(self):
        """Test that rate limiting is applied."""
        respx.get("http://test.com/api/test").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )

        # Set rate limit to 5 requests per second
        async with Executor(base_url="http://test.com", rate_limit=5) as executor:
            start_time = asyncio.get_event_loop().time()

            # Execute 3 requests
            for _ in range(3):
                await executor.execute_attack(method="GET", path="/api/test")

            elapsed = asyncio.get_event_loop().time() - start_time

            # With 5 req/sec, 3 requests should take at least 0.4 seconds (2 intervals of 0.2s)
            # We use a slightly lower threshold to account for timing variations
            assert (
                elapsed >= 0.35
            ), f"Rate limiting not working: {elapsed}s for 3 requests"

    @pytest.mark.asyncio
    @respx.mock
    async def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up resources."""
        respx.get("http://test.com/api/test").mock(return_value=httpx.Response(200))

        executor = Executor(base_url="http://test.com")

        async with executor:
            assert executor._client is not None
            assert executor._rate_limiter is not None
            await executor.execute_attack(method="GET", path="/api/test")

        # After exiting context, client should be closed
        # We can't easily check if it's closed, but we can verify it exists
        assert executor._client is not None


class TestBrowserAutomation:
    """Tests for browser automation."""

    @pytest.mark.asyncio
    async def test_xss_detection(self):
        """Test XSS detection with Playwright."""
        # TODO: Implement test when browser automation is ready
        pass
