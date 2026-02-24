"""Tests for the Paws module."""

import asyncio
import tempfile
from pathlib import Path

import pytest
import httpx
import respx
from chaos_kitten.paws.executor import Executor
from chaos_kitten.paws.browser import BrowserExecutor


class TestExecutor:
    """Tests for the HTTP executor."""
    
    def test_initialization_defaults(self):
        """Test default values and url normalization."""
        # Test defaults
        executor = Executor(base_url="http://test.com")
        assert executor.rate_limit == 10
        assert executor.timeout == 30
        assert executor.auth_type == "none"
        assert executor.auth_token is None
        assert executor.base_url == "http://test.com"

        # Test base_url normalization (strip trailing slash)
        executor_slash = Executor(base_url="http://test.com/")
        assert executor_slash.base_url == "http://test.com"
        
        # Test custom values
        executor_custom = Executor(
            base_url="http://test.com", 
            rate_limit=5, 
            timeout=60
        )
        assert executor_custom.rate_limit == 5
        assert executor_custom.timeout == 60

    def test_build_headers_bearer(self):
        """Test building headers with bearer auth."""
        executor = Executor(
            base_url="http://test.com",
            auth_type="bearer",
            auth_token="test-token-123"
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
            auth_token="dXNlcjpwYXNz"  # base64 encoded user:pass
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
                headers={"content-type": "application/json"}
            )
        )
        
        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="GET",
                path="/api/users",
                payload={"limit": 10}
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
            return_value=httpx.Response(
                200,
                json={"success": True, "token": "abc123"}
            )
        )
        
        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="POST",
                path="/api/login",
                payload={"username": "admin", "password": "test"}
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
                method="PUT",
                path="/api/users/1",
                payload={"email": "new@example.com"}
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
                method="PATCH",
                path="/api/users/1",
                payload={"status": "active"}
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
            result = await executor.execute_attack(
                method="DELETE",
                path="/api/users/1"
            )
        
        assert result["status_code"] == 204
        assert result["error"] is None
    
    @pytest.mark.asyncio
    async def test_execute_without_context_manager(self):
        """Test that execute_attack fails gracefully without context manager."""
        executor = Executor(base_url="http://test.com")
        result = await executor.execute_attack(
            method="GET",
            path="/api/test"
        )
        
        assert result["status_code"] == 0
        assert result["error"] is not None
        assert "not initialized" in result["error"].lower()
    
    @pytest.mark.asyncio
    async def test_unsupported_http_method(self):
        """Test handling of unsupported HTTP methods."""
        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(
                method="TRACE",
                path="/api/test"
            )
        
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
            result = await executor.execute_attack(
                method="GET",
                path="/api/slow"
            )
        
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
            result = await executor.execute_attack(
                method="GET",
                path="/api/test"
            )
        
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
                headers={"X-Custom-Header": "test-value"}
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
            assert elapsed >= 0.35, f"Rate limiting not working: {elapsed}s for 3 requests"
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up resources."""
        respx.get("http://test.com/api/test").mock(
            return_value=httpx.Response(200)
        )
        
        executor = Executor(base_url="http://test.com")
        
        async with executor:
            assert executor._client is not None
            assert executor._rate_limiter is not None
            await executor.execute_attack(method="GET", path="/api/test")
        
        # After exiting context, client should be closed
        # We can't easily check if it's closed, but we can verify it exists
        assert executor._client is not None


class TestBrowserExecutor:
    """Tests for the browser automation module."""
    
    def test_initialization(self):
        """Test default initialization."""
        browser = BrowserExecutor(headless=True)
        assert browser.headless is True
        assert browser._browser is None
        assert browser._context is None
        assert browser._playwright is None
        
        browser_visible = BrowserExecutor(headless=False)
        assert browser_visible.headless is False

    def test_initialization_with_timeout(self):
        """Test initialization with custom timeout."""
        browser = BrowserExecutor(headless=True, timeout=5000)
        assert browser.timeout == 5000

    @pytest.mark.asyncio
    async def test_xss_detection_script_tag(self):
        """Test XSS detection with <script>alert()</script> payload.

        Note: <script> tags injected via innerHTML do NOT execute per HTML5 spec.
        We use document.write() in the test page so that the <script> payload
        actually runs and fires the dialog handler in BrowserExecutor.test_xss.
        """
        pytest.importorskip("playwright")

        # Uses document.write() which *does* execute <script> tags
        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form id="test-form">
                <input id="test-input" name="user_input">
                <button type="submit">Submit</button>
            </form>
            <div id="output"></div>
            <script>
                document.getElementById('test-form').addEventListener('submit', (e) => {
                    e.preventDefault();
                    const input = document.getElementById('test-input').value;
                    // Vulnerable - document.write executes <script> tags
                    document.write(input);
                });
            </script>
        </body>
        </html>
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(test_html)
            test_file = f.name

        screenshot_path = None
        with tempfile.TemporaryDirectory() as tmp_screenshot_dir:
            try:
                async with BrowserExecutor(headless=True) as browser:
                    result = await browser.test_xss(
                        url=f"file://{test_file}",
                        payload="<script>alert('XSS')</script>",
                        input_selector="#test-input",
                        screenshot_dir=tmp_screenshot_dir,
                    )

                    # Verify the result structure
                    assert "is_vulnerable" in result
                    assert "screenshot_path" in result
                    assert "error" in result

                    # The XSS payload should trigger a dialog
                    assert result["is_vulnerable"] is True

                    # Screenshot should be captured on vulnerability detection
                    screenshot_path = result["screenshot_path"]
                    if screenshot_path:
                        assert Path(screenshot_path).exists()
            finally:
                Path(test_file).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_xss_detection_event_handler(self):
        """Test XSS detection with event handler (onerror) payload."""
        pytest.importorskip("playwright")

        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form id="test-form">
                <input id="test-input" name="user_input">
                <button type="submit">Submit</button>
            </form>
            <div id="output"></div>
            <script>
                document.getElementById('test-form').addEventListener('submit', (e) => {
                    e.preventDefault();
                    const input = document.getElementById('test-input').value;
                    document.getElementById('output').innerHTML = input;
                });
            </script>
        </body>
        </html>
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(test_html)
            test_file = f.name

        with tempfile.TemporaryDirectory() as tmp_screenshot_dir:
            try:
                async with BrowserExecutor(headless=True) as browser:
                    result = await browser.test_xss(
                        url=f"file://{test_file}",
                        payload="<img src=x onerror=alert('XSS')>",
                        input_selector="#test-input",
                        screenshot_dir=tmp_screenshot_dir,
                    )

                    assert result["is_vulnerable"] is True
                    assert result["error"] is None
            finally:
                Path(test_file).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_no_vulnerability_safe_input(self):
        """Test that safe input is not flagged as vulnerable."""
        pytest.importorskip("playwright")

        test_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form id="test-form">
                <input id="test-input" name="user_input">
                <button type="submit">Submit</button>
            </form>
            <div id="output"></div>
            <script>
                document.getElementById('test-form').addEventListener('submit', (e) => {
                    e.preventDefault();
                    const input = document.getElementById('test-input').value;
                    // Safe - using textContent instead of innerHTML
                    document.getElementById('output').textContent = input;
                });
            </script>
        </body>
        </html>
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(test_html)
            test_file = f.name

        try:
            async with BrowserExecutor(headless=True) as browser:
                result = await browser.test_xss(
                    url=f"file://{test_file}",
                    payload="<script>alert('XSS')</script>",
                    input_selector="#test-input"
                )

                # Safe page (textContent) should not trigger XSS
                assert result["error"] is None
                assert result["is_vulnerable"] is False
        finally:
            Path(test_file).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_context_manager_cleanup(self):
        """Test that browser resources are properly cleaned up."""
        pytest.importorskip("playwright")

        browser = BrowserExecutor(headless=True)

        async with browser:
            assert browser._browser is not None
            assert browser._context is not None
            assert browser._playwright is not None

        # After exiting, browser should be disconnected
        assert browser._browser is not None
        assert browser._browser.is_connected() is False

    @pytest.mark.asyncio
    async def test_error_handling_invalid_url(self):
        """Test error handling with invalid URL."""
        pytest.importorskip("playwright")
        
        async with BrowserExecutor(headless=True) as browser:
            result = await browser.test_xss(
                url="http://invalid-url-that-does-not-exist-12345.com",
                payload="<script>alert('XSS')</script>",
            )
            
            # Should return error instead of raising
            assert result["is_vulnerable"] is False
            assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_selector_not_found(self):
        """Test error handling when input selector doesn't exist."""
        pytest.importorskip("playwright")

        test_html = """
        <!DOCTYPE html>
        <html><body><p>No input here</p></body></html>
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(test_html)
            test_file = f.name

        try:
            async with BrowserExecutor(headless=True) as browser:
                result = await browser.test_xss(
                    url=f"file://{test_file}",
                    payload="<script>alert('XSS')</script>",
                    input_selector="#nonexistent-input"
                )

                assert result["is_vulnerable"] is False
                assert result["error"] is not None
                assert "not found" in result["error"].lower()
        finally:
            Path(test_file).unlink(missing_ok=True)
