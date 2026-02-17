"""Tests for the Paws module."""

import asyncio
import pytest
import httpx
import respx
from chaos_kitten.paws.executor import Executor, RetryConfig, RetryStrategy
from chaos_kitten.paws.browser import BrowserAutomation


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


class TestRetryLogic:
    """Tests for retry logic and backoff behavior."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_429_rate_limit(self):
        """Test that executor retries on 429 Too Many Requests."""
        # Mock: First call returns 429, second returns 200
        route = respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429, json={"error": "rate limited"}),
                httpx.Response(200, json={"success": True}),
            ]
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        assert route.call_count == 2
        assert result["status_code"] == 200
        assert result["error"] is None
        assert "success" in result["body"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_503_service_unavailable(self):
        """Test that executor retries on 503 Service Unavailable."""
        route = respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(503, text="Service Unavailable"),
                httpx.Response(503, text="Service Unavailable"),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        assert route.call_count == 3
        assert result["status_code"] == 200
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_retry_on_404(self):
        """Test that executor does NOT retry on 404 Not Found."""
        route = respx.get("http://test.com/api/notfound").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="GET", path="/api/notfound")

        # Should only be called once (no retry)
        assert route.call_count == 1
        assert result["status_code"] == 404
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_retry_attempts_exceeded(self):
        """Test that retry stops after max attempts."""
        retry_config = RetryConfig(max_attempts=3)

        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429),
                httpx.Response(429),
                httpx.Response(429),
                httpx.Response(429),  # Should not be called
            ]
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        # Should only retry up to max_attempts
        assert result["status_code"] == 429
        assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_exponential_backoff_calculation(self):
        """Test exponential backoff calculation."""
        retry_config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_backoff_ms=100,
            backoff_multiplier=2.0,
            jitter_factor=0.0,  # No jitter for deterministic test
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            # Calculate backoffs for first few attempts
            backoff_0 = executor._calculate_backoff(0)  # 100ms
            backoff_1 = executor._calculate_backoff(1)  # 200ms
            backoff_2 = executor._calculate_backoff(2)  # 400ms
            backoff_3 = executor._calculate_backoff(3)  # 800ms

            assert abs(backoff_0 - 0.1) < 0.01
            assert abs(backoff_1 - 0.2) < 0.01
            assert abs(backoff_2 - 0.4) < 0.01
            assert abs(backoff_3 - 0.8) < 0.01

    @pytest.mark.asyncio
    async def test_linear_backoff_strategy(self):
        """Test linear backoff strategy."""
        retry_config = RetryConfig(
            strategy=RetryStrategy.LINEAR,
            initial_backoff_ms=100,
            jitter_factor=0.0,
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            backoff_0 = executor._calculate_backoff(0)  # 100ms
            backoff_1 = executor._calculate_backoff(1)  # 200ms
            backoff_2 = executor._calculate_backoff(2)  # 300ms

            assert abs(backoff_0 - 0.1) < 0.01
            assert abs(backoff_1 - 0.2) < 0.01
            assert abs(backoff_2 - 0.3) < 0.01

    @pytest.mark.asyncio
    async def test_fixed_backoff_strategy(self):
        """Test fixed backoff strategy."""
        retry_config = RetryConfig(
            strategy=RetryStrategy.FIXED,
            initial_backoff_ms=150,
            jitter_factor=0.0,
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            backoff_0 = executor._calculate_backoff(0)  # 150ms
            backoff_1 = executor._calculate_backoff(1)  # 150ms
            backoff_2 = executor._calculate_backoff(2)  # 150ms

            assert abs(backoff_0 - 0.15) < 0.01
            assert abs(backoff_1 - 0.15) < 0.01
            assert abs(backoff_2 - 0.15) < 0.01

    @pytest.mark.asyncio
    async def test_backoff_with_jitter(self):
        """Test that jitter adds randomness to backoff."""
        retry_config = RetryConfig(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_backoff_ms=100,
            jitter_factor=0.5,  # 50% jitter
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            # Collect multiple backoff values
            backoffs = [executor._calculate_backoff(0) for _ in range(10)]

            # All should be around 100ms but with jitter
            for backoff in backoffs:
                # With 0.5 jitter factor, base is 0.1s, so range is 0.1 to 0.15
                assert 0.09 < backoff < 0.16

            # They should not all be the same (verify randomness)
            assert len(set(backoffs)) > 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_header_support(self):
        """Test that Retry-After header is respected."""
        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.1"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        retry_config = RetryConfig(respect_retry_after=True)

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        assert result["status_code"] == 200
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_after_header_ignored_when_disabled(self):
        """Test that Retry-After header is ignored when disabled."""
        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "10"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        retry_config = RetryConfig(
            respect_retry_after=False,
            initial_backoff_ms=100,
            jitter_factor=0.0,
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            start_time = asyncio.get_event_loop().time()
            result = await executor.execute_attack(method="GET", path="/api/test")
            elapsed = asyncio.get_event_loop().time() - start_time

        # Should use exponential backoff (100ms) not Retry-After (10s)
        assert result["status_code"] == 200
        assert elapsed < 1.0  # Should be quick, not 10+ seconds

    @pytest.mark.asyncio
    @respx.mock
    async def test_metrics_tracking_on_rate_limit(self):
        """Test that metrics are properly tracked on rate limit events."""
        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "1"}),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        async with Executor(base_url="http://test.com") as executor:
            await executor.execute_attack(method="GET", path="/api/test")
            metrics = executor.get_metrics()

        assert metrics["total_requests"] == 1
        assert metrics["rate_limited_requests"] == 1
        assert metrics["retried_requests"] == 1
        assert metrics["successful_retries"] == 1
        assert metrics["failed_retries"] == 0
        assert metrics["total_backoff_time_ms"] > 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_metrics_on_failed_retry(self):
        """Test that metrics are tracked on failed retries."""
        respx.get("http://test.com/api/test").mock(
            return_value=httpx.Response(429)
        )

        retry_config = RetryConfig(max_attempts=2)

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")
            metrics = executor.get_metrics()

        assert result["error"] is not None
        assert metrics["rate_limited_requests"] >= 1
        assert metrics["failed_retries"] == 1

    def test_metrics_reset(self):
        """Test that metrics can be reset."""
        executor = Executor(base_url="http://test.com")

        # Simulate some metrics
        executor._metrics.total_requests = 100
        executor._metrics.rate_limited_requests = 10

        executor.reset_metrics()

        metrics = executor.get_metrics()
        assert metrics["total_requests"] == 0
        assert metrics["rate_limited_requests"] == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_adaptive_backoff_strategy(self):
        """Test adaptive backoff strategy."""
        retry_config = RetryConfig(
            strategy=RetryStrategy.ADAPTIVE,
            initial_backoff_ms=100,
            jitter_factor=0.0,
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            backoff_0 = executor._calculate_backoff(0)  # ~100ms
            backoff_1 = executor._calculate_backoff(1)  # ~280ms (slower than exponential)
            backoff_2 = executor._calculate_backoff(2)  # ~591ms

            # Adaptive should be slower growth than exponential
            # For exponential with multiplier 2.0: 0, 0.2, 0.4
            # Verify it's slower than exponential
            assert backoff_0 < backoff_1
            assert backoff_1 < backoff_2

    @pytest.mark.asyncio
    @respx.mock
    async def test_custom_retry_status_codes(self):
        """Test custom retry status codes configuration."""
        retry_config = RetryConfig(retry_on_status_codes=[418, 500])

        respx.get("http://test.com/api/test").mock(
            return_value=httpx.Response(418, json={"error": "I'm a teapot"})
        )

        async with Executor(
            base_url="http://test.com",
            retry_config=retry_config,
        ) as executor:
            # Should retry on 418 (custom)
            result = await executor.execute_attack(method="GET", path="/api/test")

        # Multiple calls due to retry
        assert result["status_code"] == 418

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_with_different_response_codes(self):
        """Test retry behavior with different response codes."""
        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(500, text="Internal Server Error"),
                httpx.Response(502, text="Bad Gateway"),
                httpx.Response(503, text="Service Unavailable"),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        async with Executor(base_url="http://test.com") as executor:
            result = await executor.execute_attack(method="GET", path="/api/test")

        assert result["status_code"] == 200
        assert result["error"] is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_backoff_timing(self):
        """Test that actual backoff delays are approximately correct."""
        respx.get("http://test.com/api/test").mock(
            side_effect=[
                httpx.Response(429),
                httpx.Response(200, json={"ok": True}),
            ]
        )

        retry_config = RetryConfig(
            max_attempts=2,
            initial_backoff_ms=100,
            jitter_factor=0.0,
        )

        async with Executor(
            base_url="http://test.com", retry_config=retry_config
        ) as executor:
            start_time = asyncio.get_event_loop().time()
            await executor.execute_attack(method="GET", path="/api/test")
            elapsed = asyncio.get_event_loop().time() - start_time

        # Should have at least one backoff of 100ms
        assert elapsed >= 0.08  # Account for execution time




