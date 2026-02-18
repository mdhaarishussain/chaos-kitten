import pytest
import respx
import httpx
import time
import asyncio
import unittest.mock
from chaos_kitten.paws.executor import Executor

# --- Fixtures ---

@pytest.fixture
def base_url():
    return "http://api.example.com"

# --- Basic HTTP Requests ---

@pytest.mark.asyncio
async def test_basic_get_request(base_url):
    """Test a simple GET request logic."""
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/users").respond(200, json={"users": []}, text='{"users": []}')
            
            result = await executor.execute_attack("GET", "/users")
            
            assert result["status_code"] == 200
            assert result["error"] is None
            assert '"users": []' in result["body"]

@pytest.mark.asyncio
async def test_basic_post_request(base_url):
    """Test a simple POST request logic."""
    payload = {"name": "test"}
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/users").respond(201, json={"id": 1, "name": "test"}, text='{"id": 1, "name": "test"}')
            
            result = await executor.execute_attack("POST", "/users", payload=payload)
            
            assert result["status_code"] == 201
            assert result["error"] is None
            assert '"id": 1' in result["body"]

@pytest.mark.asyncio
async def test_basic_put_request(base_url):
    """Test a simple PUT request logic."""
    payload = {"name": "updated"}
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.put("/users/1").respond(200, json={"id": 1, "name": "updated"})
            
            result = await executor.execute_attack("PUT", "/users/1", payload=payload)
            
            assert result["status_code"] == 200
            assert result["error"] is None

@pytest.mark.asyncio
async def test_basic_delete_request(base_url):
    """Test a simple DELETE request logic."""
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.delete("/users/1").respond(204)
            
            result = await executor.execute_attack("DELETE", "/users/1")
            
            assert result["status_code"] == 204
            assert result["error"] is None

@pytest.mark.asyncio
async def test_basic_patch_request(base_url):
    """Test a simple PATCH request logic."""
    payload = {"name": "patched"}
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.patch("/users/1").respond(200, json={"id": 1, "name": "patched"})
            
            result = await executor.execute_attack("PATCH", "/users/1", payload=payload)
            
            assert result["status_code"] == 200
            assert result["error"] is None

# --- Authentication Types ---

@pytest.mark.asyncio
async def test_auth_bearer(base_url):
    """Test Bearer token authentication."""
    token = "secret_token"
    async with Executor(base_url=base_url, auth_type="bearer", auth_token=token) as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.get("/protected")
            route.respond(200)
            
            await executor.execute_attack("GET", "/protected")
            
            assert route.called
            headers = route.calls.last.request.headers
            assert headers["Authorization"] == f"Bearer {token}"

@pytest.mark.asyncio
async def test_auth_basic(base_url):
    """Test Basic authentication."""
    token = "dXNlcjpwYXNz" # user:pass base64
    async with Executor(base_url=base_url, auth_type="basic", auth_token=token) as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.get("/protected")
            route.respond(200)
            
            await executor.execute_attack("GET", "/protected")
            
            assert route.called
            headers = route.calls.last.request.headers
            assert headers["Authorization"] == f"Basic {token}"

@pytest.mark.asyncio
async def test_auth_none(base_url):
    """Test no authentication."""
    async with Executor(base_url=base_url, auth_type="none") as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.get("/public")
            route.respond(200)
            
            await executor.execute_attack("GET", "/public")
            
            assert route.called
            headers = route.calls.last.request.headers
            assert "Authorization" not in headers

# --- Rate Limiting ---

@pytest.mark.asyncio
async def test_rate_limiting(base_url):
    """Test rate limiting logic."""
    # Set a very strict rate limit (e.g., 2 requests per second)
    rate_limit = 2
    async with Executor(base_url=base_url, rate_limit=rate_limit) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/limit").respond(200)
            
            start_time = time.perf_counter()
            
            # Execute 3 requests. 
            # 1st request: t=0
            # 2nd request: t=0.5
            # 3rd request: t=1.0
            for _ in range(3):
                await executor.execute_attack("GET", "/limit")
            
            duration = time.perf_counter() - start_time
            # With 2 req/s, we expect at least 1.0s to have passed for 3 requests
            # (since the 3rd request waits for the slot)
            assert duration >= 1.0

# --- Error Handling & Timeouts ---

@pytest.mark.asyncio
async def test_timeout_handling(base_url):
    """Test request timeout handling."""
    async with Executor(base_url=base_url, timeout=1) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # Mock a timeout exception
            mock.get("/slow").mock(side_effect=httpx.TimeoutException("Timeout"))
            
            result = await executor.execute_attack("GET", "/slow")
            
            assert result["status_code"] == 0
            assert "Request timeout" in result["error"]

@pytest.mark.asyncio
async def test_connection_error(base_url):
    """Test connection error handling."""
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/down").mock(side_effect=httpx.ConnectError("Connection refused"))
            
            result = await executor.execute_attack("GET", "/down")
            
            assert result["status_code"] == 0
            assert "Connection error" in result["error"]

# --- Custom Headers & Body ---

@pytest.mark.asyncio
async def test_custom_headers(base_url):
    """Test adding custom headers."""
    custom_headers = {"X-Custom-Header": "test-value"}
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.get("/headers")
            route.respond(200)
            
            await executor.execute_attack("GET", "/headers", headers=custom_headers)
            
            assert route.called
            headers = route.calls.last.request.headers
            assert headers["X-Custom-Header"] == "test-value"

@pytest.mark.asyncio
async def test_request_body_encoding(base_url):
    """Test request body JSON encoding."""
    payload = {"key": "value", "nested": {"id": 1}}
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.post("/data")
            route.respond(200)
            
            await executor.execute_attack("POST", "/data", payload=payload)
            
            assert route.called
            request = route.calls.last.request
            assert request.headers["Content-Type"] == "application/json"
            import json
            body = json.loads(request.content)
            assert body == payload

# --- Advanced Scenarios ---

@pytest.mark.asyncio
async def test_large_response(base_url):
    """Test handling of large response bodies."""
    large_body = "x" * 100000 # 100KB
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/large").respond(200, text=large_body)
            
            result = await executor.execute_attack("GET", "/large")
            
            assert result["status_code"] == 200
            assert len(result["body"]) == 100000

@pytest.mark.asyncio
async def test_concurrent_requests(base_url):
    """Test concurrent requests execution."""
    async with Executor(base_url=base_url, rate_limit=100) as executor: # High limits for concurrency test
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/concurrent").respond(200)
            
            # Using asyncio.gather directly within the async test function
            tasks = [executor.execute_attack("GET", "/concurrent") for _ in range(5)]
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 5
            for res in results:
                assert res["status_code"] == 200

@pytest.mark.asyncio
async def test_supported_auth_validation():
    """Test that invalid auth types raise ValueError."""
    with pytest.raises(ValueError):
        Executor(base_url="http://test.com", auth_type="invalid")

# --- Edge Cases for Full Coverage ---

@pytest.mark.asyncio
async def test_client_not_initialized(base_url):
    """Test execution without context manager."""
    # Create executor but don't use 'async with'
    executor = Executor(base_url=base_url)
    # execute_attack handles uninitialized client
    result = await executor.execute_attack("GET", "/")
    assert result["status_code"] == 0
    assert "Client not initialized" in result["error"]

@pytest.mark.asyncio
async def test_unsupported_method(base_url):
    """Test unsupported HTTP method (e.g. invalid string not handled by httpx/executor logic if extended)."""
    async with Executor(base_url=base_url) as executor:
        result = await executor.execute_attack("HEAD", "/")
        assert result["status_code"] == 0
        assert "Unsupported HTTP method" in result["error"]

@pytest.mark.asyncio
async def test_unexpected_error(base_url):
    """Test unexpected error handling."""
    async with Executor(base_url=base_url) as executor:
        # Create a mock that raises an Exception when awaited
        mock_get = unittest.mock.AsyncMock(side_effect=Exception("Unexpected boom"))
        # Patch the method on the client instance
        with unittest.mock.patch.object(executor._client, 'get', mock_get):
            result = await executor.execute_attack("GET", "/boom")
            
            assert result["status_code"] == 0
            assert "Unexpected error" in result["error"]
