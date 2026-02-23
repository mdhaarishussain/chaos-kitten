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


# --- Request/Response Logging Tests ---

@pytest.mark.asyncio
async def test_logging_enabled_logs_request_and_response(base_url, caplog):
    """Test that enabling logging captures request and response details."""
    import logging
    caplog.set_level(logging.INFO)
    
    async with Executor(base_url=base_url, enable_logging=True) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/users").respond(200, json={"users": []})
            
            await executor.execute_attack("GET", "/users")
            
            # Check that request and response were logged
            log_messages = [record.message for record in caplog.records]
            assert any("REQUEST" in msg and "GET" in msg for msg in log_messages)
            assert any("RESPONSE" in msg and "Status: 200" in msg for msg in log_messages)


@pytest.mark.asyncio
async def test_logging_redacts_authorization_header(base_url, caplog):
    """Test that sensitive Authorization header is redacted in logs."""
    import logging
    caplog.set_level(logging.DEBUG)
    
    token = "secret_token_12345"
    async with Executor(
        base_url=base_url,
        auth_type="bearer",
        auth_token=token,
        enable_logging=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/protected").respond(200, json={"data": "sensitive"})
            
            await executor.execute_attack("GET", "/protected")
            
            # Check that token is NOT in logs
            log_text = " ".join([record.message for record in caplog.records])
            assert token not in log_text
            assert "[REDACTED]" in log_text


@pytest.mark.asyncio
async def test_logging_redacts_api_key_in_query_params(base_url, caplog):
    """Test that API keys in query parameters are redacted."""
    import logging
    caplog.set_level(logging.INFO)
    
    async with Executor(base_url=base_url, enable_logging=True) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/data").respond(200, json={"result": "ok"})
            
            await executor.execute_attack(
                "GET",
                "/data?api_key=secret123&other=value"
            )
            
            # Check that API key is redacted but other params remain
            log_text = " ".join([record.message for record in caplog.records])
            assert "secret123" not in log_text
            assert "api_key=[REDACTED]" in log_text
            assert "other=value" in log_text


@pytest.mark.asyncio
async def test_logging_truncates_large_request_body(base_url, caplog):
    """Test that large request bodies are truncated in logs."""
    import logging
    caplog.set_level(logging.DEBUG)
    
    # Create a large payload (over 500 chars)
    large_payload = {"data": "x" * 600}
    
    async with Executor(base_url=base_url, enable_logging=True) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201, json={"id": 1})
            
            await executor.execute_attack("POST", "/upload", payload=large_payload)
            
            # Check that body was truncated
            log_text = " ".join([record.message for record in caplog.records])
            assert "[truncated]" in log_text


@pytest.mark.asyncio
async def test_logging_full_body_for_errors(base_url, caplog):
    """Test that full response body is logged for errors."""
    import logging
    caplog.set_level(logging.WARNING)
    
    error_body = "Detailed error message with stack trace"
    
    async with Executor(base_url=base_url, enable_logging=True) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/fail").respond(500, text=error_body)
            
            await executor.execute_attack("GET", "/fail")
            
            # Check that error details are logged
            log_messages = [record.message for record in caplog.records]
            # HTTP error responses (4xx/5xx) should include full body at WARNING level
            assert any(error_body in msg for msg in log_messages)


@pytest.mark.asyncio
async def test_logging_to_file(base_url, tmp_path):
    """Test that logs are written to file when log_file is specified."""
    import logging
    
    log_file = tmp_path / "executor.log"
    
    async with Executor(
        base_url=base_url,
        enable_logging=True,
        log_file=str(log_file)
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/test").respond(200, json={"status": "ok"})
            
            await executor.execute_attack("GET", "/test")
    
    # Check that log file was created and contains logs
    assert log_file.exists()
    log_content = log_file.read_text()
    assert "REQUEST" in log_content
    assert "GET" in log_content
    assert "RESPONSE" in log_content
    assert "Status: 200" in log_content


@pytest.mark.asyncio
async def test_logging_disabled_by_default(base_url, caplog):
    """Test that logging is disabled by default."""
    import logging
    caplog.set_level(logging.DEBUG)
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/users").respond(200, json={"users": []})
            
            await executor.execute_attack("GET", "/users")
            
            # Check that no request/response logs were created
            log_messages = [record.message for record in caplog.records]
            assert not any("REQUEST" in msg and "GET" in msg for msg in log_messages)
            assert not any("RESPONSE" in msg and "Status: 200" in msg for msg in log_messages)


@pytest.mark.asyncio
async def test_logging_includes_response_time(base_url, caplog):
    """Test that response logging includes elapsed time in milliseconds."""
    import logging
    caplog.set_level(logging.INFO)
    
    async with Executor(base_url=base_url, enable_logging=True) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/users").respond(200, json={"users": []})
            
            await executor.execute_attack("GET", "/users")
            
            # Check that response time is logged
            log_messages = [record.message for record in caplog.records]
            assert any("Time:" in msg and "ms" in msg for msg in log_messages)

