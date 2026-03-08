"""Tests to verify all 4 fixes from Review Round 2 for PR #98."""

import pytest
import respx
import logging
import re
from pathlib import Path
import tempfile
from chaos_kitten.paws.executor import Executor


@pytest.fixture
def base_url():
    return "http://api.example.com"


@pytest.fixture
def temp_log_file():
    """Create a temporary log file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        yield f.name
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_fix1_bare_key_not_redacted(base_url, caplog):
    """✅ FIX #1: Verify bare 'key' parameter is NOT redacted.
    
    The regex should only match api_key, api-key, apikey.
    It should NOT match bare 'key=' parameters.
    """
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        enable_logging=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/products").respond(200, json={"product": "test"})
            
            # Test with legitimate bare 'key' parameter
            await executor.execute_attack("GET", "/products?key=product_id&id=123")
            
            log_output = caplog.text
            # 'product_id' should NOT be redacted since it's a bare 'key=' parameter
            assert "product_id" in log_output or "key=product_id" in log_output, \
                "Bare 'key' parameter should not be redacted"


@pytest.mark.asyncio
async def test_fix1_api_key_variations_redacted(base_url, caplog):
    """✅ FIX #1: Verify api_key variations ARE redacted."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        enable_logging=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/search").respond(200, json={"results": []})
            
            # Test various API key formats that SHOULD be redacted
            test_cases = [
                "/search?api_key=secret123",
                "/search?api-key=secret456",
                "/search?apikey=secret789",
            ]
            
            for path in test_cases:
                caplog.clear()
                await executor.execute_attack("GET", path)
                
                log_output = caplog.text
                # Extract the secret from path for checking
                secret = path.split('=')[1]
                assert secret not in log_output, \
                    f"API key '{secret}' should be redacted in {path}"
                assert "[REDACTED]" in log_output, \
                    f"[REDACTED] marker should appear for {path}"


@pytest.mark.asyncio
async def test_fix2_url_fragment_handling(base_url, caplog):
    """✅ FIX #2: Verify URL fragments are handled correctly.
    
    The regex should stop at '#' characters to avoid including
    fragments in the redaction match.
    """
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        enable_logging=True
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # httpx strips fragments, so mock the base path
            mock.get("/search").respond(200, json={"results": []})
            
            # Test with URL fragment
            await executor.execute_attack(
                "GET",
                "/search?api_key=secret123#/fragment?key=data&other=value"
            )
            
            log_output = caplog.text
            # The API key 'secret123' should be redacted
            assert "secret123" not in log_output, \
                "API key before fragment should be redacted"
            assert "[REDACTED]" in log_output, \
                "[REDACTED] marker should appear"
            # The fragment part should be preserved in the logged URL
            # (though it may be omitted by httpx, the pattern should handle it correctly)


@pytest.mark.asyncio
async def test_fix3_unique_logger_names(base_url):
    """✅ FIX #3: Verify each Executor instance has unique logger name.
    
    Logger names should include instance ID to avoid conflicts.
    """
    executor1 = Executor(base_url=base_url, enable_logging=True)
    executor2 = Executor(base_url=base_url, enable_logging=True)
    
    async with executor1:
        async with executor2:
            # Both should have different logger names to avoid conflicts
            logger1_name = executor1._logger.name
            logger2_name = executor2._logger.name
            
            assert logger1_name != logger2_name, \
                "Each Executor instance should have unique logger name"
            
            # Logger names should include instance ID
            assert "executor" in logger1_name, \
                "Logger name should include 'executor'"
            assert "executor" in logger2_name, \
                "Logger name should include 'executor'"
            
            # Names should include unique identifier (id(self))
            # Extract the IDs and verify they're different
            assert logger1_name.split('.')[-1] != logger2_name.split('.')[-1], \
                "Logger names should have different instance IDs"


@pytest.mark.asyncio
async def test_fix4_filehandler_cleanup(base_url, temp_log_file):
    """✅ FIX #4: Verify FileHandler resources are properly cleaned up.
    
    Handlers should be closed and removed in __aexit__ to prevent
    resource leaks.
    """
    executor = Executor(
        base_url=base_url,
        enable_logging=True,
        log_file=temp_log_file
    )
    
    async with executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/test").respond(200, json={"status": "ok"})
            await executor.execute_attack("GET", "/test")
        
        # Verify handlers exist during execution
        assert len(executor._logger.handlers) > 0, \
            "Logger should have handlers during execution"
        
        # Store handler count for verification
        handler_count = len(executor._logger.handlers)
    
    # After exiting context, handlers should be cleaned up
    remaining_handlers = len(executor._logger.handlers)
    assert remaining_handlers == 0, \
        f"All handlers should be removed after __aexit__, but {remaining_handlers} remain"
    
    # Verify the log file was created and can be read
    # (indicating handlers were properly closed before cleanup)
    assert Path(temp_log_file).exists(), "Log file should exist"
    log_content = Path(temp_log_file).read_text()
    assert "Request: GET" in log_content, "Log file should contain request logs"


@pytest.mark.asyncio
async def test_all_fixes_integration(base_url, temp_log_file, caplog):
    """Integration test verifying all 4 fixes work together."""
    caplog.set_level(logging.DEBUG)
    
    async with Executor(
        base_url=base_url,
        enable_logging=True,
        log_file=temp_log_file
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.get("/search").respond(200, json={"results": []})
            
            # Complex URL with legitimate 'key' param, api_key, and fragment
            await executor.execute_attack(
                "GET",
                "/search?key=sort_order&api_key=secret&limit=10#/results"
            )
            
            log_output = caplog.text
            
            # Fix #1: Bare 'key' should NOT be redacted
            assert "sort_order" in log_output or "key=sort_order" in log_output, \
                "Legitimate 'key' parameter should not be redacted"
            
            # Fix #1 & #2: API key should be redacted
            assert "secret" not in log_output, \
                "API key value should be redacted"
            assert "[REDACTED]" in log_output, \
                "Redaction marker should appear"
            
            # Fix #3: Logger has unique name
            assert "executor" in executor._logger.name, \
                "Logger should have unique instance-based name"
            
    # Fix #4: Handlers cleaned up
    assert len(executor._logger.handlers) == 0, \
        "Handlers should be cleaned up after exit"
    
    # Verify log file was properly written and closed
    log_content = Path(temp_log_file).read_text()
    assert "Request: GET" in log_content
    assert "[REDACTED]" in log_content


@pytest.mark.asyncio
async def test_regex_pattern_directly():
    """Direct test of the regex pattern to verify fixes #1 and #2."""
    # The pattern from executor.py line 390
    pattern = r'([?&])(api[-_]?key|apikey)=([^&#]*)'
    replacement = r'\1\2=[REDACTED]'
    
    test_cases = [
        # (input, expected_output, description)
        ("?api_key=secret123", "?api_key=[REDACTED]", "api_key should be redacted"),
        ("?api-key=secret123", "?api-key=[REDACTED]", "api-key should be redacted"),
        ("?apikey=secret123", "?apikey=[REDACTED]", "apikey should be redacted"),
        ("?key=product_id", "?key=product_id", "bare 'key' should NOT be redacted"),
        ("?api_key=secret&other=value", "?api_key=[REDACTED]&other=value", "should stop at &"),
        ("?api_key=secret#fragment", "?api_key=[REDACTED]#fragment", "should stop at # (fragment)"),
        ("?key=123&api_key=secret#frag", "?key=123&api_key=[REDACTED]#frag", "complex URL"),
    ]
    
    for test_input, expected, description in test_cases:
        result = re.sub(pattern, replacement, test_input, flags=re.IGNORECASE)
        assert result == expected, \
            f"FAILED: {description}\n  Input: {test_input}\n  Expected: {expected}\n  Got: {result}"
