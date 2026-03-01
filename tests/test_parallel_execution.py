"""Tests for parallel execution of attack profiles."""

import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch
from chaos_kitten.brain.orchestrator import execute_and_analyze, AgentState

@pytest.mark.asyncio
async def test_parallel_category_execution_speed():
    """Test that different categories run in parallel."""
    
    # Mock executor with delay
    executor = AsyncMock()
    
    async def fast_mock_attack(method, path, payload):
        await asyncio.sleep(0.1) # Simulate network delay
        return {
            "status_code": 200, 
            "body": "OK", 
            "elapsed_ms": 100
        }
    
    executor.execute_attack.side_effect = fast_mock_attack
    
    # Setup state with 3 attacks in 3 different categories
    state = {
        "current_endpoint": 0,
        "endpoints": [{"method": "GET", "path": "/test"}],
        "planned_attacks": [
            {"type": "sql_injection", "payload": "1", "name": "SQLi"},
            {"type": "xss", "payload": "2", "name": "XSS"},
            {"type": "auth_bypass", "payload": "3", "name": "Auth"}
        ],
        "findings": []
    }
    
    config = {
        "agent": {
            "max_concurrent_agents": 3
        },
        "adaptive": {"enabled": False}
    }
    
    start_time = time.time()
    
    # Execution
    result = await execute_and_analyze(state, executor, config)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Should be close to 0.1s, definitely less than 0.3s (sequential)
    # Give some buffer for overhead
    assert duration < 0.25, f"Parallel execution took too long: {duration}s (expected ~0.1s)"
    assert len(result["findings"]) == 0 # No vulnerabilities in mock
    
    # Verify all attacks were executed
    assert executor.execute_attack.call_count == 3

@pytest.mark.asyncio
async def test_sequential_category_execution_speed():
    """Test that max_concurrent_agents=1 enforces sequential execution."""
    
    executor = AsyncMock()
    
    async def mock_attack(method, path, payload):
        await asyncio.sleep(0.1)
        return {"status_code": 200, "body": "OK"}
    
    executor.execute_attack.side_effect = mock_attack
    
    state = {
        "current_endpoint": 0,
        "endpoints": [{"method": "GET", "path": "/test"}],
        "planned_attacks": [
            {"type": "cat1", "payload": "1", "name": "A1"},
            {"type": "cat2", "payload": "2", "name": "A2"}
        ],
        "findings": []
    }
    
    config = {
        "agent": {
            "max_concurrent_agents": 1
        },
        "adaptive": {"enabled": False}
    }
    
    start_time = time.time()
    await execute_and_analyze(state, executor, config)
    end_time = time.time()
    duration = end_time - start_time
    
    # 2 attacks * 0.1s = 0.2s minimum
    assert duration >= 0.2, f"Sequential execution was too fast: {duration}s"

@pytest.mark.asyncio
async def test_findings_accumulation():
    """Test that findings from different concurrent tasks are collected correctly."""
    
    executor = AsyncMock()
    executor.execute_attack.return_value = {
        "status_code": 500, 
        "body": "Error", 
        "elapsed_ms": 10
    }
    
    state = {
        "current_endpoint": 0,
        "endpoints": [{"method": "GET", "path": "/test"}],
        "planned_attacks": [
            {"type": "cat1", "payload": "p1", "name": "A1"},
            {"type": "cat2", "payload": "p2", "name": "A2"} # runs parallel
        ],
        "findings": [{"id": "existing"}]
    }
    
    config = {"agent": {"max_concurrent_agents": 2}}
    
    # Mock Analyzer to return findings
    with patch("chaos_kitten.brain.orchestrator.ResponseAnalyzer") as MockAnalyzer:
        analyzer_instance = MockAnalyzer.return_value
        finding_mock = MagicMock()
        finding_mock.vulnerability_type = "Bug"
        finding_mock.severity = "High"
        finding_mock.evidence = "Proof"
        finding_mock.endpoint = "/test"
        # Return a finding for each attack
        analyzer_instance.analyze.return_value = finding_mock
        
        result = await execute_and_analyze(state, executor, config)
        
        # total findings = 1 existing + 2 new
        assert len(result["findings"]) == 3
        # Check order is preserved is harder with concurrency but we check presence
        types = [f.get("type") for f in result["findings"] if "type" in f]
        assert types.count("Bug") == 2
