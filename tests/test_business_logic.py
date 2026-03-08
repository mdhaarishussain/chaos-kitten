import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from chaos_kitten.brain.orchestrator import execute_and_analyze

@pytest.mark.asyncio
async def test_concurrent_attack_execution():
    # Setup state
    state = {
        "planned_attacks": [
            {
                "name": "Race Condition Test",
                "type": "race_condition",
                "concurrency": {"count": 3},
                "path": "/api/race",
                "method": "POST",
                "headers": {"X-Test": "1"},
                "payload": {"data": "test"}
            }
        ]
    }
    
    # Mock executor
    mock_executor = AsyncMock()
    # Simulate 3 invocations. 
    # Since asyncio.gather runs them concurrently, side_effect might be consumed in any order, 
    # but typically it just pops from the list.
    mock_executor.execute.side_effect = [
        {"status_code": 200, "body": "Success 1"},
        {"status_code": 200, "body": "Success 2"},
        {"status_code": 409, "body": "Conflict 3"}
    ]
    
    app_config = {"target": {"base_url": "http://test"}}
    
    # We need to mock ResponseAnalyzer internal usage if we want, 
    # but for concurrency logic handling, we embedded logic directly in orchestrator for now.
    
    # Run
    with patch("chaos_kitten.paws.analyzer.ResponseAnalyzer") as MockAnalyzer:
        mock_analyzer_instance = MockAnalyzer.return_value
        mock_analyzer_instance.analyze.return_value = None # Default no finding from standard analysis
        
        result = await execute_and_analyze(state, mock_executor, app_config)
    
    # Assertions
    assert mock_executor.execute.call_count == 3
    
    findings = result.get("findings", [])
    # Logic: 2 successes out of 3. >1 success => race condition detected.
    assert len(findings) == 1
    assert findings[0]["type"] == "race_condition"
    assert "2/3" in findings[0]["description"] or "2 successes" in findings[0]["evidence"]

@pytest.mark.asyncio
async def test_workflow_attack_execution():
    # Setup state
    state = {
        "planned_attacks": [
            {
                "name": "Workflow Bypass Test",
                "workflow": [
                    {"step": 1, "path": "/step1", "method": "POST"},
                    {"step": 2, "path": "/step2", "method": "POST"}
                ],
                "path": "/workflow", # informative
                "success_indicators": {"status_codes": [200]}
            }
        ]
    }
    
    mock_executor = AsyncMock()
    mock_executor.execute.side_effect = [
        {"status": 200, "body": "Step 1 OK"},
        {"status": 200, "body": "Step 2 OK"}
    ]
    
    app_config = {"target": {"base_url": "http://test"}}

    with patch("chaos_kitten.paws.analyzer.ResponseAnalyzer") as MockAnalyzer:
        mock_analyzer_instance = MockAnalyzer.return_value
        # Mock analyzer to return a finding for the final step
        mock_analyzer_instance.analyze.return_value = {
            "name": "Workflow Bypass",
            "type": "business_logic"
        }
        
        result = await execute_and_analyze(state, mock_executor, app_config)
        
    start_call_args = mock_executor.execute.call_args_list[0]
    final_call_args = mock_executor.execute.call_args_list[1]
    
    assert start_call_args[0][0]["url"] == "http://test/step1"
    assert final_call_args[0][0]["url"] == "http://test/step2"
    
    findings = result.get("findings", [])
    assert len(findings) == 1
    assert findings[0]["name"] == "Workflow Bypass"
