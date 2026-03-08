import pytest
from unittest.mock import AsyncMock, patch
from chaos_kitten.brain.orchestrator import execute_and_analyze

@pytest.fixture
def mock_executor():
    executor = AsyncMock()
    # execute_attack returns a valid response dict
    executor.execute_attack.return_value = {"status_code": 200, "body": "Success"}
    return executor

@pytest.fixture
def mock_state():
    return {
        "planned_attacks": [
            {
                "name": "Test Attack",
                "method": "POST",
                "path": "/api/test",
                "payload": {"key": "original"},
                "headers": {"Content-Type": "application/json"}
            }
        ]
    }

@pytest.mark.asyncio
async def test_interactive_mode_yes(mock_state, mock_executor):
    """Test interactive execution when user confirms with 'y'."""
    app_config = {"execution": {"interactive": True}, "target": {"base_url": "http://test.com"}}
    
    with patch("chaos_kitten.brain.orchestrator.Prompt.ask", return_value="y"):
        await execute_and_analyze(mock_state, mock_executor, app_config)
        
    mock_executor.execute_attack.assert_called_once()
    call_args = mock_executor.execute_attack.call_args
    # Verify the payload passed to executor is the original one
    assert call_args.kwargs['payload'] == {"key": "original"}

@pytest.mark.asyncio
async def test_interactive_mode_no(mock_state, mock_executor):
    """Test user skips execution with 'n'."""
    app_config = {"execution": {"interactive": True}, "target": {"base_url": "http://test.com"}}
    
    with patch("chaos_kitten.brain.orchestrator.Prompt.ask", return_value="n"):
        await execute_and_analyze(mock_state, mock_executor, app_config)
        
    mock_executor.execute_attack.assert_not_called()

@pytest.mark.asyncio
async def test_interactive_mode_modify(mock_state, mock_executor):
    """Test user modification with 'm'."""
    app_config = {"execution": {"interactive": True}, "target": {"base_url": "http://test.com"}}
    
    # First prompt returns 'm', second prompt returns new JSON payload
    with patch("chaos_kitten.brain.orchestrator.Prompt.ask", side_effect=["m", '{"key": "modified"}']):
        await execute_and_analyze(mock_state, mock_executor, app_config)
        
    mock_executor.execute_attack.assert_called_once()
    call_args = mock_executor.execute_attack.call_args
    assert call_args.kwargs['payload'] == {"key": "modified"}

@pytest.mark.asyncio
async def test_interactive_disabled(mock_state, mock_executor):
    """Test execution proceeds without prompting when flag is off."""
    app_config = {"execution": {"interactive": False}, "target": {"base_url": "http://test.com"}}
    
    with patch("chaos_kitten.brain.orchestrator.Prompt.ask") as mock_ask:
        await execute_and_analyze(mock_state, mock_executor, app_config)
        assert not mock_ask.called
        
    mock_executor.execute_attack.assert_called_once()

@pytest.mark.asyncio
async def test_interactive_mode_invalid_json(mock_state, mock_executor):
    """Test invalid JSON input reverts to original payload."""
    app_config = {"execution": {"interactive": True}, "target": {"base_url": "http://test.com"}}
    
    with patch("chaos_kitten.brain.orchestrator.Prompt.ask", side_effect=["m", "not-valid-json"]):
        await execute_and_analyze(mock_state, mock_executor, app_config)
        
    mock_executor.execute_attack.assert_called_once()
    # Should use original payload
    assert mock_executor.execute_attack.call_args.kwargs["payload"] == {"key": "original"}

