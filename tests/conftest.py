import pytest
import os
import sys
from unittest.mock import MagicMock

# Mock langgraph if not installed
try:
    import langgraph
except ImportError:
    mock_langgraph = MagicMock()
    sys.modules["langgraph"] = mock_langgraph
    sys.modules["langgraph.prebuilt"] = MagicMock()
    sys.modules["langgraph.graph"] = MagicMock()
    sys.modules["langgraph.graph.message"] = MagicMock()

# Mock langchain libraries if not installed
try:
    import langchain_openai
except ImportError:
    sys.modules["langchain_openai"] = MagicMock()
    sys.modules["langchain_openai.chat_models"] = MagicMock()

try:
    import langchain_anthropic
except ImportError:
    sys.modules["langchain_anthropic"] = MagicMock()

try:
    import langchain_ollama
except ImportError:
    sys.modules["langchain_ollama"] = MagicMock()

try:
    import langchain_core
except ImportError:
    sys.modules["langchain_core"] = MagicMock()
    sys.modules["langchain_core.messages"] = MagicMock()
    sys.modules["langchain_core.prompts"] = MagicMock()
    sys.modules["langchain_core.output_parsers"] = MagicMock()
    sys.modules["langchain_core.runnables"] = MagicMock()

# Re-import essential modules required later
import subprocess
import time
import requests
import json
import yaml
from unittest.mock import patch

# Path definitions
DEMO_APP_PATH = os.path.join("examples", "demo_api", "app.py")
SAMPLE_OPENAPI_PATH = os.path.join("examples", "sample_openapi.json")
DEMO_PORT = 5002
DEMO_URL = f"http://localhost:{DEMO_PORT}"

@pytest.fixture(scope="session")
def demo_api_server():
    """Start the demo API server for integration tests."""
    if not os.path.exists(DEMO_APP_PATH):
        pytest.skip(f"Demo app not found at {DEMO_APP_PATH}")

    # Check port availability or existing server
    try:
        requests.get(f"{DEMO_URL}/api/health", timeout=1)
        # Verify if we should use existing or fail? 
        # For CI, assume clean state. Local dev might leave it running.
        # We'll just use it if it's there.
    except Exception:
        # Start server
        env = os.environ.copy()
        env["FLASK_APP"] = DEMO_APP_PATH
        
        process = subprocess.Popen(
            [sys.executable, "-m", "flask", "run", "--port", str(DEMO_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )

        # Wait for start
        started = False
        for _ in range(40): # 20 seconds
            try:
                requests.get(f"{DEMO_URL}/api/health", timeout=0.5)
                started = True
                break
            except:
                time.sleep(0.5)
        
        if not started:
            process.terminate()
            stdout, stderr = process.communicate()
            pytest.fail(f"Failed to start demo API:\n{stderr}")

        yield DEMO_URL

        # Cleanup
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            process.terminate()
            process.wait()
    else:
        # Server was already running
        yield DEMO_URL

@pytest.fixture
def mock_llm_client():
    """Mocks the LLM to return valid JSON attack plans."""
    mock_llm = MagicMock()
    
    # Mock message structure
    mock_message = MagicMock()
    # Default plan: generic SQLi
    mock_message.content = json.dumps([
        {
            "type": "sql_injection",
            "name": "SQL Injection Basic",
            "description": "Standard SQL injection test",
            "payload": "' OR 1=1 --",
            "target_param": "username",
            "priority": "high",
            "method": "POST",
            "field": "username",
            "location": "body",
            "expected_indicators": {"status_codes": [500], "response_contains": ["SQL syntax"]}
        }
    ])
    mock_llm.invoke.return_value = mock_message

    # Patch the AttackPlanner to use our mock
    # Note: We patch where the class is IMPORTED or DEFINED
    with patch("chaos_kitten.brain.attack_planner.AttackPlanner._init_llm", return_value=mock_llm):
        yield mock_llm

@pytest.fixture
def sample_scan_results():
    """Returns mock scan results for reporter tests."""
    return {
        "vulnerabilities": [
            {
                "type": "sql_injection",
                "title": "SQL Injection in Login",
                "description": "The login endpoint is vulnerable to SQLi.",
                "severity": "critical",
                "endpoint": "/api/login",
                "payload": "' OR 1=1 --",
                "evidence": "SQL syntax error in response",
                "remediation": "Use parameterized queries.",
                "proof_of_concept": "curl -X POST ...",
                "id": "vuln_1"
            },
            {
                "type": "xss",
                "title": "Reflected XSS",
                "description": "Search parameter reflects input.",
                "severity": "medium",
                "endpoint": "/api/search",
                "evidence": "<script>alert(1)</script>",
                "id": "vuln_2"
            }
        ],
        "total_vulnerabilities": 2
    }

@pytest.fixture
def sample_config(tmp_path):
    """Creates a temporary config file."""
    config_path = tmp_path / "chaos-kitten.yaml"
    config_data = {
        "target": {
            "base_url": DEMO_URL,
            "type": "rest"
        },
        "agent": {
            "llm_provider": "anthropic",
            "model": "claude-3-5-sonnet"
        }
    }
    with open(config_path, "w") as f:
        yaml.dump(config_data, f)
    return str(config_path)
