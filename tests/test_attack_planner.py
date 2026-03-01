import os
import pytest
import yaml
from pathlib import Path
from unittest.mock import MagicMock, patch
from chaos_kitten.brain.attack_planner import AttackPlanner, AttackProfile

# Fixtures

@pytest.fixture
def toys_dir(tmp_path):
    """Create a temporary directory for toys (attack profiles)."""
    d = tmp_path / "toys"
    d.mkdir()
    return d

@pytest.fixture
def valid_profile_yaml(toys_dir):
    """Create a valid attack profile YAML file."""
    profile_data = {
        "name": "SQL Injection Basic",
        "category": "sql_injection",
        "severity": "high",
        "description": "Basic SQL injection attack",
        "payloads": ["' OR 1=1 --", "' UNION SELECT 1,2,3 --"],
        "target_fields": ["id", "user", "q"],
        "success_indicators": {"status_codes": [500]},
        "remediation": "Use prepared statements",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
    }
    file_path = toys_dir / "sqli.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump(profile_data, f)
    return file_path

@pytest.fixture
def low_severity_profile_yaml(toys_dir):
    """Create a low severity attack profile."""
    profile_data = {
        "name": "Clickjacking",
        "category": "ui_redress",
        "severity": "low",
        "description": "Clickjacking attack",
        "payloads": ["<iframe>...</iframe>"],
        "target_fields": ["*"],
        "success_indicators": {"headers": {"X-Frame-Options": None}}
    }
    file_path = toys_dir / "clickjacking.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump(profile_data, f)
    return file_path

@pytest.fixture
def mock_llm_setup():
    """Mock the LLM initialization to avoid external calls."""
    with patch("chaos_kitten.brain.attack_planner.ChatAnthropic") as mock_anthropic, \
         patch("chaos_kitten.brain.attack_planner.ChatOpenAI") as mock_openai, \
         patch("chaos_kitten.brain.attack_planner.ChatOllama") as mock_ollama:
        yield {
            "anthropic": mock_anthropic,
            "openai": mock_openai,
            "ollama": mock_ollama
        }

# Tests

def test_load_attack_profiles_valid(toys_dir, valid_profile_yaml, mock_llm_setup):
    """Test loading a valid attack profile."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    assert len(planner.attack_profiles) == 1
    profile = planner.attack_profiles[0]
    assert profile.name == "SQL Injection Basic"
    assert profile.category == "sql_injection"
    assert profile.severity == "high"
    assert len(profile.payloads) == 2
    assert "id" in profile.target_fields

def test_parse_profile_structure(toys_dir, valid_profile_yaml, mock_llm_setup):
    """Test that all fields are correctly parsed into the AttackProfile object."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    profile = planner.attack_profiles[0]
    
    assert isinstance(profile, AttackProfile)
    assert profile.description == "Basic SQL injection attack"
    assert profile.remediation == "Use prepared statements"
    assert "https://owasp.org/www-community/attacks/SQL_Injection" in profile.references
    assert profile.success_indicators == {"status_codes": [500]}

def test_filter_by_severity(toys_dir, valid_profile_yaml, low_severity_profile_yaml, mock_llm_setup):
    """Test that we can filter loaded profiles by severity."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    assert len(planner.attack_profiles) == 2
    
    high_sev = [p for p in planner.attack_profiles if p.severity == "high"]
    low_sev = [p for p in planner.attack_profiles if p.severity == "low"]
    
    assert len(high_sev) == 1
    assert high_sev[0].name == "SQL Injection Basic"
    assert len(low_sev) == 1
    assert low_sev[0].name == "Clickjacking"

def test_filter_by_category(toys_dir, valid_profile_yaml, low_severity_profile_yaml, mock_llm_setup):
    """Test that we can filter loaded profiles by category."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    sqli = [p for p in planner.attack_profiles if p.category == "sql_injection"]
    ui = [p for p in planner.attack_profiles if p.category == "ui_redress"]
    
    assert len(sqli) == 1
    assert len(ui) == 1

def test_filter_by_target_field(toys_dir, valid_profile_yaml, mock_llm_setup):
    """Test that plan_attacks filters profiles based on target fields (rule-based)."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    # Endpoint with 'id' parameter -> should match SQLi profile
    endpoint_matching = {
        "path": "/users",
        "method": "GET",
        "parameters": [{"name": "id", "in": "query"}]
    }
    
    # We test _plan_rule_based directly to bypass LLM logic
    attacks = planner._plan_rule_based(endpoint_matching)
    
    # Clean up generated 'unique' list for assertion
    sqli_attacks = [a for a in attacks if a["type"] == "sql_injection" and a["profile_name"] == "SQL Injection Basic"]
    assert len(sqli_attacks) >= 1
    assert sqli_attacks[0]["field"] == "id"
    assert sqli_attacks[0]["payload"]["id"] == "' OR 1=1 --"

def test_handle_missing_files(toys_dir, mock_llm_setup):
    """Test behavior when toys directory exists but no files match pattern."""
    # toys_dir is created but empty of yaml files
    # create a txt file to ensure dir isn't empty, but glob won't pick it up
    (toys_dir / "readme.txt").write_text("hello")
    
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    assert len(planner.attack_profiles) == 0

def test_invalid_yaml(toys_dir, mock_llm_setup):
    """Test handling of invalid YAML files."""
    file_path = toys_dir / "invalid.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("name: [unclosed list") # Invalid syntax
    
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    # Should log error and skip file, not crash
    assert len(planner.attack_profiles) == 0

def test_incomplete_profile_validation(toys_dir, mock_llm_setup):
    """Test that profiles missing required fields are skipped."""
    file_path = toys_dir / "incomplete.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump({"name": "Incomplete"}, f) # Missing category, severity etc.
    
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    assert len(planner.attack_profiles) == 0

def test_bad_types_validation(toys_dir, mock_llm_setup):
    """Test validation of field types (payloads must be list)."""
    file_path = toys_dir / "bad_types.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump({
            "name": "Bad Types",
            "category": "test",
            "severity": "low",
            "payloads": "not-a-list", # Error
            "target_fields": ["id"]
        }, f)
    
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    assert len(planner.attack_profiles) == 0

def test_profile_endpoints_matching_negative(toys_dir, valid_profile_yaml, mock_llm_setup):
    """Test that rule-based planning does NOT suggest irrelevant attacks."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    # Endpoint with non-matching param 'version' (profile targets 'id', 'user', 'q')
    endpoint_nomatch = {
        "path": "/about",
        "method": "GET",
        "parameters": [{"name": "version", "in": "query"}]
    }
    
    attacks = planner._plan_rule_based(endpoint_nomatch)
    
    # Should only return fallback, not SQL Injection Basic
    profile_attacks = [a for a in attacks if a["name"] == "SQL Injection Basic"]
    assert len(profile_attacks) == 0
    
    # Fallback should be present
    fallback = [a for a in attacks if a["name"] == "Fallback SQLi Probe"]
    assert len(fallback) > 0

def test_llm_init_providers(toys_dir, mock_llm_setup):
    """Test LLM initialization for different providers."""
    # Anthropic
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir), llm_provider="anthropic")
    assert mock_llm_setup["anthropic"].called
    
    # OpenAI
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir), llm_provider="openai")
    assert mock_llm_setup["openai"].called
    
    # Ollama
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir), llm_provider="ollama")
    assert mock_llm_setup["ollama"].called
    
    # Unknown -> Fallback to Anthropic and log warning
    with patch("chaos_kitten.brain.attack_planner.logger") as mock_logger:
        planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir), llm_provider="unknown")
        # Should create Anthropic instance (reusing mock from fixture since we patch class)
        # Note: the fixture patches the classes, so subsequent calls use new mocks if not careful,
        # but we are just asserting call count on the shared fixture mocks.
        # Actually need to reset mocks if we care about counts per call, 
        # but simply asserting 'called' handles multiple calls.
        
        # Verify warning log
        mock_logger.warning.assert_any_call("Unknown LLM provider %s. Falling back to Claude.", "unknown")

def test_empty_profile_directory(toys_dir, mock_llm_setup):
    """Test behavior when toys directory path itself does not exist or empty."""
    # Point to a non-existent path
    non_existent = toys_dir / "non_existent"
    planner = AttackPlanner(endpoints=[], toys_path=str(non_existent))
    assert len(planner.attack_profiles) == 0

def test_plan_attacks_fallback_on_llm_failure(toys_dir, valid_profile_yaml, mock_llm_setup):
    """Test that plan_attacks falls back to rule-based if LLM fails."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    endpoint = {
        "path": "/users",
        "method": "GET",
        "parameters": [{"name": "id", "in": "query"}]
    }
    
    # Setup mock to raise exception when invoked
    mock_llm_instance = mock_llm_setup["anthropic"].return_value
    # The pipeline is: prompt | self.llm | parser
    # We need to mock the invoke method of the chain. 
    # Since chain is constructed inside method, we can mock ChatPromptTemplate or one of the components
    # to return a mock chain that fails.
    
    with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate.from_template") as mock_prompt_cls:
        mock_chain = MagicMock()
        mock_chain.invoke.side_effect = Exception("LLM API Error")
        
        # prompt | llm | parser -> returns a RunnableSerializable which has invoke()
        # We can mock the result of the pipe operations
        mock_prompt = MagicMock()
        mock_prompt.__or__.return_value.__or__.return_value = mock_chain
        mock_prompt_cls.return_value = mock_prompt
        
        # Run
        attacks = planner.plan_attacks(endpoint)
        
        # Should contain rule-based attacks (SQL Injection Basic)
        sqli = [a for a in attacks if a["name"] == "SQL Injection Basic"]
        assert len(sqli) == 1

def test_llm_attack_generation_success(toys_dir, mock_llm_setup):
    """Test successful generation of attacks via LLM."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    endpoint = {
        "path": "/users", 
        "method": "GET", 
        "parameters": [{"name": "id", "in": "query"}]
    }
    
    # Mock the LLM chain to return a valid list of attacks
    mock_attacks = [
        {
            "type": "sql_injection",
            "name": "LLM SQLi",
            "description": "Output generated by LLM",
            "payload": "' OR 1=1",
            "target_param": "id",
            "severity": "high",
            "priority": "high",
            "expected_status": 500
        }
    ]
    
    with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate.from_template") as mock_prompt_cls:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = mock_attacks
        
        mock_prompt = MagicMock()
        mock_prompt.__or__.return_value.__or__.return_value = mock_chain
        mock_prompt_cls.return_value = mock_prompt
        
        attacks = planner.plan_attacks(endpoint)
        
        assert len(attacks) == 1
        assert attacks[0]["name"] == "LLM SQLi"
        assert attacks[0]["payload"]["id"] == "' OR 1=1"
        assert attacks[0]["severity"] == "high"

def test_fuzzy_field_matching(toys_dir, mock_llm_setup):
    """Test fuzzy matching logic in _field_matches_target."""
    # Create profile targeting 'email'
    profile_data = {
        "name": "Email Injection",
        "category": "injection",
        "severity": "medium",
        "payloads": ["test"],
        "target_fields": ["email"],
    }
    file_path = toys_dir / "email.yaml"
    with open(file_path, "w", encoding="utf-8") as f:
        yaml.dump(profile_data, f)
        
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    # Endpoint with 'user_email' -> should match 'email' via fuzzy logic
    endpoint = {
        "path": "/register",
        "method": "POST",
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "user_email": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner._plan_rule_based(endpoint)
    email_attacks = [a for a in attacks if a["name"] == "Email Injection"]
    assert len(email_attacks) > 0
    assert email_attacks[0]["field"] == "user_email"

def test_suggest_payloads(toys_dir, mock_llm_setup):
    """Test suggest_payloads method."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate.from_template") as mock_prompt_cls:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = ["payload1", "payload2"]
        
        mock_prompt = MagicMock()
        mock_prompt.__or__.return_value.__or__.return_value = mock_chain
        mock_prompt_cls.return_value = mock_prompt
        
        payloads = planner.suggest_payloads("sql_injection", {"path": "/test"})
        assert len(payloads) == 2
        assert "payload1" in payloads

def test_suggest_payloads_fallback(toys_dir, mock_llm_setup):
    """Test suggest_payloads fallback when LLM fails."""
    planner = AttackPlanner(endpoints=[], toys_path=str(toys_dir))
    
    with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate.from_template") as mock_prompt_cls:
        mock_chain = MagicMock()
        mock_chain.invoke.side_effect = Exception("LLM Error")
        
        mock_prompt = MagicMock()
        mock_prompt.__or__.return_value.__or__.return_value = mock_chain
        mock_prompt_cls.return_value = mock_prompt
        
        payloads = planner.suggest_payloads("sql_injection", {})
        assert len(payloads) > 0
        assert "' OR 1=1 --" in payloads # Check fallback payload
