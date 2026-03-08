import pytest
import yaml
from pathlib import Path
from unittest.mock import MagicMock, patch
from chaos_kitten.brain.attack_planner import AttackPlanner

@pytest.fixture
def planner(tmp_path):
    d = tmp_path / "toys"
    d.mkdir()
    
    # Create mock language profiles
    profiles = [
        {"name": "Java Deserialization", "category": "deserialization", "severity": "critical", "supported_languages": ["java"], "target_fields": ["data"], "payloads": ["rO0ABQ=="]},
        {"name": "Python Deserialization", "category": "deserialization", "severity": "critical", "supported_languages": ["python"], "target_fields": ["data"], "payloads": ["cos\\nsystem"]},
        {"name": "PHP Deserialization", "category": "deserialization", "severity": "critical", "supported_languages": ["php"], "target_fields": ["data"], "payloads": ["O:8:"]},
        {"name": "Ruby Deserialization", "category": "deserialization", "severity": "critical", "supported_languages": ["ruby"], "target_fields": ["data"], "payloads": ["BAhbAA=="]},
    ]
    
    for i, prof in enumerate(profiles):
        with open(d / f"p{i}.yaml", "w") as f:
            yaml.dump(prof, f)
            
    with patch.object(AttackPlanner, "_init_llm", return_value=MagicMock()):
        p = AttackPlanner(endpoints=[], toys_path=str(d))
        return p

def test_language_detection_headers(planner):
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "requestBody": {
            "content": {
                "application/x-java-serialized-object": {"schema": {"properties": {"data": {"type": "string"}}}},
                "application/python-pickle": {"schema": {}}
            }
        }
    }
    
    langs = planner._detect_serialization_languages(endpoint)
    assert "java" in langs
    assert "python" in langs
    assert "php" not in langs
    
    attacks = planner._plan_rule_based(endpoint)
    attack_names = [a["name"] for a in attacks]
    assert "Java Deserialization" in attack_names
    assert "Python Deserialization" in attack_names
    assert "PHP Deserialization" not in attack_names

def test_language_detection_path(planner):
    endpoint = {
        "path": "/api/process.php",
        "method": "POST",
        "parameters": [{"name": "data", "in": "query"}]
    }
    langs = planner._detect_serialization_languages(endpoint)
    assert "php" in langs
    
    attacks = planner._plan_rule_based(endpoint)
    assert any(a["name"] == "PHP Deserialization" for a in attacks)
    assert not any(a["name"] == "Java Deserialization" for a in attacks)

def test_language_detection_params(planner):
    endpoint = {
        "path": "/submit",
        "method": "POST",
        "parameters": [{"name": "ruby_marshal_data", "in": "query"}]
    }
    langs = planner._detect_serialization_languages(endpoint)
    assert "ruby" in langs
    
    attacks = planner._plan_rule_based(endpoint)
    assert any(a["name"] == "Ruby Deserialization" for a in attacks)

def test_no_language_detected(planner):
    # Should skip language-specific profiles if no language detected
    endpoint = {
        "path": "/submit",
        "method": "POST",
        "parameters": [{"name": "data", "in": "query"}]
    }
    langs = planner._detect_serialization_languages(endpoint)
    assert len(langs) == 0
    
    attacks = planner._plan_rule_based(endpoint)
    assert not any("Deserialization" in a["name"] for a in attacks)
