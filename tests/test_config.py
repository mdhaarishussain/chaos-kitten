import os
import pytest
import yaml
from pathlib import Path
from chaos_kitten.utils.config import Config

@pytest.fixture
def temp_config_file(tmp_path):
    def _create_config(data, filename="chaos-kitten.yaml"):
        file_path = tmp_path / filename
        if data is not None:
            with open(file_path, "w", encoding="utf-8") as f:
                if data == "":
                    pass # Empty file
                else:
                    yaml.dump(data, f)
        else:
            file_path.touch()
        return file_path
    
    return _create_config

def test_valid_rest_config(temp_config_file):
    data = {"target": {"type": "rest", "base_url": "http://localhost:8080"}}
    path = temp_config_file(data)
    config = Config(path)
    config.load()
    assert config.target["base_url"] == "http://localhost:8080"
    assert config.target.get("type", "rest") == "rest"

def test_valid_graphql_config(temp_config_file):
    data = {"target": {"type": "graphql", "graphql_endpoint": "http://localhost:8080/graphql"}}
    path = temp_config_file(data)
    config = Config(path)
    config.load()
    assert config.target["graphql_endpoint"] == "http://localhost:8080/graphql"

def test_env_var_expansion(temp_config_file, monkeypatch):
    data = {"target": {"base_url": "http://localhost:8080", "api_key": "${API_TOKEN}"}}
    path = temp_config_file(data)
    monkeypatch.setenv("API_TOKEN", "secret123")
    config = Config(path)
    config.load()
    assert config.target["api_key"] == "secret123"

def test_recursive_env_var_expansion(temp_config_file, monkeypatch):
    data = {
        "target": {"type": "rest", "base_url": "http://localhost:8080"},
        "key": {"nested": "${VAR}"},
        "list_key": [{"nested_list": "${VAR3}"}]
    }
    path = temp_config_file(data)
    monkeypatch.setenv("VAR", "nested_val")
    monkeypatch.setenv("VAR3", "nested_list_val")
    config = Config(path)
    config.load()
    assert config._config["key"]["nested"] == "nested_val"
    assert config._config["list_key"][0]["nested_list"] == "nested_list_val"

def test_agent_default_max_concurrent_agents(temp_config_file):
    data = {"target": {"base_url": "http://localhost:8080"}}
    path = temp_config_file(data)
    config = Config(path)
    config.load()
    assert config.agent["max_concurrent_agents"] == 3

def test_non_dict_root_error(temp_config_file):
    path = temp_config_file(["this", "is", "a", "list", "not", "a", "dict"])
    config = Config(path)
    with pytest.raises(ValueError, match=r"Configuration root must be a mapping/object"):
        config.load()

def test_missing_target_error(temp_config_file):
    data = {"other": "value"}
    path = temp_config_file(data)
    config = Config(path)
    with pytest.raises(ValueError, match=r"Missing required configuration field: target"):
        config.load()

def test_missing_base_url_error(temp_config_file):
    data = {"target": {"type": "rest"}}
    path = temp_config_file(data)
    config = Config(path)
    with pytest.raises(ValueError, match=r"Missing required field: target\.base_url"):
        config.load()

def test_missing_graphql_fields_error(temp_config_file):
    data = {"target": {"type": "graphql"}}
    path = temp_config_file(data)
    config = Config(path)
    with pytest.raises(ValueError, match=r"GraphQL target requires either 'graphql_endpoint' or 'graphql_schema'"):
        config.load()

def test_invalid_max_rounds_error(temp_config_file):
    data = {"target": {"base_url": "http://localhost"}, "adaptive": {"max_rounds": -1}}
    path = temp_config_file(data)
    config = Config(path)
    with pytest.raises(ValueError, match=r"adaptive\.max_rounds must be an integer between 1 and 10"):
        config.load()

def test_auth_default_totp_field(temp_config_file):
    data = {"target": {"base_url": "http://localhost"}, "auth": {}}
    path = temp_config_file(data)
    config = Config(path)
    config.load()
    assert config.auth.get("totp_field") == "code"

def test_property_getters(temp_config_file):
    data = {
        "target": {"base_url": "http://target"},
        "agent": {"max_concurrent_agents": 5},
        "executor": {"timeout": 30},
        "recon": {"mode": "passive"},
        "safety": {"level": "high"},
        "adaptive": {"max_rounds": 10},
        "auth": {"type": "basic"}
    }
    path = temp_config_file(data)
    config = Config(path)
    config.load()
    
    assert config.target == {"base_url": "http://target"}
    assert config.agent == {"max_concurrent_agents": 5}
    assert config.executor == {"timeout": 30}
    assert config.recon == {"mode": "passive"}
    assert config.safety == {"level": "high"}
    assert config.adaptive == {"max_rounds": 10}
    assert config.auth == {"type": "basic", "totp_field": "code"}

def test_empty_file_error(temp_config_file):
    path = temp_config_file(None)  
    config = Config(path)
    with pytest.raises(ValueError, match=r"Missing required configuration field: target"):
        config.load()

def test_file_not_found_error(tmp_path):
    path = tmp_path / "nonexistent.yaml"
    config = Config(path)
    with pytest.raises(FileNotFoundError, match=r"Configuration file not found"):
        config.load()
