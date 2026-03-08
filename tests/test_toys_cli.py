import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from chaos_kitten.cli import app
from chaos_kitten.toys_cli import _get_local_toys_dir

runner = CliRunner()

@pytest.fixture
def mock_registry():
    return {
        "version": "1.0",
        "profiles": {
            "test-toy": {
                "name": "Test Toy",
                "description": "A test toy profile",
                "author": "tester",
                "category": "Testing",
                "url": "https://example.com/test-toy.yaml"
            },
            "another-toy": {
                "name": "Another Toy",
                "description": "Another test toy",
                "author": "tester2",
                "category": "Security",
                "url": "https://example.com/another-toy.yaml"
            }
        }
    }

@pytest.fixture
def mock_fetch_registry(mock_registry):
    with patch("chaos_kitten.toys_cli._fetch_registry", return_value=mock_registry) as mock:
        yield mock

@pytest.fixture
def temp_toys_dir(tmp_path):
    with patch("chaos_kitten.toys_cli._get_local_toys_dir", return_value=tmp_path):
        yield tmp_path

def test_toys_search_no_args(mock_fetch_registry):
    result = runner.invoke(app, ["toys", "search"])
    assert result.exit_code == 0
    assert "Test Toy" in result.stdout
    assert "Another Toy" in result.stdout
    assert "test-toy" in result.stdout

def test_toys_search_with_keyword(mock_fetch_registry):
    result = runner.invoke(app, ["toys", "search", "another"])
    assert result.exit_code == 0
    assert "Another Toy" in result.stdout
    assert "Test Toy" not in result.stdout

def test_toys_search_with_category(mock_fetch_registry):
    result = runner.invoke(app, ["toys", "search", "--category", "Security"])
    assert result.exit_code == 0
    assert "Another Toy" in result.stdout
    assert "Test Toy" not in result.stdout

def test_toys_list_empty(temp_toys_dir):
    result = runner.invoke(app, ["toys", "list"])
    assert result.exit_code == 0
    assert "No profiles installed" in result.stdout

def test_toys_list_with_files(temp_toys_dir):
    (temp_toys_dir / "test1.yaml").touch()
    (temp_toys_dir / "test2.json").touch()
    
    result = runner.invoke(app, ["toys", "list"])
    assert result.exit_code == 0
    assert "test1.yaml" in result.stdout
    assert "test2.json" in result.stdout

def test_toys_publish():
    with runner.isolated_filesystem():
        Path("my_toy.yaml").touch()
        result = runner.invoke(app, ["toys", "publish", "my_toy.yaml"])
        assert result.exit_code == 0
        assert "Publishing to Chaos Kitten Registry" in result.stdout
        assert "Fork the repository" in result.stdout

@patch("urllib.request.urlopen")
def test_toys_install_success(mock_urlopen, mock_fetch_registry, temp_toys_dir):
    # Mock the response for downloading the profile
    mock_response = MagicMock()
    mock_response.status = 200
    
    # Valid profile content
    valid_profile = '''
name: Test Profile
description: A test profile
author: tester
version: "1.0"
type: attack_profile
phases:
  - name: test_phase
    steps:
      - name: test_step
        type: request
        method: GET
        path: /test
'''
    mock_response.read.return_value = valid_profile.encode('utf-8')
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    # Mock the validator to always return valid
    with patch("chaos_kitten.validators.profile_validator.AttackProfileValidator.validate_profile") as mock_validate:
        mock_report = MagicMock()
        mock_report.is_valid = True
        mock_validate.return_value = mock_report
        
        result = runner.invoke(app, ["toys", "install", "test-toy"])
        
        assert result.exit_code == 0
        assert "Successfully installed 'test-toy'" in result.stdout
        assert (temp_toys_dir / "test-toy.yaml").exists()

@patch("urllib.request.urlopen")
def test_toys_install_allows_payload_content(mock_urlopen, mock_fetch_registry, temp_toys_dir):
    # Mock the response for downloading the profile
    mock_response = MagicMock()
    mock_response.status = 200
    
    # Dangerous profile content
    dangerous_profile = '''
name: Dangerous Profile
description: A dangerous profile
author: attacker
version: "1.0"
type: attack_profile
phases:
  - name: test_phase
    steps:
      - name: test_step
        type: request
        method: GET
        path: /test
        payload: "eval('import os; os.system(\"rm -rf /\")')"
'''
    mock_response.read.return_value = dangerous_profile.encode('utf-8')
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    # Mock the validator to treat the profile as valid even though
    # the payload string contains code-like content. The YAML is data,
    # and schema validation (not keyword scanning) guards safety.
    with patch("chaos_kitten.validators.profile_validator.AttackProfileValidator.validate_profile") as mock_validate:
        mock_report = MagicMock()
        mock_report.is_valid = True
        mock_validate.return_value = mock_report

        with patch("chaos_kitten.toys_cli.logger.warning") as mock_warning:
            result = runner.invoke(app, ["toys", "install", "test-toy"])

            assert result.exit_code == 0
            assert "Successfully installed 'test-toy'" in result.stdout
            assert (temp_toys_dir / "test-toy.yaml").exists()
            mock_warning.assert_called_with("Profile contains suspicious pattern: \\.system\\(")
