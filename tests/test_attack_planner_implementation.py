import os
import tempfile

import pytest
import yaml

from chaos_kitten.brain.attack_planner import AttackPlanner


@pytest.fixture
def temp_toys_dir():
    """Create a temporary directory with dummy attack profiles."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create a valid profile
        valid_profile = {
            "name": "SQL Injection Test",
            "category": "injection",
            "severity": "critical",
            "description": "Test SQLi",
            "payloads": ["' OR 1=1 --"],
            "target_fields": ["username", "id"],
            "success_indicators": {"status_codes": [500]},
        }
        with open(os.path.join(tmpdirname, "sqli.yaml"), "w") as f:
            yaml.dump(valid_profile, f)

        # Create another profile
        xss_profile = {
            "name": "XSS Test",
            "category": "injection",
            "severity": "high",
            "description": "Test XSS",
            "payloads": ["<script>alert(1)</script>"],
            "target_fields": ["comment", "bio"],
            "success_indicators": {"response_contains": ["<script>"]},
        }
        with open(os.path.join(tmpdirname, "xss.yaml"), "w") as f:
            yaml.dump(xss_profile, f)

        # Create an invalid profile (missing required fields)
        invalid_profile = {
            "name": "Invalid Profile",
            # Missing category, severity, etc.
        }
        with open(os.path.join(tmpdirname, "invalid.yaml"), "w") as f:
            yaml.dump(invalid_profile, f)

        yield tmpdirname


def test_load_attack_profiles(temp_toys_dir):
    """Test loading attack profiles from a directory."""
    planner = AttackPlanner(endpoints=[], toys_path=temp_toys_dir)
    planner.load_attack_profiles()

    assert len(planner.attack_profiles) == 2

    profile_names = [p.name for p in planner.attack_profiles]
    assert "SQL Injection Test" in profile_names
    assert "XSS Test" in profile_names
    assert "Invalid Profile" not in profile_names


def test_plan_attacks(temp_toys_dir):
    """Test planning attacks for an endpoint."""
    planner = AttackPlanner(endpoints=[], toys_path=temp_toys_dir)
    planner.load_attack_profiles()

    # Define an endpoint vulnerable to SQLi (username matches)
    endpoint = {
        "path": "/login",
        "method": "post",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                        }
                    }
                }
            }
        },
    }

    attacks = planner.plan_attacks(endpoint)

    # Should find match for username (SQLi)
    # Should likely NOT find match for XSS unless fuzzy matching is very loose (comment/bio != username)

    assert len(attacks) >= 1
    sqli_attack = next(
        (a for a in attacks if a["profile_name"] == "SQL Injection Test"), None
    )
    assert sqli_attack is not None
    assert sqli_attack["field"] == "username"
    assert sqli_attack["method"] == "post"
    assert "' OR 1=1 --" in sqli_attack["payloads"]


def test_plan_attacks_fuzzy_match(temp_toys_dir):
    """Test fuzzy matching for fields."""
    planner = AttackPlanner(endpoints=[], toys_path=temp_toys_dir)
    planner.load_attack_profiles()

    # Endpoint with 'user_id' which should match 'id' or 'username' depending on fuzzy logic
    # Our profiles have 'id' in SQLi target_fields
    endpoint = {
        "path": "/users/{user_id}",
        "method": "get",
        "parameters": [
            {"name": "user_id", "in": "path", "schema": {"type": "integer"}}
        ],
    }

    attacks = planner.plan_attacks(endpoint)

    # Should find match for user_id (matches 'id' in SQLi profile)
    match = next((a for a in attacks if a["field"] == "user_id"), None)
    assert match is not None
    assert match["profile_name"] == "SQL Injection Test"


def test_plan_attacks_severity_sorting(temp_toys_dir):
    """Test that attacks are sorted by severity."""
    planner = AttackPlanner(endpoints=[], toys_path=temp_toys_dir)
    planner.load_attack_profiles()

    endpoint = {
        "path": "/universal_vuln",
        "method": "post",
        "parameters": [
            {
                "name": "username",
                "in": "query",
                "schema": {"type": "string"},
            },  # Matches SQLi (critical)
            {
                "name": "comment",
                "in": "query",
                "schema": {"type": "string"},
            },  # Matches XSS (high)
        ],
    }

    attacks = planner.plan_attacks(endpoint)
    assert len(attacks) >= 2

    # First should be critical (SQLi)
    assert attacks[0]["severity"] == "critical"
    # Second should be high (XSS)
    assert attacks[1]["severity"] == "high"
