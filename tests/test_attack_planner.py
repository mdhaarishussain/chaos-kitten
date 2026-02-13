import pytest
import yaml

from chaos_kitten.brain.attack_planner import AttackPlanner


@pytest.fixture
def mock_toys_dir(tmp_path):
    """Creates a temporary directory for attack profiles."""
    d = tmp_path / "toys"
    d.mkdir()
    return d


def test_load_yaml_profiles(mock_toys_dir):
    """1. Load YAML profiles"""
    profile_data = {
        "name": "Test Profile",
        "category": "injection",
        "severity": "high",
        "description": "A test profile",
        "payloads": ["<script>alert(1)</script>"],
        "target_fields": ["input"],
        "success_indicators": {"status_code": 200},
    }
    with open(mock_toys_dir / "test.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()

    assert len(planner.attack_profiles) == 1
    assert planner.attack_profiles[0].name == "Test Profile"


def test_parse_fields(mock_toys_dir):
    """2. Parse fields"""
    profile_data = {
        "name": "Field Test",
        "category": "xss",
        "severity": "medium",
        "description": "Checking fields",
        "payloads": ["payload1"],
        "target_fields": ["field1"],
        "success_indicators": {"key": "value"},
        "remediation": "Fix it",
        "references": ["ref1"],
    }
    with open(mock_toys_dir / "fields.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()

    profile = planner.attack_profiles[0]
    assert profile.name == "Field Test"
    assert profile.category == "xss"
    assert profile.severity == "medium"
    assert profile.description == "Checking fields"
    assert profile.payloads == ["payload1"]
    assert profile.target_fields == ["field1"]
    assert profile.success_indicators == {"key": "value"}
    assert profile.remediation == "Fix it"
    assert profile.references == ["ref1"]


def test_filter_severity(mock_toys_dir):
    """3. Filter severity (actually sorting by severity)"""
    profiles = [
        {"name": "Low", "severity": "low", "target_fields": ["q"]},
        {"name": "Critical", "severity": "critical", "target_fields": ["q"]},
        {"name": "High", "severity": "high", "target_fields": ["q"]},
    ]
    for p in profiles:
        data = {
            "name": p["name"],
            "category": "test",
            "severity": p["severity"],
            "payloads": ["p"],
            "target_fields": p["target_fields"],
            "success_indicators": {},
        }
        with open(mock_toys_dir / f"{p['name']}.yaml", "w") as f:
            yaml.dump(data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    endpoint = {
        "path": "/test",
        "method": "get",
        "parameters": [{"name": "q", "in": "query"}],
    }

    attacks = planner.plan_attacks(endpoint)

    assert len(attacks) == 3
    assert attacks[0]["severity"] == "critical"
    assert attacks[1]["severity"] == "high"
    assert attacks[2]["severity"] == "low"


def test_filter_category(mock_toys_dir):
    """4. Filter category (e.g. body on GET)"""
    profile_data = {
        "name": "Body Attack",
        "category": "injection",
        "severity": "high",
        "payloads": ["p"],
        "target_fields": ["body_param"],
        "success_indicators": {},
    }
    with open(mock_toys_dir / "body.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))

    # Endpoint is GET, but has a "body" param (unlikely but possible in this structure)
    # The code filters: if field_info["location"] == "body" and method == "get": continue
    endpoint = {
        "path": "/test",
        "method": "get",
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"properties": {"body_param": {"type": "string"}}}
                }
            }
        },
    }

    attacks = planner.plan_attacks(endpoint)
    assert len(attacks) == 0


def test_filter_target_field(mock_toys_dir):
    """5. Filter target field (fuzzy matching)"""
    profile_data = {
        "name": "Email Attack",
        "category": "test",
        "severity": "medium",
        "payloads": ["p"],
        "target_fields": ["email"],
        "success_indicators": {},
    }
    with open(mock_toys_dir / "email.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))

    # "user_email" should match "email"
    endpoint = {
        "path": "/test",
        "method": "post",
        "parameters": [{"name": "user_email", "in": "query"}],
    }

    attacks = planner.plan_attacks(endpoint)
    assert len(attacks) == 1
    assert attacks[0]["field"] == "user_email"

    # "username" should NOT match "email"
    endpoint_nomatch = {
        "path": "/test",
        "method": "post",
        "parameters": [{"name": "username", "in": "query"}],
    }
    attacks_nomatch = planner.plan_attacks(endpoint_nomatch)
    assert len(attacks_nomatch) == 0


def test_missing_file(mock_toys_dir):
    """6. Missing file (or no files found)"""
    # Directory is empty
    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()
    assert len(planner.attack_profiles) == 0


def test_invalid_yaml(mock_toys_dir):
    """7. Invalid YAML"""
    with open(mock_toys_dir / "invalid.yaml", "w") as f:
        f.write("invalid: [ yaml: content: {")  # Broken syntax

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    # Should not raise exception, just log error and skip
    planner.load_attack_profiles()
    assert len(planner.attack_profiles) == 0


def test_empty_dir(mock_toys_dir):
    """8. Empty dir"""
    # Same as missing file test really, but specific to requirement
    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()
    assert len(planner.attack_profiles) == 0


def test_required_fields_validation(mock_toys_dir):
    """9. Required fields validation"""
    # Missing 'severity'
    data = {
        "name": "Bad Profile",
        "category": "test",
        # severity missing
        "payloads": ["p"],
        "target_fields": ["f"],
    }
    with open(mock_toys_dir / "bad.yaml", "w") as f:
        yaml.dump(data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()
    assert len(planner.attack_profiles) == 0


def test_random_payload(mock_toys_dir):
    """10. Random payload (verify payloads are present)"""
    payloads = ["p1", "p2", "p3"]
    profile_data = {
        "name": "Payload Test",
        "category": "test",
        "severity": "low",
        "payloads": payloads,
        "target_fields": ["param"],
        "success_indicators": {},
    }
    with open(mock_toys_dir / "payload.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    endpoint = {
        "path": "/test",
        "method": "get",
        "parameters": [{"name": "param", "in": "query"}],
    }

    attacks = planner.plan_attacks(endpoint)
    assert len(attacks) == 1
    # Check that the plan includes the payloads from the profile
    assert attacks[0]["payloads"] == payloads


def test_endpoint_matching(mock_toys_dir):
    """11. Endpoint matching"""
    profile_data = {
        "name": "Match Test",
        "category": "test",
        "severity": "low",
        "payloads": ["p"],
        "target_fields": ["match_me"],
        "success_indicators": {},
    }
    with open(mock_toys_dir / "match.yaml", "w") as f:
        yaml.dump(profile_data, f)

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    endpoint = {
        "path": "/target",
        "method": "get",
        "parameters": [{"name": "match_me", "in": "query"}],
    }

    attacks = planner.plan_attacks(endpoint)
    assert len(attacks) == 1
    assert attacks[0]["endpoint"] == "/target"
    assert attacks[0]["field"] == "match_me"


def test_empty_file(mock_toys_dir):
    """Test loading an empty file."""
    with open(mock_toys_dir / "empty.yaml", "w"):
        pass  # Create empty file

    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    planner.load_attack_profiles()
    assert len(planner.attack_profiles) == 0


def test_reason_about_field(mock_toys_dir):
    """Test reasoning logic (placeholder currently)."""
    planner = AttackPlanner(endpoints=[], toys_path=str(mock_toys_dir))
    reasoning = planner.reason_about_field("age", "integer")
    assert "Standard testing for integer field 'age'" in reasoning
