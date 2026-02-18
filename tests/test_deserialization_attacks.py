"""Tests for deserialization attack detection and payload generation."""

import pytest
from unittest.mock import MagicMock, patch
from chaos_kitten.brain.attack_planner import AttackPlanner, AttackProfile


@pytest.fixture
def base_url():
    return "http://api.example.com"


@pytest.fixture
def planner():
    """Create an AttackPlanner with loaded profiles and mocked LLM."""
    endpoints = []
    with patch("chaos_kitten.brain.attack_planner.ChatAnthropic"):
        planner = AttackPlanner(
            endpoints=endpoints,
            toys_path="toys/",
            llm_provider="anthropic",
            temperature=0.7
        )
        planner.llm = MagicMock()
    return planner


# --- Java Deserialization Detection Tests ---


def test_java_deserialization_detection_via_path(planner):
    """Test Java deserialization detection via path keywords."""
    endpoint = {
        "path": "/api/java/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_java_deserialization_detection_via_spring_path(planner):
    """Test Java deserialization detection via Spring framework path."""
    endpoint = {
        "path": "/spring-boot/api/deserialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "object": {"type": "object"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_java_deserialization_detection_via_jackson_path(planner):
    """Test Java deserialization detection via Jackson path."""
    endpoint = {
        "path": "/api/jackson/parse",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "json": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_java_deserialization_detection_via_content_type(planner):
    """Test Java deserialization detection via Content-Type header."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-java-serialized-object": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_java_deserialization_detection_via_serialized_field(planner):
    """Test Java deserialization detection via serialized field name."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "serialized": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_java_deserialization_not_detected_for_get(planner):
    """Test that GET requests are not flagged as deserialization endpoints."""
    endpoint = {
        "path": "/api/java/process",
        "method": "GET",
        "parameters": [],
        "requestBody": {}
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is False


# --- Python Deserialization Detection Tests ---


def test_python_deserialization_detection_via_path(planner):
    """Test Python deserialization detection via path keywords."""
    endpoint = {
        "path": "/api/python/pickle",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_python_deserialization_detection_via_django_path(planner):
    """Test Python deserialization detection via Django path."""
    endpoint = {
        "path": "/django/api/load",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "pickle": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_python_deserialization_detection_via_flask_path(planner):
    """Test Python deserialization detection via Flask path."""
    endpoint = {
        "path": "/flask/api/session",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "session": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_python_deserialization_detection_via_yaml_content_type(planner):
    """Test Python deserialization detection via YAML Content-Type."""
    endpoint = {
        "path": "/api/config",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-yaml": {
                    "schema": {
                        "properties": {
                            "config": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_python_deserialization_detection_via_pickle_content_type(planner):
    """Test Python deserialization detection via pickle Content-Type."""
    endpoint = {
        "path": "/api/load",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-python-pickle": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_python_deserialization_detection_via_pickle_field(planner):
    """Test Python deserialization detection via pickle field name."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "pickle": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


# --- PHP Deserialization Detection Tests ---


def test_php_deserialization_detection_via_path(planner):
    """Test PHP deserialization detection via path keywords."""
    endpoint = {
        "path": "/api/php/unserialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_laravel_path(planner):
    """Test PHP deserialization detection via Laravel path."""
    endpoint = {
        "path": "/laravel/api/session",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "session": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_symfony_path(planner):
    """Test PHP deserialization detection via Symfony path."""
    endpoint = {
        "path": "/symfony/api/cache",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "cache": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_wordpress_path(planner):
    """Test PHP deserialization detection via WordPress path."""
    endpoint = {
        "path": "/wordpress/wp-admin/options",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "options": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_php_content_type(planner):
    """Test PHP deserialization detection via PHP Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-php-serialize": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_session_field(planner):
    """Test PHP deserialization detection via session field name."""
    endpoint = {
        "path": "/api/auth",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "session": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_php_deserialization_detection_via_phar_field(planner):
    """Test PHP deserialization detection via phar field name."""
    endpoint = {
        "path": "/api/upload",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "phar": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


# --- Content-Type Header Analysis Tests ---


def test_content_type_detection_java_serialized_object(planner):
    """Test detection of Java serialized object Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-java-serialized-object": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_python_pickle(planner):
    """Test detection of Python pickle Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-python-pickle": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_php_serialize(planner):
    """Test detection of PHP serialize Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-php-serialize": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_kryo(planner):
    """Test detection of Kryo Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-kryo": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_hessian(planner):
    """Test detection of Hessian Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-hessian": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_avro(planner):
    """Test detection of Avro Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-avro": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_content_type_detection_protobuf(planner):
    """Test detection of Protocol Buffers Content-Type."""
    endpoint = {
        "path": "/api/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-protobuf": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_no_deserialization_for_regular_json(planner):
    """Test that regular JSON endpoints are not flagged as deserialization."""
    endpoint = {
        "path": "/api/users",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "name": {"type": "string"},
                            "email": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is False


def test_no_deserialization_for_form_data(planner):
    """Test that form-data endpoints are not flagged as deserialization."""
    endpoint = {
        "path": "/api/submit",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-www-form-urlencoded": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is False


# --- Language Detection Tests ---


def test_detect_deserialization_languages_java(planner):
    """Test detection of Java language from endpoint characteristics."""
    endpoint = {
        "path": "/api/java/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-java-serialized-object": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    languages = planner._detect_deserialization_languages(endpoint)
    assert "Java" in languages


def test_detect_deserialization_languages_python(planner):
    """Test detection of Python language from endpoint characteristics."""
    endpoint = {
        "path": "/api/python/pickle",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-python-pickle": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    languages = planner._detect_deserialization_languages(endpoint)
    assert "Python" in languages


def test_detect_deserialization_languages_php(planner):
    """Test detection of PHP language from endpoint characteristics."""
    endpoint = {
        "path": "/api/php/unserialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/x-php-serialize": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    languages = planner._detect_deserialization_languages(endpoint)
    assert "PHP" in languages


def test_detect_deserialization_languages_multiple(planner):
    """Test detection of multiple languages from endpoint characteristics."""
    endpoint = {
        "path": "/api/multi/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {"properties": {}}
                }
            }
        }
    }
    
    languages = planner._detect_deserialization_languages(endpoint)
    # When no specific language is detected, all should be returned
    assert "Java" in languages
    assert "Python" in languages
    assert "PHP" in languages


# --- Gadget Chain Payload Generation Tests ---


def test_select_deserialization_payloads_java(planner):
    """Test payload selection for Java deserialization."""
    # Get Java deserialization profile
    java_profile = next(
        (p for p in planner.attack_profiles if "Java" in p.name),
        None
    )
    
    assert java_profile is not None, "Java deserialization profile should be loaded"
    payloads = planner._select_deserialization_payloads("Java", java_profile.payloads)
    assert len(payloads) > 0, "Should select some Java payloads"
    # Check for Java-specific payload patterns
    assert any("rO0AB" in p for p in payloads), "Should contain base64 Java serialized objects"


def test_select_deserialization_payloads_python(planner):
    """Test payload selection for Python deserialization."""
    # Get Python deserialization profile
    python_profile = next(
        (p for p in planner.attack_profiles if "Python" in p.name),
        None
    )
    
    assert python_profile is not None, "Python deserialization profile should be loaded"
    payloads = planner._select_deserialization_payloads("Python", python_profile.payloads)
    assert len(payloads) > 0, "Should select some Python payloads"
    # Check for Python-specific payload patterns
    assert any("pickle" in p.lower() or "!!python" in p for p in payloads), "Should contain Python-specific patterns"


def test_select_deserialization_payloads_php(planner):
    """Test payload selection for PHP deserialization."""
    # Get PHP deserialization profile
    php_profile = next(
        (p for p in planner.attack_profiles if "PHP" in p.name),
        None
    )
    
    assert php_profile is not None, "PHP deserialization profile should be loaded"
    payloads = planner._select_deserialization_payloads("PHP", php_profile.payloads)
    assert len(payloads) > 0, "Should select some PHP payloads"
    # Check for PHP-specific payload patterns
    assert any("O:" in p or "s:" in p for p in payloads), "Should contain PHP serialized format"


def test_plan_deserialization_attacks_java(planner):
    """Test planning of Java deserialization attacks."""
    endpoint = {
        "path": "/api/java/process",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner._plan_deserialization_attacks(endpoint)
    
    # Should generate attacks
    assert len(attacks) > 0
    
    # Check attack structure
    for attack in attacks:
        assert attack["type"] == "deserialization"
        assert "Java" in attack.get("target_language", "") or "deserialization" in attack.get("attack_subtype", "")
        assert attack["severity"] == "critical"
        assert attack["priority"] == "critical"


def test_plan_deserialization_attacks_python(planner):
    """Test planning of Python deserialization attacks."""
    endpoint = {
        "path": "/api/python/pickle",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "pickle": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner._plan_deserialization_attacks(endpoint)
    
    # Should generate attacks
    assert len(attacks) > 0
    
    # Check attack structure
    for attack in attacks:
        assert attack["type"] == "deserialization"
        assert "Python" in attack.get("target_language", "") or "deserialization" in attack.get("attack_subtype", "")
        assert attack["severity"] == "critical"


def test_plan_deserialization_attacks_php(planner):
    """Test planning of PHP deserialization attacks."""
    endpoint = {
        "path": "/api/php/unserialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner._plan_deserialization_attacks(endpoint)
    
    # Should generate attacks
    assert len(attacks) > 0
    
    # Check attack structure
    for attack in attacks:
        assert attack["type"] == "deserialization"
        assert "PHP" in attack.get("target_language", "") or "deserialization" in attack.get("attack_subtype", "")
        assert attack["severity"] == "critical"


def test_plan_deserialization_attacks_no_profiles(planner):
    """Test that no attacks are planned when no deserialization profiles exist."""
    # Temporarily clear profiles
    original_profiles = planner.attack_profiles
    planner.attack_profiles = []
    
    endpoint = {
        "path": "/api/test",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner._plan_deserialization_attacks(endpoint)
    
    # Should return empty list
    assert len(attacks) == 0
    
    # Restore profiles
    planner.attack_profiles = original_profiles


# --- Success Indicator Matching Tests ---


def test_java_success_indicators(planner):
    """Test Java deserialization success indicator patterns."""
    java_profile = next(
        (p for p in planner.attack_profiles if "Java" in p.name),
        None
    )
    
    if java_profile:
        indicators = java_profile.success_indicators
        assert "response_contains" in indicators
        # Check for Java-specific error patterns
        java_patterns = indicators["response_contains"]
        assert any("java.io" in p for p in java_patterns)
        assert any("ClassNotFoundException" in p for p in java_patterns)


def test_python_success_indicators(planner):
    """Test Python deserialization success indicator patterns."""
    python_profile = next(
        (p for p in planner.attack_profiles if "Python" in p.name),
        None
    )
    
    if python_profile:
        indicators = python_profile.success_indicators
        assert "response_contains" in indicators
        # Check for Python-specific error patterns
        python_patterns = indicators["response_contains"]
        assert any("pickle" in p.lower() for p in python_patterns)
        assert any("UnpicklingError" in p for p in python_patterns)


def test_php_success_indicators(planner):
    """Test PHP deserialization success indicator patterns."""
    php_profile = next(
        (p for p in planner.attack_profiles if "PHP" in p.name),
        None
    )
    
    if php_profile:
        indicators = php_profile.success_indicators
        assert "response_contains" in indicators
        # Check for PHP-specific error patterns
        php_patterns = indicators["response_contains"]
        assert any("unserialize" in p.lower() for p in php_patterns)
        assert any("serialized" in p.lower() for p in php_patterns)


def test_status_code_indicators(planner):
    """Test status code success indicators for deserialization."""
    for profile in planner.attack_profiles:
        if profile.category == "deserialization":
            indicators = profile.success_indicators
            if "status_codes" in indicators:
                # Should typically return 500 for deserialization errors
                assert 500 in indicators["status_codes"]


# --- Field Matching Tests ---


def test_field_matching_for_deserialization(planner):
    """Test field matching for deserialization target fields."""
    # Test various field names that should match deserialization profiles
    test_fields = [
        ("data", True),
        ("object", True),
        ("serialized", True),
        ("pickle", True),
        ("json", True),
        ("yaml", True),
        ("xml", True),
        ("body", True),
        ("content", True),
        ("payload", True),
        ("session", True),
        ("cache", True),
        ("name", False),
        ("email", False),
        ("password", False),
    ]
    
    for field_name, should_match in test_fields:
        matches = any(
            planner._field_matches_target(field_name, target)
            for target in ["data", "object", "serialized", "pickle", "json", 
                          "yaml", "body", "content", "payload", "session", "cache"]
        )
        assert matches == should_match, f"Field '{field_name}' matching failed"


# --- Integration Tests ---


def test_plan_attacks_includes_deserialization(planner):
    """Test that plan_attacks includes deserialization attacks for vulnerable endpoints."""
    endpoint = {
        "path": "/api/java/deserialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner.plan_attacks(endpoint)
    
    # Should have deserialization attacks
    has_deserialization = any(
        attack.get("type") == "deserialization" 
        for attack in attacks
    )
    assert has_deserialization is True


def test_plan_attacks_excludes_deserialization_for_safe_endpoints(planner):
    """Test that plan_attacks excludes deserialization for safe endpoints."""
    endpoint = {
        "path": "/api/users",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "name": {"type": "string"},
                            "email": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    attacks = planner.plan_attacks(endpoint)
    
    # Should not have deserialization attacks
    has_deserialization = any(
        attack.get("type") == "deserialization" 
        for attack in attacks
    )
    assert has_deserialization is False, "Safe endpoints should not have deserialization attacks"


# --- Attack Profile Loading Tests ---


def test_deserialization_profiles_loaded(planner):
    """Test that deserialization profiles are loaded."""
    deserialization_profiles = [
        p for p in planner.attack_profiles 
        if p.category == "deserialization"
    ]
    
    # Should have at least 3 profiles (Java, Python, PHP)
    assert len(deserialization_profiles) >= 3


def test_deserialization_profile_structure(planner):
    """Test that deserialization profiles have correct structure."""
    for profile in planner.attack_profiles:
        if profile.category == "deserialization":
            # Check required fields
            assert profile.name is not None
            assert profile.category == "deserialization"
            assert profile.severity in ["critical", "high", "medium", "low"]
            assert len(profile.payloads) > 0
            assert len(profile.target_fields) > 0
            assert isinstance(profile.success_indicators, dict)


# --- Error Handling Tests ---


def test_plan_deserialization_with_invalid_endpoint(planner):
    """Test planning deserialization attacks with invalid endpoint."""
    attacks = planner._plan_deserialization_attacks({})
    
    # Should handle gracefully and return empty or fallback attacks
    assert isinstance(attacks, list)


def test_is_deserialization_endpoint_with_empty_request_body(planner):
    """Test detection with empty request body."""
    endpoint = {
        "path": "/api/test",
        "method": "POST",
        "parameters": [],
        "requestBody": {}
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    # Should return False for non-deserialization path
    assert result is False


def test_is_deserialization_endpoint_with_missing_content(planner):
    """Test detection with missing content in request body."""
    endpoint = {
        "path": "/api/test",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {}
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    # Should return False for non-deserialization path
    assert result is False


# --- Edge Cases ---


def test_multiple_content_types(planner):
    """Test detection when endpoint has multiple content types."""
    endpoint = {
        "path": "/api/serialize",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {"schema": {"properties": {}}},
                "application/x-java-serialized-object": {"schema": {"properties": {}}}
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_case_insensitive_path_matching(planner):
    """Test that path matching is case insensitive."""
    endpoint = {
        "path": "/API/JAVA/DESERIALIZE",
        "method": "POST",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "data": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_put_method_deserialization(planner):
    """Test that PUT method can be flagged as deserialization."""
    endpoint = {
        "path": "/api/java/object",
        "method": "PUT",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "object": {"type": "object"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


def test_patch_method_deserialization(planner):
    """Test that PATCH method can be flagged as deserialization."""
    endpoint = {
        "path": "/api/python/update",
        "method": "PATCH",
        "parameters": [],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "pickle": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
    
    result = planner._is_deserialization_endpoint(endpoint)
    assert result is True


# --- JSON Payload Tests for Deserialization ---


def test_jackson_json_payloads(planner):
    """Test that Jackson JSON deserialization payloads are included."""
    java_profile = next(
        (p for p in planner.attack_profiles if "Java" in p.name),
        None
    )
    
    if java_profile:
        payloads_str = " ".join(java_profile.payloads)
        # Should have Jackson-specific payloads
        assert "@class" in payloads_str or "@type" in payloads_str


def test_yaml_payloads(planner):
    """Test that YAML deserialization payloads are included."""
    python_profile = next(
        (p for p in planner.attack_profiles if "Python" in p.name),
        None
    )
    
    if python_profile:
        payloads_str = " ".join(python_profile.payloads)
        # Should have YAML-specific payloads
        assert "!!python" in payloads_str


def test_php_pop_chain_payloads(planner):
    """Test that PHP POP chain payloads are included."""
    php_profile = next(
        (p for p in planner.attack_profiles if "PHP" in p.name),
        None
    )
    
    if php_profile:
        payloads_str = " ".join(php_profile.payloads)
        # Should have Laravel or Symfony POP chain payloads
        assert "Illuminate" in payloads_str or "Symfony" in payloads_str or "O:" in payloads_str
