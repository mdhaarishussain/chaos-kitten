"""Tests for Natural Language Attack Planning."""

import pytest
from unittest.mock import MagicMock, patch
from chaos_kitten.brain.attack_planner import NaturalLanguagePlanner


@pytest.fixture
def sample_endpoints():
    """Sample API endpoints for testing."""
    return [
        {
            "method": "POST",
            "path": "/api/checkout",
            "parameters": [
                {"name": "user_id", "in": "query", "required": True, "schema": {"type": "integer"}},
                {"name": "cart_id", "in": "query", "required": True, "schema": {"type": "integer"}}
            ],
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "total": {"type": "number"},
                                "items": {"type": "array"}
                            }
                        }
                    }
                }
            }
        },
        {
            "method": "GET",
            "path": "/api/users/{id}",
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
            ],
            "requestBody": None
        },
        {
            "method": "POST",
            "path": "/api/login",
            "parameters": [],
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"},
                                "password": {"type": "string"}
                            }
                        }
                    }
                }
            }
        },
        {
            "method": "PUT",
            "path": "/api/cart/update",
            "parameters": [
                {"name": "cart_id", "in": "query", "required": True, "schema": {"type": "integer"}}
            ],
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "quantity": {"type": "integer"},
                                "price": {"type": "number"}
                            }
                        }
                    }
                }
            }
        }
    ]


@pytest.fixture
def sample_config():
    """Sample configuration."""
    return {
        "agent": {
            "llm_provider": "anthropic",
            "model": "claude-3-5-sonnet-20241022",
            "temperature": 0.7
        }
    }


@patch("chaos_kitten.brain.attack_planner.ChatAnthropic")
def test_natural_language_planner_payment_goal(mock_llm, sample_endpoints, sample_config):
    """Test NL planner identifies payment-related endpoints for price manipulation goal."""
    # Mock LLM response
    mock_llm_instance = MagicMock()
    mock_llm.return_value = mock_llm_instance
    
    # Mock the chain invoke to return a structured response
    mock_response = {
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/checkout",
                "relevance_score": 0.95,
                "reason": "Handles payment processing, critical for price manipulation"
            },
            {
                "method": "PUT",
                "path": "/api/cart/update",
                "relevance_score": 0.85,
                "reason": "Allows updating cart quantities and prices"
            }
        ],
        "profiles": ["idor_basic", "mass_assignment", "bola"],
        "focus": "Test for price/quantity manipulation in cart and checkout flows"
    }
    
    # Create a mock chain that returns the expected response
    with patch.object(
        NaturalLanguagePlanner,
        "_init_llm",
        return_value=mock_llm_instance
    ):
        with patch("chaos_kitten.brain.attack_planner.JsonOutputParser") as mock_parser:
            mock_parser_instance = MagicMock()
            mock_parser.return_value = mock_parser_instance
            
            # Mock the chain to return our response
            with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate") as mock_template:
                mock_template_instance = MagicMock()
                mock_template.from_template.return_value = mock_template_instance
                
                # Mock the chain __or__ operations
                mock_chain = MagicMock()
                mock_chain.invoke.return_value = mock_response
                mock_template_instance.__or__.return_value.__or__.return_value = mock_chain
                
                planner = NaturalLanguagePlanner(sample_endpoints, sample_config)
                result = planner.plan("Test payment endpoints for price manipulation")
                
                # Assertions
                assert "endpoints" in result
                assert "profiles" in result
                assert "focus" in result
                assert len(result["endpoints"]) == 2
                assert result["endpoints"][0]["path"] == "/api/checkout"
                assert "price" in result["focus"].lower() or "payment" in result["focus"].lower()
                assert "idor_basic" in result["profiles"]


@patch("chaos_kitten.brain.attack_planner.ChatAnthropic")
def test_natural_language_planner_fallback(mock_llm, sample_endpoints, sample_config):
    """Test NL planner fallback when LLM fails."""
    mock_llm_instance = MagicMock()
    mock_llm.return_value = mock_llm_instance
    
    # Mock the chain to raise an exception
    with patch.object(
        NaturalLanguagePlanner,
        "_init_llm",
        return_value=mock_llm_instance
    ):
        with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate") as mock_template:
            mock_template_instance = MagicMock()
            mock_template.from_template.return_value = mock_template_instance
            
            # Make the chain raise an exception
            mock_chain = MagicMock()
            mock_chain.invoke.side_effect = Exception("LLM API error")
            mock_template_instance.__or__.return_value.__or__.return_value = mock_chain
            
            planner = NaturalLanguagePlanner(sample_endpoints, sample_config)
            result = planner.plan("Test admin access control")
            
            # Assertions - should fallback gracefully
            assert "endpoints" in result
            assert len(result["endpoints"]) == len(sample_endpoints)  # All endpoints returned
            assert "Fallback" in result["reasoning"]
            assert "reasoning" in result


@patch("chaos_kitten.brain.attack_planner.ChatAnthropic")
def test_natural_language_planner_load_profiles(mock_llm):
    """Test loading available attack profiles."""
    config = {"agent": {"llm_provider": "anthropic"}}
    mock_llm_instance = MagicMock()
    mock_llm.return_value = mock_llm_instance
    
    planner = NaturalLanguagePlanner([], config)
    profiles = planner._load_available_profiles()
    
    # Should return a list of profile names
    assert isinstance(profiles, list)
    assert len(profiles) > 0
    # Common profiles should be in the list (matches actual name: field in YAML)
    assert "SQL Injection - Basic" in profiles or "SSRF" in profiles


@patch("chaos_kitten.brain.attack_planner.ChatAnthropic")
def test_natural_language_planner_auth_goal(mock_llm, sample_endpoints, sample_config):
    """Test NL planner for authentication testing goal."""
    mock_llm_instance = MagicMock()
    mock_llm.return_value = mock_llm_instance
    
    mock_response = {
        "endpoints": [
            {
                "method": "POST",
                "path": "/api/login",
                "relevance_score": 0.98,
                "reason": "Primary authentication endpoint"
            },
            {
                "method": "GET",
                "path": "/api/users/{id}",
                "relevance_score": 0.75,
                "reason": "May require authentication to access"
            }
        ],
        "profiles": ["sql_injection_basic", "auth_bypass", "bola"],
        "focus": "Test authentication bypass and SQL injection in login flow"
    }
    
    with patch.object(
        NaturalLanguagePlanner,
        "_init_llm",
        return_value=mock_llm_instance
    ):
        with patch("chaos_kitten.brain.attack_planner.JsonOutputParser"):
            with patch("chaos_kitten.brain.attack_planner.ChatPromptTemplate") as mock_template:
                mock_template_instance = MagicMock()
                mock_template.from_template.return_value = mock_template_instance
                
                mock_chain = MagicMock()
                mock_chain.invoke.return_value = mock_response
                mock_template_instance.__or__.return_value.__or__.return_value = mock_chain
                
                planner = NaturalLanguagePlanner(sample_endpoints, sample_config)
                result = planner.plan("I want to check if admin endpoints are accessible to regular users")
                
                assert "/api/login" in [ep["path"] for ep in result["endpoints"]]
                assert len(result["profiles"]) > 0
