"""Tests for business logic vulnerability detection framework."""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from chaos_kitten.brain.business_logic_attacker import (
    BusinessLogicAttacker,
    BusinessLogicAttackType,
    BusinessLogicVulnerability,
    ConcurrentRequestConfig,
)


@pytest.fixture
def mock_executor():
    """Create a mock executor for testing."""
    executor = AsyncMock()
    return executor


@pytest.fixture
def business_logic_attacker(mock_executor):
    """Create a BusinessLogicAttacker instance with mock executor."""
    return BusinessLogicAttacker(executor=mock_executor)


@pytest.fixture
def mock_race_condition_profile():
    """Create a mock race condition attack profile."""
    profile = MagicMock()
    profile.attack_type = "race-condition"
    profile.payloads = ["+1", "-1", "+100"]
    profile.target_fields = ["balance", "amount", "count"]
    profile.state_transitions = [
        {
            "name": "debit_then_check",
            "steps": [
                {"action": "POST", "target": "/debit"},
                {"action": "GET", "target": "/balance"},
            ],
        }
    ]
    profile.concurrent_requests = 5
    profile.success_indicators = {"status_codes": [409, 500]}
    return profile


@pytest.fixture
def mock_workflow_profile():
    """Create a mock workflow bypass attack profile."""
    profile = MagicMock()
    profile.attack_type = "workflow-bypass"
    profile.payloads = ["completed", "approved", "final"]
    profile.target_fields = ["status", "step", "workflow_state"]
    profile.state_transitions = [
        {
            "name": "checkout_workflow",
            "steps": [
                {"action": "POST", "target": "/checkout/shipping"},
                {"action": "POST", "target": "/checkout/payment"},
                {"action": "POST", "target": "/checkout/confirm"},
            ],
        }
    ]
    profile.requires_state = True
    profile.success_indicators = {"status_codes": [200, 201]}
    return profile


@pytest.fixture
def mock_auth_profile():
    """Create a mock authorization bypass attack profile."""
    profile = MagicMock()
    profile.attack_type = "authorization"
    profile.payloads = ["admin", "true", "1"]
    profile.target_fields = ["is_admin", "role", "user_type"]
    profile.success_indicators = {"status_codes": [200]}
    return profile


@pytest.fixture
def mock_price_profile():
    """Create a mock price manipulation attack profile."""
    profile = MagicMock()
    profile.attack_type = "payment"
    profile.payloads = ["-100", "0", "-1000"]
    profile.target_fields = ["price", "discount", "total"]
    profile.success_indicators = {"status_codes": [200, 201]}
    return profile


@pytest.fixture
def sample_endpoint():
    """Create a sample endpoint for testing."""
    return {
        "path": "/api/account/balance",
        "method": "POST",
        "target_fields": ["amount"],
    }


class TestBusinessLogicAttackerInit:
    """Test BusinessLogicAttacker initialization."""

    def test_init_with_executor(self, mock_executor):
        """Test initialization with executor."""
        attacker = BusinessLogicAttacker(executor=mock_executor)
        assert attacker.executor == mock_executor
        assert attacker.vulnerabilities == []

    def test_init_without_executor(self):
        """Test initialization without executor."""
        attacker = BusinessLogicAttacker()
        assert attacker.executor is None
        assert attacker.vulnerabilities == []


class TestRaceConditionDetection:
    """Test race condition detection."""

    @pytest.mark.asyncio
    async def test_race_condition_detection_with_state_change(
        self, business_logic_attacker, sample_endpoint, mock_race_condition_profile
    ):
        """Test detection of race condition through state change."""
        # Mock executor responses
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},  # Initial state
            {"body": "101", "status_code": 200},  # Concurrent request 1
            {"body": "102", "status_code": 200},  # Concurrent request 2
            {"body": "103", "status_code": 200},  # Concurrent request 3
            {"body": "104", "status_code": 200},  # Concurrent request 4
            {"body": "105", "status_code": 200},  # Concurrent request 5
            {"body": "107", "status_code": 200},  # Final state (unexpected)
        ]

        vulnerabilities = await business_logic_attacker.test_race_condition(
            sample_endpoint, mock_race_condition_profile, concurrent_requests=5
        )

        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].attack_type == BusinessLogicAttackType.RACE_CONDITION
        assert "race condition" in vulnerabilities[0].description.lower()

    @pytest.mark.asyncio
    async def test_race_condition_no_vulnerability(
        self, business_logic_attacker, sample_endpoint, mock_race_condition_profile
    ):
        """Test when no race condition is detected."""
        # Mock executor responses with consistent behavior
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},  # Initial state
            {"body": "101", "status_code": 200},  # All concurrent requests return same status
            {"body": "101", "status_code": 200},
            {"body": "101", "status_code": 200},
            {"body": "101", "status_code": 200},
            {"body": "101", "status_code": 200},
            {"body": "101", "status_code": 200},  # Final state matches expected
        ]

        vulnerabilities = await business_logic_attacker.test_race_condition(
            sample_endpoint, mock_race_condition_profile, concurrent_requests=5
        )

        # No vulnerability should be detected
        assert len(vulnerabilities) == 0

    @pytest.mark.asyncio
    async def test_race_condition_with_conflict_errors(
        self, business_logic_attacker, sample_endpoint, mock_race_condition_profile
    ):
        """Test race condition detection through conflict errors."""
        # Mock executor to raise conflicts
        error = Exception("409 Conflict")
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},  # Initial state
            error,  # Concurrent request causes conflict
            error,
            error,
            {"body": "100", "status_code": 409},  # Conflict response
            {"body": "100", "status_code": 409},
            {"body": "100", "status_code": 200},  # Final state
        ]

        vulnerabilities = await business_logic_attacker.test_race_condition(
            sample_endpoint, mock_race_condition_profile, concurrent_requests=5
        )

        assert len(vulnerabilities) > 0


class TestWorkflowBypassDetection:
    """Test workflow bypass detection."""

    @pytest.mark.asyncio
    async def test_workflow_bypass_detected(
        self, business_logic_attacker, sample_endpoint, mock_workflow_profile
    ):
        """Test detection of workflow bypass."""
        # Mock endpoint that accepts step skipping
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"status": "completed"}',
            "status_code": 200,
        }

        vulnerabilities = await business_logic_attacker.test_workflow_bypass(
            sample_endpoint, mock_workflow_profile
        )

        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].attack_type == BusinessLogicAttackType.WORKFLOW_BYPASS

    @pytest.mark.asyncio
    async def test_workflow_bypass_blocked(
        self, business_logic_attacker, sample_endpoint, mock_workflow_profile
    ):
        """Test when workflow bypass is properly blocked."""
        # Mock endpoint that rejects step skipping
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"error": "Invalid workflow step"}',
            "status_code": 400,
        }

        vulnerabilities = await business_logic_attacker.test_workflow_bypass(
            sample_endpoint, mock_workflow_profile
        )

        # No vulnerability should be detected
        assert len(vulnerabilities) == 0


class TestAuthorizationBypassDetection:
    """Test authorization bypass detection."""

    @pytest.mark.asyncio
    async def test_authorization_bypass_detected(
        self, business_logic_attacker, sample_endpoint, mock_auth_profile
    ):
        """Test detection of authorization bypass."""
        # Mock endpoint that accepts admin privilege escalation
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"status": "success", "admin": true}',
            "status_code": 200,
        }

        vulnerabilities = await business_logic_attacker.test_authorization_bypass(
            sample_endpoint, mock_auth_profile
        )

        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].attack_type == BusinessLogicAttackType.AUTHORIZATION_BYPASS

    @pytest.mark.asyncio
    async def test_authorization_bypass_blocked(
        self, business_logic_attacker, sample_endpoint, mock_auth_profile
    ):
        """Test when authorization bypass is blocked."""
        # Mock endpoint that rejects privilege escalation
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"error": "Forbidden"}',
            "status_code": 403,
        }

        vulnerabilities = await business_logic_attacker.test_authorization_bypass(
            sample_endpoint, mock_auth_profile
        )

        # No vulnerability should be detected
        assert len(vulnerabilities) == 0


class TestPriceManipulationDetection:
    """Test price manipulation detection."""

    @pytest.mark.asyncio
    async def test_price_manipulation_negative_price(
        self, business_logic_attacker, sample_endpoint, mock_price_profile
    ):
        """Test detection of negative price manipulation."""
        # Mock endpoint that accepts negative price
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"price": -100, "total": -100}',
            "status_code": 200,
        }

        vulnerabilities = await business_logic_attacker.test_price_manipulation(
            sample_endpoint, mock_price_profile
        )

        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].attack_type == BusinessLogicAttackType.PRICE_MANIPULATION

    @pytest.mark.asyncio
    async def test_price_manipulation_zero_price(
        self, business_logic_attacker, sample_endpoint, mock_price_profile
    ):
        """Test detection of zero price manipulation."""
        # Mock endpoint that accepts zero price
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"price": 0, "total": 0}',
            "status_code": 201,
        }

        vulnerabilities = await business_logic_attacker.test_price_manipulation(
            sample_endpoint, mock_price_profile
        )

        assert len(vulnerabilities) > 0
        assert "price validation" in vulnerabilities[0].description.lower()

    @pytest.mark.asyncio
    async def test_price_manipulation_blocked(
        self, business_logic_attacker, sample_endpoint, mock_price_profile
    ):
        """Test when price manipulation is blocked."""
        # Mock endpoint that rejects invalid price
        business_logic_attacker.executor.execute_attack.return_value = {
            "body": '{"error": "Invalid price"}',
            "status_code": 400,
        }

        vulnerabilities = await business_logic_attacker.test_price_manipulation(
            sample_endpoint, mock_price_profile
        )

        # No vulnerability should be detected
        assert len(vulnerabilities) == 0


class TestBusinessLogicVulnerability:
    """Test BusinessLogicVulnerability dataclass."""

    def test_vulnerability_creation(self):
        """Test creating a vulnerability object."""
        vuln = BusinessLogicVulnerability(
            attack_type=BusinessLogicAttackType.RACE_CONDITION,
            endpoint="POST /api/transfer",
            method="POST",
            vulnerability_name="Race Condition",
            description="Concurrent requests cause race condition",
            severity="high",
            evidence=[{"type": "state_change"}],
            remediation="Use locks",
            proof_of_concept="Execute 5 concurrent requests",
        )

        assert vuln.attack_type == BusinessLogicAttackType.RACE_CONDITION
        assert vuln.severity == "high"
        assert len(vuln.evidence) == 1
        assert vuln.timestamp  # Should have timestamp

    def test_vulnerability_with_default_timestamp(self):
        """Test that timestamp is set automatically."""
        vuln = BusinessLogicVulnerability(
            attack_type=BusinessLogicAttackType.WORKFLOW_BYPASS,
            endpoint="POST /checkout",
            method="POST",
            vulnerability_name="Workflow Bypass",
            description="Can skip workflow steps",
            severity="critical",
            evidence=[],
            remediation="Validate state transitions",
            proof_of_concept="POST final step directly",
        )

        assert vuln.timestamp
        assert "T" in vuln.timestamp  # ISO format


class TestConcurrentRequestConfig:
    """Test ConcurrentRequestConfig."""

    def test_default_config(self):
        """Test default concurrent request configuration."""
        config = ConcurrentRequestConfig()
        assert config.count == 5
        assert config.delay_ms == 0
        assert config.timeout_seconds == 30.0

    def test_custom_config(self):
        """Test custom concurrent request configuration."""
        config = ConcurrentRequestConfig(count=10, delay_ms=100, timeout_seconds=60.0)
        assert config.count == 10
        assert config.delay_ms == 100
        assert config.timeout_seconds == 60.0


class TestVulnerabilityStorage:
    """Test vulnerability storage and retrieval."""

    @pytest.mark.asyncio
    async def test_vulnerability_accumulation(
        self, business_logic_attacker, sample_endpoint, mock_race_condition_profile, mock_workflow_profile
    ):
        """Test that vulnerabilities are accumulated."""
        # Setup first test
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "107", "status_code": 200},
        ]

        # Get initial vulnerabilities
        assert len(business_logic_attacker.get_vulnerabilities()) == 0

        # Test race condition
        await business_logic_attacker.test_race_condition(
            sample_endpoint, mock_race_condition_profile, concurrent_requests=5
        )

        # Should have at least 1 vulnerability
        all_vulns = business_logic_attacker.get_vulnerabilities()
        assert len(all_vulns) >= 1

    def test_clear_vulnerabilities(self, business_logic_attacker):
        """Test clearing vulnerabilities."""
        # Add some vulnerabilities
        vuln = BusinessLogicVulnerability(
            attack_type=BusinessLogicAttackType.RACE_CONDITION,
            endpoint="POST /test",
            method="POST",
            vulnerability_name="Test",
            description="Test vulnerability",
            severity="high",
            evidence=[],
            remediation="Test",
            proof_of_concept="Test",
        )
        business_logic_attacker.vulnerabilities.append(vuln)
        assert len(business_logic_attacker.get_vulnerabilities()) == 1

        # Clear
        business_logic_attacker.clear_vulnerabilities()
        assert len(business_logic_attacker.get_vulnerabilities()) == 0


class TestEndpointTesting:
    """Test comprehensive endpoint testing."""

    @pytest.mark.asyncio
    async def test_test_endpoint_race_condition(
        self, business_logic_attacker, sample_endpoint, mock_race_condition_profile
    ):
        """Test endpoint testing with race condition profile."""
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "105", "status_code": 200},
            {"body": "107", "status_code": 200},
        ]

        vulnerabilities = await business_logic_attacker.test_endpoint(
            sample_endpoint, mock_race_condition_profile
        )

        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].attack_type == BusinessLogicAttackType.RACE_CONDITION

    @pytest.mark.asyncio
    async def test_test_endpoint_with_no_executor(self, sample_endpoint, mock_race_condition_profile):
        """Test endpoint testing without executor."""
        attacker = BusinessLogicAttacker(executor=None)

        vulnerabilities = await attacker.test_endpoint(
            sample_endpoint, mock_race_condition_profile
        )

        # Should return empty list when no executor
        assert len(vulnerabilities) == 0


class TestIntegration:
    """Integration tests for business logic framework."""

    @pytest.mark.asyncio
    async def test_multiple_attack_types(self, business_logic_attacker):
        """Test detecting multiple types of vulnerabilities."""
        endpoint = {
            "path": "/api/transaction",
            "method": "POST",
            "target_fields": ["amount", "status"],
        }

        # Create profiles for different attacks
        profiles = []

        # Race condition profile
        rc_profile = MagicMock()
        rc_profile.attack_type = "race-condition"
        rc_profile.payloads = ["+1"]
        rc_profile.target_fields = ["amount"]
        rc_profile.state_transitions = []
        rc_profile.concurrent_requests = 3
        profiles.append(rc_profile)

        # Setup mock responses for race condition
        business_logic_attacker.executor.execute_attack.side_effect = [
            {"body": "100", "status_code": 200},  # initial
            {"body": "101", "status_code": 200},  # req 1
            {"body": "102", "status_code": 200},  # req 2
            {"body": "103", "status_code": 200},  # req 3
            {"body": "105", "status_code": 200},  # final (unexpected)
        ]

        # Test with race condition profile
        vulns = await business_logic_attacker.test_endpoint(endpoint, rc_profile)

        # Should detect race condition
        assert any(v.attack_type == BusinessLogicAttackType.RACE_CONDITION for v in vulns)
