"""Business Logic Vulnerability Detector module.

This module provides detection and testing for business logic flaws including:
- Race conditions in state transitions
- Workflow bypass attacks
- Authorization flaws
- Price/discount manipulation
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from enum import Enum

logger = logging.getLogger(__name__)


class BusinessLogicAttackType(Enum):
    """Types of business logic attacks."""

    RACE_CONDITION = "race-condition"
    WORKFLOW_BYPASS = "workflow-bypass"
    AUTHORIZATION_BYPASS = "authorization"
    PRICE_MANIPULATION = "payment"


@dataclass
class ConcurrentRequestConfig:
    """Configuration for concurrent request execution."""

    count: int = 5
    delay_ms: int = 0  # Delay between requests in milliseconds
    timeout_seconds: float = 30.0
    expected_behavior: str = ""  # How requests should behave concurrently


@dataclass
class BusinessLogicVulnerability:
    """Represents a detected business logic vulnerability."""

    attack_type: BusinessLogicAttackType
    endpoint: str
    method: str
    vulnerability_name: str
    description: str
    severity: str
    evidence: list[dict[str, Any]]
    remediation: str
    proof_of_concept: str
    timestamp: str = ""

    def __post_init__(self) -> None:
        """Set timestamp if not provided."""
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class BusinessLogicAttacker:
    """Executes business logic attacks and detects vulnerabilities."""

    def __init__(self, executor: Any = None) -> None:
        """Initialize the business logic attacker.

        Args:
            executor: The HTTP executor for making requests
        """
        self.executor = executor
        self.vulnerabilities: list[BusinessLogicVulnerability] = []

    async def test_race_condition(
        self,
        endpoint: dict[str, Any],
        profile: Any,
        concurrent_requests: int = 5,
    ) -> list[BusinessLogicVulnerability]:
        """Test for race condition vulnerabilities.

        Args:
            endpoint: The endpoint to test
            profile: The attack profile with race condition configuration
            concurrent_requests: Number of concurrent requests to make

        Returns:
            List of detected vulnerabilities
        """
        if not self.executor:
            logger.warning("No executor configured for race condition testing")
            return []

        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        vulnerabilities: list[BusinessLogicVulnerability] = []

        try:
            # Get initial state
            initial_response = await self.executor.execute_attack(
                method="GET", path=path, payload=None
            )
            initial_state = initial_response.get("body", "")

            # Log initial state
            logger.debug(f"Initial state for {path}: {initial_state}")

            # Execute concurrent requests
            concurrent_payload = profile.payloads[0] if profile.payloads else "+1"
            tasks = [
                self.executor.execute_attack(
                    method=method,
                    path=path,
                    payload={endpoint.get("target_fields", ["amount"])[0]: concurrent_payload},
                )
                for _ in range(concurrent_requests)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Check for race condition indicators
            final_response = await self.executor.execute_attack(
                method="GET", path=path, payload=None
            )
            final_state = final_response.get("body", "")

            # Analyze results for race conditions
            errors = [r for r in results if isinstance(r, Exception)]
            successful = [r for r in results if not isinstance(r, Exception)]

            # Look for indicators of race conditions
            race_condition_detected = False
            evidence = []

            # Check for unexpected state changes or conflicts
            if initial_state != final_state:
                evidence.append(
                    {
                        "type": "state_change",
                        "initial": initial_state,
                        "final": final_state,
                    }
                )

            # Check for errors indicating conflicts
            if any("conflict" in str(e).lower() for e in errors):
                race_condition_detected = True
                evidence.append({"type": "conflict_error", "count": len(errors)})

            # Check for inconsistent responses
            response_values = [r.get("status_code") for r in successful]
            if len(set(response_values)) > 1:
                race_condition_detected = True
                evidence.append({"type": "inconsistent_responses", "statuses": response_values})

            if race_condition_detected or evidence:
                vulnerability = BusinessLogicVulnerability(
                    attack_type=BusinessLogicAttackType.RACE_CONDITION,
                    endpoint=f"{method} {path}",
                    method=method,
                    vulnerability_name="Race Condition detected",
                    description=f"Concurrent requests ({concurrent_requests}) revealed potential race condition in state management",
                    severity="high",
                    evidence=evidence,
                    remediation="Implement pessimistic or optimistic locking mechanisms for concurrent state modifications",
                    proof_of_concept=f"Execute {concurrent_requests} concurrent {method} requests to {path}",
                )
                vulnerabilities.append(vulnerability)
                logger.info(f"Race condition detected at {path}")

        except Exception as e:
            logger.error(f"Failed to test race condition at {path}: {e}")

        return vulnerabilities

    async def test_workflow_bypass(
        self, endpoint: dict[str, Any], profile: Any
    ) -> list[BusinessLogicVulnerability]:
        """Test for workflow bypass vulnerabilities.

        Args:
            endpoint: The endpoint to test
            profile: The attack profile with workflow configuration

        Returns:
            List of detected vulnerabilities
        """
        if not self.executor:
            logger.warning("No executor configured for workflow bypass testing")
            return []

        path = endpoint.get("path", "")
        method = endpoint.get("method", "POST")
        vulnerabilities: list[BusinessLogicVulnerability] = []

        try:
            # Get all state transitions from profile
            transitions = profile.state_transitions or []

            for transition in transitions:
                steps = transition.get("steps", [])
                if not steps:
                    continue

                # Try to skip initial steps and jump to final state
                first_step = steps[0]
                last_step = steps[-1]

                # Attempt to skip to final step directly
                for payload in profile.payloads:
                    try:
                        target_field = profile.target_fields[0] if profile.target_fields else "status"
                        response = await self.executor.execute_attack(
                            method=method,
                            path=last_step.get("target", path),
                            payload={target_field: payload},
                        )

                        # Check if we successfully bypassed workflow
                        status_code = response.get("status_code", 0)
                        response_body = response.get("body", "")

                        if status_code in [200, 201]:
                            # Workflow bypass successful
                            vulnerability = BusinessLogicVulnerability(
                                attack_type=BusinessLogicAttackType.WORKFLOW_BYPASS,
                                endpoint=f"{method} {path}",
                                method=method,
                                vulnerability_name="Workflow Bypass Detected",
                                description=f"Successfully skipped workflow steps by directly accessing final state with payload: {payload}",
                                severity="high",
                                evidence=[
                                    {
                                        "type": "bypass_success",
                                        "payload": payload,
                                        "status_code": status_code,
                                        "step_skipped": "All previous steps",
                                    }
                                ],
                                remediation="Implement strict state machine validation and require sequential state transitions",
                                proof_of_concept=f"Directly POST {last_step.get('target', path)} with status={payload}",
                            )
                            vulnerabilities.append(vulnerability)
                            logger.info(f"Workflow bypass detected at {path}")

                    except Exception as e:
                        logger.debug(f"Workflow bypass test failed for payload {payload}: {e}")

        except Exception as e:
            logger.error(f"Failed to test workflow bypass at {path}: {e}")

        return vulnerabilities

    async def test_authorization_bypass(
        self, endpoint: dict[str, Any], profile: Any
    ) -> list[BusinessLogicVulnerability]:
        """Test for authorization bypass vulnerabilities.

        Args:
            endpoint: The endpoint to test
            profile: The attack profile with authorization configuration

        Returns:
            List of detected vulnerabilities
        """
        if not self.executor:
            logger.warning("No executor configured for authorization testing")
            return []

        path = endpoint.get("path", "")
        method = endpoint.get("method", "POST")
        vulnerabilities: list[BusinessLogicVulnerability] = []

        try:
            # Test each payload for authorization bypass
            for payload in profile.payloads:
                for field in profile.target_fields:
                    try:
                        response = await self.executor.execute_attack(
                            method=method, path=path, payload={field: payload}
                        )

                        status_code = response.get("status_code", 0)
                        response_body = response.get("body", "")

                        # Check if authorization was bypassed
                        if status_code == 200:
                            # Verify this wasn't supposed to succeed
                            if "admin" in field and "true" in str(payload).lower():
                                vulnerability = BusinessLogicVulnerability(
                                    attack_type=BusinessLogicAttackType.AUTHORIZATION_BYPASS,
                                    endpoint=f"{method} {path}",
                                    method=method,
                                    vulnerability_name="Authorization Bypass Detected",
                                    description=f"Successfully escalated privileges by setting {field}={payload}",
                                    severity="critical",
                                    evidence=[
                                        {
                                            "type": "privilege_escalation",
                                            "field": field,
                                            "payload": payload,
                                            "status_code": status_code,
                                        }
                                    ],
                                    remediation="Verify user authorization server-side for all sensitive operations",
                                    proof_of_concept=f"POST {path} with {field}={payload}",
                                )
                                vulnerabilities.append(vulnerability)
                                logger.warning(f"Authorization bypass detected at {path}")

                    except Exception as e:
                        logger.debug(f"Authorization test failed for {field}: {e}")

        except Exception as e:
            logger.error(f"Failed to test authorization bypass at {path}: {e}")

        return vulnerabilities

    async def test_price_manipulation(
        self, endpoint: dict[str, Any], profile: Any
    ) -> list[BusinessLogicVulnerability]:
        """Test for price manipulation vulnerabilities.

        Args:
            endpoint: The endpoint to test
            profile: The attack profile with pricing configuration

        Returns:
            List of detected vulnerabilities
        """
        if not self.executor:
            logger.warning("No executor configured for price manipulation testing")
            return []

        path = endpoint.get("path", "")
        method = endpoint.get("method", "POST")
        vulnerabilities: list[BusinessLogicVulnerability] = []

        try:
            # Test each payload for price manipulation
            for payload in profile.payloads:
                for field in profile.target_fields:
                    if "price" not in field.lower() and "discount" not in field.lower():
                        continue

                    try:
                        response = await self.executor.execute_attack(
                            method=method, path=path, payload={field: payload}
                        )

                        status_code = response.get("status_code", 0)
                        response_body = response.get("body", "")

                        # Check if price was manipulated (negative or zero)
                        if status_code in [200, 201]:
                            try:
                                body_dict = json.loads(response_body)
                                actual_price = body_dict.get("price", body_dict.get("total", None))

                                if actual_price is not None:
                                    try:
                                        price_val = float(actual_price)
                                        if price_val < 0 or (price_val == 0 and "0" in str(payload)):
                                            vulnerability = BusinessLogicVulnerability(
                                                attack_type=BusinessLogicAttackType.PRICE_MANIPULATION,
                                                endpoint=f"{method} {path}",
                                                method=method,
                                                vulnerability_name="Price Manipulation Detected",
                                                description=f"Price validation bypassed: {field}={payload} resulted in {price_val}",
                                                severity="critical",
                                                evidence=[
                                                    {
                                                        "type": "price_bypass",
                                                        "field": field,
                                                        "payload": payload,
                                                        "resulting_price": price_val,
                                                        "status_code": status_code,
                                                    }
                                                ],
                                                remediation="Always calculate prices server-side and validate them before transaction processing",
                                                proof_of_concept=f"POST {path} with {field}={payload} to bypass price validation",
                                            )
                                            vulnerabilities.append(vulnerability)
                                            logger.warning(f"Price manipulation detected at {path}")
                                    except (ValueError, TypeError):
                                        pass
                            except (json.JSONDecodeError, AttributeError):
                                pass

                    except Exception as e:
                        logger.debug(f"Price manipulation test failed for {field}: {e}")

        except Exception as e:
            logger.error(f"Failed to test price manipulation at {path}: {e}")

        return vulnerabilities

    async def test_endpoint(
        self, endpoint: dict[str, Any], profile: Any
    ) -> list[BusinessLogicVulnerability]:
        """Test an endpoint for business logic vulnerabilities based on profile.

        Args:
            endpoint: The endpoint configuration
            profile: The attack profile to use

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        attack_type = profile.attack_type.lower()

        try:
            if attack_type == "race-condition":
                vulns = await self.test_race_condition(
                    endpoint, profile, profile.concurrent_requests
                )
                vulnerabilities.extend(vulns)
            elif attack_type == "workflow-bypass":
                vulns = await self.test_workflow_bypass(endpoint, profile)
                vulnerabilities.extend(vulns)
            elif attack_type == "authorization":
                vulns = await self.test_authorization_bypass(endpoint, profile)
                vulnerabilities.extend(vulns)
            elif attack_type == "payment":
                vulns = await self.test_price_manipulation(endpoint, profile)
                vulnerabilities.extend(vulns)
        except Exception as e:
            logger.error(f"Error testing endpoint {endpoint.get('path')}: {e}")

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    def get_vulnerabilities(self) -> list[BusinessLogicVulnerability]:
        """Get all detected vulnerabilities.

        Returns:
            List of detected vulnerabilities
        """
        return self.vulnerabilities

    def clear_vulnerabilities(self) -> None:
        """Clear detected vulnerabilities."""
        self.vulnerabilities = []
