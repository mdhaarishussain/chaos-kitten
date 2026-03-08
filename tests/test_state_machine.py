"""Tests for the Multi-Step State Machine Agent."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from chaos_kitten.brain.state_machine import (
    EndpointNode,
    RelationshipMapper,
    StateChain,
    StateMachineAgent,
    _extract_resource,
    _is_parameterised,
    _substitute_params,
)


# ── Helpers ─────────────────────────────────────────────────────────────

CRUD_ENDPOINTS = [
    {"method": "POST", "path": "/api/orders", "parameters": []},
    {"method": "GET", "path": "/api/orders/{id}", "parameters": []},
    {"method": "PUT", "path": "/api/orders/{id}", "parameters": []},
    {"method": "DELETE", "path": "/api/orders/{id}", "parameters": []},
]

NESTED_ENDPOINTS = [
    {"method": "POST", "path": "/api/orders", "parameters": []},
    {"method": "GET", "path": "/api/orders/{order_id}/items/{item_id}", "parameters": []},
    {"method": "DELETE", "path": "/api/orders/{order_id}/items/{item_id}", "parameters": []},
]

TWO_RESOURCE_ENDPOINTS = CRUD_ENDPOINTS + [
    {"method": "POST", "path": "/api/users", "parameters": []},
    {"method": "GET", "path": "/api/users/{id}", "parameters": []},
]


def _mock_executor(status_code=200, body="{}"):
    """Return an executor mock whose ``execute_attack`` always succeeds."""
    executor = AsyncMock()
    executor.execute_attack.return_value = {
        "status_code": status_code,
        "body": body,
        "elapsed_ms": 50,
    }
    return executor


# ── Unit tests: helper functions ───────────────────────────────────────


class TestHelpers:
    def test_extract_resource_simple(self):
        assert _extract_resource("/users") == "users"

    def test_extract_resource_with_prefix(self):
        assert _extract_resource("/api/v1/orders") == "orders"

    def test_extract_resource_with_param(self):
        assert _extract_resource("/api/orders/{id}") == "orders"

    def test_extract_resource_nested(self):
        assert _extract_resource("/api/v2/orders/{id}/items") == "orders"

    def test_extract_resource_empty(self):
        assert _extract_resource("/") is None

    def test_is_parameterised_true(self):
        assert _is_parameterised("/orders/{id}") is True

    def test_is_parameterised_false(self):
        assert _is_parameterised("/orders") is False


# ── Unit tests: _substitute_params ─────────────────────────────────────


class TestSubstituteParams:
    def test_single_param(self):
        result = _substitute_params("/orders/{id}", "42")
        assert result == "/orders/42"

    def test_nested_params_get_unique_ids(self):
        """Each placeholder must receive a distinct value."""
        result = _substitute_params("/orders/{order_id}/items/{item_id}", "42")
        assert result == "/orders/42/items/43"

    def test_three_params(self):
        result = _substitute_params("/a/{x}/b/{y}/c/{z}", "10")
        assert result == "/a/10/b/11/c/12"

    def test_no_params(self):
        result = _substitute_params("/orders", "1")
        assert result == "/orders"

    def test_non_numeric_base_id(self):
        """UUID-style IDs: first param gets the UUID, rest get ints."""
        result = _substitute_params(
            "/orders/{order_id}/items/{item_id}", "abc-uuid"
        )
        assert result == "/orders/abc-uuid/items/1"


# ── Unit tests: EndpointNode ───────────────────────────────────────────


class TestEndpointNode:
    def test_key(self):
        node = EndpointNode(method="post", path="/users")
        assert node.key == "POST /users"


# ── Unit tests: RelationshipMapper ─────────────────────────────────────


class TestRelationshipMapper:
    def test_maps_crud_chain(self):
        mapper = RelationshipMapper()
        chains = mapper.map(CRUD_ENDPOINTS)
        assert len(chains) == 1
        assert chains[0].resource == "orders"
        assert len(chains[0].steps) == 4

    def test_orders_by_crud(self):
        mapper = RelationshipMapper()
        chains = mapper.map(CRUD_ENDPOINTS)
        methods = [s.method for s in chains[0].steps]
        assert methods == ["POST", "GET", "PUT", "DELETE"]

    def test_multiple_resources(self):
        mapper = RelationshipMapper()
        chains = mapper.map(TWO_RESOURCE_ENDPOINTS)
        resources = {c.resource for c in chains}
        assert "orders" in resources
        assert "users" in resources

    def test_skips_single_endpoint_resource(self):
        mapper = RelationshipMapper()
        chains = mapper.map([{"method": "GET", "path": "/health"}])
        assert len(chains) == 0

    def test_chain_step_keys(self):
        mapper = RelationshipMapper()
        chains = mapper.map(CRUD_ENDPOINTS)
        keys = chains[0].step_keys()
        assert keys[0] == "POST /api/orders"
        assert keys[-1] == "DELETE /api/orders/{id}"


# ── Unit tests: StateFinding ──────────────────────────────────────────


class TestStateFinding:
    def test_to_dict(self):
        from chaos_kitten.brain.state_machine import StateFinding
        f = StateFinding(
            finding_type="broken_flow",
            chain_name="orders_crud",
            description="test",
            severity="high",
            evidence="status 200",
            endpoint="DELETE /orders/{id}",
            recommendation="fix it",
        )
        d = f.to_dict()
        assert d["type"] == "broken_flow"
        assert d["severity"] == "high"
        assert "Broken Flow" in d["name"]


# ── Integration tests: StateMachineAgent ──────────────────────────────


class TestStateMachineAgent:
    @pytest.mark.asyncio
    async def test_broken_flow_detected(self):
        """Direct call to DELETE without POST should be flagged."""
        executor = _mock_executor(status_code=200)
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        broken = [f for f in findings if f["type"] == "broken_flow"]
        assert len(broken) >= 1

    @pytest.mark.asyncio
    async def test_broken_flow_not_detected_on_failure(self):
        """If the direct call returns 404, no broken-flow is reported."""
        executor = _mock_executor(status_code=404)
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        broken = [f for f in findings if f["type"] == "broken_flow"]
        assert len(broken) == 0

    @pytest.mark.asyncio
    async def test_broken_flow_idempotent_delete_not_flagged(self):
        """DELETE returning 200 but GET returning 404 is idempotent, not broken flow."""
        call_count = [0]

        async def _side_effect(method, path, payload=None, headers=None):
            call_count[0] += 1
            if method == "DELETE":
                return {"status_code": 200, "body": "{}", "elapsed_ms": 10}
            if method == "GET":
                # Verification GET returns 404 → resource doesn't exist
                return {"status_code": 404, "body": "{}", "elapsed_ms": 10}
            # POST for skip-middle-steps strategy
            return {"status_code": 201, "body": json.dumps({"id": "1"}), "elapsed_ms": 10}

        executor = AsyncMock()
        executor.execute_attack.side_effect = _side_effect
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        broken = [f for f in findings if f["type"] == "broken_flow"]
        # The "high" severity broken_flow for the direct DELETE call
        # should be suppressed because GET returned 404 (idempotent).
        high_broken = [f for f in broken if f["severity"] == "high"]
        assert len(high_broken) == 0

    @pytest.mark.asyncio
    async def test_out_of_order_detected(self):
        """Reverse-order call succeeding should be flagged."""
        executor = _mock_executor(status_code=200)
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        ooo = [f for f in findings if f["type"] == "out_of_order"]
        assert len(ooo) >= 1

    @pytest.mark.asyncio
    async def test_idor_detected(self):
        """Cross-user access succeeding should flag IDOR."""
        body_with_id = json.dumps({"id": "42"})
        executor = _mock_executor(status_code=200, body=body_with_id)
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
            auth_token_b="user_b_token",
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        idor = [f for f in findings if f["type"] == "idor"]
        assert len(idor) >= 1
        assert idor[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_idor_uses_correct_token(self):
        """Verify User B's token is actually sent in the IDOR read request."""
        calls = []

        async def _capture(method, path, payload=None, headers=None):
            calls.append({"method": method, "path": path, "headers": headers})
            if method == "POST":
                return {"status_code": 201, "body": json.dumps({"id": "42"}), "elapsed_ms": 10}
            return {"status_code": 200, "body": "{}", "elapsed_ms": 10}

        executor = AsyncMock()
        executor.execute_attack.side_effect = _capture

        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
            auth_token_b="user_b_token",
        )
        await agent.analyse(CRUD_ENDPOINTS)

        # Find the GET call that used custom headers (the IDOR read)
        get_calls_with_headers = [
            c for c in calls
            if c["method"] == "GET" and c["headers"] is not None
        ]
        assert len(get_calls_with_headers) >= 1
        assert get_calls_with_headers[0]["headers"]["Authorization"] == "Bearer user_b_token"

    @pytest.mark.asyncio
    async def test_idor_skipped_without_token_b(self):
        """IDOR tests should not run without a second auth token."""
        executor = _mock_executor(status_code=200)
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
            auth_token_b=None,
        )
        findings = await agent.analyse(CRUD_ENDPOINTS)
        idor = [f for f in findings if f["type"] == "idor"]
        assert len(idor) == 0

    @pytest.mark.asyncio
    async def test_no_chains_returns_empty(self):
        """Single-endpoint resources produce no chains → no findings."""
        executor = _mock_executor()
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        findings = await agent.analyse([{"method": "GET", "path": "/health"}])
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_executor_returns_empty(self):
        """Without an executor, nothing can be tested."""
        agent = StateMachineAgent(base_url="http://localhost", executor=None)
        findings = await agent.analyse(CRUD_ENDPOINTS)
        # No executor → all _execute calls return None → no findings
        assert all(f["type"] not in ("idor",) for f in findings)

    @pytest.mark.asyncio
    async def test_extract_id_from_response(self):
        body = json.dumps({"id": "abc-123"})
        assert StateMachineAgent._extract_id({"body": body}) == "abc-123"

    @pytest.mark.asyncio
    async def test_extract_id_missing(self):
        assert StateMachineAgent._extract_id({"body": "{}"}) is None


# ── Edge cases ────────────────────────────────────────────────────────


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_executor_raises_exception(self):
        """Agent should handle executor exceptions gracefully."""
        executor = AsyncMock()
        executor.execute_attack.side_effect = Exception("network error")
        agent = StateMachineAgent(
            base_url="http://localhost",
            executor=executor,
        )
        # Should not raise
        findings = await agent.analyse(CRUD_ENDPOINTS)
        assert isinstance(findings, list)

    def test_extract_id_with_dict_body(self):
        resp = {"body": {"id": 99}}
        assert StateMachineAgent._extract_id(resp) == "99"

    def test_extract_id_with_order_id(self):
        body = json.dumps({"order_id": "ORD-001"})
        assert StateMachineAgent._extract_id({"body": body}) == "ORD-001"

    def test_extract_id_camel_case(self):
        """itemId, productId etc. should be detected by the regex."""
        body = json.dumps({"itemId": "ITEM-99"})
        assert StateMachineAgent._extract_id({"body": body}) == "ITEM-99"

    def test_extract_id_snake_case_custom(self):
        """product_id, shipment_id etc. should be detected."""
        body = json.dumps({"shipment_id": "SHIP-001"})
        assert StateMachineAgent._extract_id({"body": body}) == "SHIP-001"
