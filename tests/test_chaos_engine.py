"""Tests for the Chaos Engine - negative testing engine."""

import math
import pytest
from chaos_kitten.brain.chaos_engine import (
    ChaosEngine,
    ChaosGenerator,
    ChaosInput,
    AnomalyDetector,
    AnomalyResult,
)


# ─── ChaosInput Tests ───


class TestChaosInput:
    def test_creation(self):
        ci = ChaosInput("age", "integer", None, "Null value")
        assert ci.field_name == "age"
        assert ci.original_type == "integer"
        assert ci.chaos_value is None
        assert ci.description == "Null value"

    def test_to_dict(self):
        ci = ChaosInput("name", "string", "", "Empty string")
        result = ci.to_dict()
        assert result["field_name"] == "name"
        assert result["original_type"] == "string"
        assert result["description"] == "Empty string"


# ─── ChaosGenerator Tests ───


class TestChaosGenerator:
    def test_default_chaos_level(self):
        gen = ChaosGenerator()
        assert gen.chaos_level == 3

    def test_chaos_level_clamping_low(self):
        gen = ChaosGenerator(chaos_level=0)
        assert gen.chaos_level == 1

    def test_chaos_level_clamping_high(self):
        gen = ChaosGenerator(chaos_level=10)
        assert gen.chaos_level == 5

    def test_generate_int_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("age", "integer")
        assert len(inputs) > 0
        assert all(isinstance(i, ChaosInput) for i in inputs)

    def test_generate_float_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("price", "float")
        assert len(inputs) > 0
        descriptions = [i.description for i in inputs]
        # Should contain NaN and infinity inputs
        assert any("NaN" in d or "infinity" in d.lower() for d in descriptions)

    def test_generate_string_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("name", "string")
        assert len(inputs) > 0
        # All inputs should be ChaosInput instances
        assert all(isinstance(i, ChaosInput) for i in inputs)
        # Should have descriptions
        assert all(i.description for i in inputs)

    def test_generate_boolean_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("active", "boolean")
        assert len(inputs) > 0

    def test_generate_array_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("tags", "array")
        assert len(inputs) > 0

    def test_generate_object_chaos(self):
        gen = ChaosGenerator(chaos_level=5)
        inputs = gen.generate_for_field("metadata", "object")
        assert len(inputs) > 0

    def test_generate_unknown_type_falls_back_to_null(self):
        gen = ChaosGenerator(chaos_level=3)
        inputs = gen.generate_for_field("field", "unknown_type")
        assert len(inputs) > 0
        # Should at least have null chaos + type mismatch
        assert any(i.chaos_value is None for i in inputs)

    def test_chaos_level_limits_output(self):
        gen_low = ChaosGenerator(chaos_level=1)
        gen_high = ChaosGenerator(chaos_level=5)
        inputs_low = gen_low.generate_for_field("name", "string")
        inputs_high = gen_high.generate_for_field("name", "string")
        assert len(inputs_low) <= len(inputs_high)

    def test_missing_fields_payload(self):
        gen = ChaosGenerator()
        payloads = gen.generate_missing_fields_payload(
            fields=["name", "email", "age"],
            required_fields=["name", "email"],
        )
        # Should have one per required field + empty + unknown
        assert len(payloads) >= 3
        # First payload should be missing 'name'
        assert "name" not in payloads[0][0]
        assert "email" in payloads[0][0]

    def test_header_chaos(self):
        gen = ChaosGenerator()
        headers = gen.generate_header_chaos()
        assert len(headers) > 0
        # Should include no Content-Type
        assert any(h[1] == "No Content-Type header" for h in headers)


# ─── AnomalyDetector Tests ───


class TestAnomalyDetector:
    def test_set_baseline(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1, 0.15, 0.12, 0.11, 0.13])
        assert detector._baseline_mean > 0
        assert detector._baseline_std > 0

    def test_set_baseline_empty(self):
        detector = AnomalyDetector()
        detector.set_baseline([])
        assert detector._baseline_mean == 1.0
        assert detector._baseline_std == 0.5

    def test_set_baseline_single_value(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.5])
        assert detector._baseline_mean == 0.5
        assert detector._baseline_std == 0.25  # 50% of mean

    def test_detect_server_error(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1, 0.1, 0.1])
        ci = ChaosInput("field", "string", None, "test")
        anomalies = detector.detect_anomalies(
            status_code=500,
            response_time=0.1,
            response_body="Internal Server Error",
            endpoint="/api/test",
            method="POST",
            chaos_input=ci,
        )
        assert len(anomalies) >= 1
        assert anomalies[0].anomaly_type == "server_error"
        assert anomalies[0].severity == "critical"

    def test_detect_502_error(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1])
        ci = ChaosInput("field", "string", None, "test")
        anomalies = detector.detect_anomalies(
            status_code=502,
            response_time=0.1,
            response_body="Bad Gateway",
            endpoint="/api/test",
            method="GET",
            chaos_input=ci,
        )
        assert len(anomalies) >= 1
        assert anomalies[0].severity == "high"

    def test_detect_response_time_outlier(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1, 0.12, 0.09, 0.11, 0.13])
        ci = ChaosInput("field", "string", "A" * 100000, "Very long string")
        anomalies = detector.detect_anomalies(
            status_code=200,
            response_time=15.0,
            response_body="ok",
            endpoint="/api/test",
            method="POST",
            chaos_input=ci,
        )
        assert any(a.anomaly_type == "response_time_outlier" for a in anomalies)

    def test_detect_information_leak(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1])
        ci = ChaosInput("field", "string", None, "test")
        anomalies = detector.detect_anomalies(
            status_code=500,
            response_time=0.1,
            response_body='{"error": "NullReferenceException at line 42, stack trace..."}',
            endpoint="/api/users",
            method="POST",
            chaos_input=ci,
        )
        assert any(a.anomaly_type == "information_leak" for a in anomalies)

    def test_no_anomaly_on_normal_response(self):
        detector = AnomalyDetector()
        detector.set_baseline([0.1, 0.15, 0.12])
        ci = ChaosInput("field", "string", "test", "normal input")
        anomalies = detector.detect_anomalies(
            status_code=400,
            response_time=0.11,
            response_body='{"error": "invalid input"}',
            endpoint="/api/test",
            method="POST",
            chaos_input=ci,
        )
        assert len(anomalies) == 0

    def test_detect_connection_error(self):
        detector = AnomalyDetector()
        ci = ChaosInput("field", "string", "A" * 100000, "Huge payload")
        result = detector.detect_connection_error(
            endpoint="/api/test",
            method="POST",
            chaos_input=ci,
            error_message="Connection refused",
        )
        assert result.anomaly_type == "connection_error"
        assert result.severity == "critical"
        assert result.status_code == 0


# ─── ChaosEngine Tests ───


class TestChaosEngine:
    def test_initialization(self):
        engine = ChaosEngine(chaos_level=2)
        assert engine.chaos_level == 2
        assert engine.generator.chaos_level == 2
        assert len(engine.findings) == 0

    def test_level_clamping(self):
        engine = ChaosEngine(chaos_level=99)
        assert engine.chaos_level == 5

    def test_generate_chaos_payloads(self):
        engine = ChaosEngine(chaos_level=3)
        test_cases = engine.generate_chaos_payloads(
            endpoint="/api/users",
            method="POST",
            fields={"name": "string", "age": "integer"},
            required_fields=["name"],
        )
        assert len(test_cases) > 0
        # Each test case should have payload, headers, description
        for tc in test_cases:
            assert "payload" in tc
            assert "headers" in tc
            assert "description" in tc
            assert "[CHAOS]" in tc["description"]

    def test_generate_payloads_no_fields(self):
        engine = ChaosEngine()
        test_cases = engine.generate_chaos_payloads(
            endpoint="/api/health",
            method="GET",
            fields=None,
        )
        # Should still generate header chaos tests
        assert len(test_cases) > 0

    def test_get_summary_empty(self):
        engine = ChaosEngine()
        summary = engine.get_summary()
        assert summary["total_findings"] == 0
        assert summary["chaos_level"] == 3

    @pytest.mark.asyncio
    async def test_run_chaos_tests(self):
        engine = ChaosEngine(chaos_level=1)
        findings = await engine.run_chaos_tests("http://localhost:5000")
        assert isinstance(findings, list)
        # All findings should be dicts
        for f in findings:
            assert isinstance(f, dict)

    @pytest.mark.asyncio
    async def test_run_chaos_tests_custom_endpoints(self):
        engine = ChaosEngine(chaos_level=1)
        endpoints = [
            {
                "path": "/api/test",
                "method": "POST",
                "fields": {"value": "integer"},
                "required_fields": ["value"],
            }
        ]
        findings = await engine.run_chaos_tests(
            "http://localhost:5000", endpoints=endpoints
        )
        assert isinstance(findings, list)

    def test_get_summary_with_findings(self):
        engine = ChaosEngine()
        ci = ChaosInput("field", "string", None, "test")
        engine.findings.append(
            AnomalyResult(
                anomaly_type="server_error",
                endpoint="/api/test",
                method="POST",
                chaos_input=ci,
                status_code=500,
                response_time=0.1,
                response_body="error",
                severity="critical",
            )
        )
        summary = engine.get_summary()
        assert summary["total_findings"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_type"]["server_error"] == 1


# ─── AnomalyResult Tests ───


class TestAnomalyResult:
    def test_to_dict(self):
        ci = ChaosInput("age", "integer", None, "Null value")
        result = AnomalyResult(
            anomaly_type="server_error",
            endpoint="/api/users",
            method="POST",
            chaos_input=ci,
            status_code=500,
            response_time=0.15,
            response_body="Internal Server Error",
            severity="critical",
        )
        d = result.to_dict()
        assert d["anomaly_type"] == "server_error"
        assert d["endpoint"] == "/api/users"
        assert d["status_code"] == 500
        assert d["severity"] == "critical"
        assert "chaos_input" in d
