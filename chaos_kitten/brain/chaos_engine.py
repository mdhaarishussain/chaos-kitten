"""Chaos Engine - Negative testing engine for discovering unknown vulnerabilities.

Chaos Mode goes beyond known attack signatures by randomly generating
structurally invalid inputs: wrong types, boundary extremes, null bytes,
Unicode edge cases, and missing required fields to discover undocumented
crashes, 500 errors, and hidden behaviors.
"""

import random
import string
import time
import math
from typing import Any, Dict, List, Optional, Tuple


class ChaosInput:
    """Represents a single chaos test input with metadata."""

    def __init__(
        self,
        field_name: str,
        original_type: str,
        chaos_value: Any,
        description: str,
    ) -> None:
        self.field_name = field_name
        self.original_type = original_type
        self.chaos_value = chaos_value
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "original_type": self.original_type,
            "chaos_value": repr(self.chaos_value),
            "description": self.description,
        }


class AnomalyResult:
    """Represents an anomaly detected during chaos testing."""

    def __init__(
        self,
        anomaly_type: str,
        endpoint: str,
        method: str,
        chaos_input: ChaosInput,
        status_code: int,
        response_time: float,
        response_body: str,
        severity: str = "medium",
    ) -> None:
        self.anomaly_type = anomaly_type
        self.endpoint = endpoint
        self.method = method
        self.chaos_input = chaos_input
        self.status_code = status_code
        self.response_time = response_time
        self.response_body = response_body
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "chaos_input": self.chaos_input.to_dict(),
            "status_code": self.status_code,
            "response_time": self.response_time,
            "response_body_preview": self.response_body[:500],
            "severity": self.severity,
        }


class ChaosGenerator:
    """Type-aware random input generator for chaos testing.

    Generates structurally invalid and edge-case inputs based on field types
    to discover undocumented crashes and hidden behaviors.
    """

    # Chaos level determines how many mutations are generated per field
    MUTATIONS_PER_LEVEL = {1: 2, 2: 4, 3: 6, 4: 8, 5: 12}

    def __init__(self, chaos_level: int = 3) -> None:
        """Initialize the chaos generator.

        Args:
            chaos_level: Intensity from 1 (gentle) to 5 (maximum carnage).
        """
        self.chaos_level = max(1, min(5, chaos_level))

    def generate_for_field(
        self, field_name: str, field_type: str
    ) -> List[ChaosInput]:
        """Generate chaos inputs for a given field based on its type.

        Args:
            field_name: Name of the API field.
            field_type: Expected type (int, float, string, boolean, array, object, null).

        Returns:
            List of ChaosInput objects with mutated values.
        """
        generators = {
            "integer": self._generate_int_chaos,
            "int": self._generate_int_chaos,
            "number": self._generate_float_chaos,
            "float": self._generate_float_chaos,
            "string": self._generate_string_chaos,
            "boolean": self._generate_boolean_chaos,
            "bool": self._generate_boolean_chaos,
            "array": self._generate_array_chaos,
            "object": self._generate_object_chaos,
        }

        generator_fn = generators.get(field_type.lower(), self._generate_null_chaos)
        all_inputs = generator_fn(field_name)

        # Always include null/None and type-mismatch inputs
        all_inputs.extend(self._generate_null_chaos(field_name))
        all_inputs.extend(self._generate_type_mismatch(field_name, field_type))

        # Limit based on chaos level
        max_mutations = self.MUTATIONS_PER_LEVEL.get(self.chaos_level, 6)
        if len(all_inputs) > max_mutations:
            random.shuffle(all_inputs)
            all_inputs = all_inputs[:max_mutations]

        return all_inputs

    def _generate_int_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic integer inputs."""
        inputs = [
            ChaosInput(field_name, "integer", 0, "Zero value"),
            ChaosInput(field_name, "integer", -1, "Negative one"),
            ChaosInput(field_name, "integer", -2147483648, "Int32 minimum"),
            ChaosInput(field_name, "integer", 2147483647, "Int32 maximum"),
            ChaosInput(field_name, "integer", 9999999999999999, "Very large integer"),
            ChaosInput(field_name, "integer", -9999999999999999, "Very large negative integer"),
            ChaosInput(field_name, "integer", float("nan"), "NaN as integer"),
            ChaosInput(field_name, "integer", float("inf"), "Infinity as integer"),
            ChaosInput(field_name, "integer", float("-inf"), "Negative infinity"),
            ChaosInput(field_name, "integer", 1e308, "Float overflow boundary"),
            ChaosInput(field_name, "integer", "0", "Zero as string"),
            ChaosInput(field_name, "integer", "", "Empty string instead of int"),
        ]
        return inputs

    def _generate_float_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic float inputs."""
        inputs = [
            ChaosInput(field_name, "float", 0.0, "Zero float"),
            ChaosInput(field_name, "float", -0.0, "Negative zero"),
            ChaosInput(field_name, "float", 1e-308, "Smallest positive float"),
            ChaosInput(field_name, "float", 1e308, "Float overflow boundary"),
            ChaosInput(field_name, "float", -1e308, "Negative float overflow"),
            ChaosInput(field_name, "float", float("nan"), "NaN"),
            ChaosInput(field_name, "float", float("inf"), "Positive infinity"),
            ChaosInput(field_name, "float", float("-inf"), "Negative infinity"),
            ChaosInput(field_name, "float", 0.1 + 0.2, "Floating point precision (0.3)"),
            ChaosInput(field_name, "float", 1e-45, "Denormalized float"),
            ChaosInput(field_name, "float", "NaN", "NaN as string"),
            ChaosInput(field_name, "float", "", "Empty string instead of float"),
        ]
        return inputs

    def _generate_string_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic string inputs."""
        inputs = [
            ChaosInput(field_name, "string", "", "Empty string"),
            ChaosInput(field_name, "string", " ", "Single space"),
            ChaosInput(field_name, "string", "   \t\n\r  ", "Whitespace characters"),
            ChaosInput(field_name, "string", "\x00", "Null byte"),
            ChaosInput(field_name, "string", "\x00\x01\x02\x03", "Control characters"),
            ChaosInput(field_name, "string", "A" * 10000, "Very long string (10K)"),
            ChaosInput(field_name, "string", "A" * 100000, "Extremely long string (100K)"),
            ChaosInput(
                field_name, "string",
                "\u202e\u200b\u200c\u200d\ufeff",
                "Unicode direction overrides and zero-width chars",
            ),
            ChaosInput(
                field_name, "string",
                "\ud800",
                "Unpaired surrogate (invalid UTF-16)",
            ),
            ChaosInput(field_name, "string", "🐱" * 1000, "Emoji flood"),
            ChaosInput(
                field_name, "string",
                "".join(chr(i) for i in range(0, 32)),
                "All ASCII control characters",
            ),
            ChaosInput(
                field_name, "string",
                "%00%0a%0d%25",
                "URL-encoded special characters",
            ),
            ChaosInput(
                field_name, "string",
                "$(cat /etc/passwd)",
                "Command injection attempt",
            ),
            ChaosInput(
                field_name, "string",
                "{{7*7}}",
                "Template injection (SSTI)",
            ),
        ]
        return inputs

    def _generate_boolean_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic boolean inputs."""
        inputs = [
            ChaosInput(field_name, "boolean", "true", "String true"),
            ChaosInput(field_name, "boolean", "false", "String false"),
            ChaosInput(field_name, "boolean", 1, "Integer 1 as boolean"),
            ChaosInput(field_name, "boolean", 0, "Integer 0 as boolean"),
            ChaosInput(field_name, "boolean", "yes", "String yes"),
            ChaosInput(field_name, "boolean", "", "Empty string as boolean"),
            ChaosInput(field_name, "boolean", "null", "String null"),
            ChaosInput(field_name, "boolean", 2, "Integer 2 (truthy but not true)"),
        ]
        return inputs

    def _generate_array_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic array inputs."""
        inputs = [
            ChaosInput(field_name, "array", [], "Empty array"),
            ChaosInput(field_name, "array", [None], "Array with null"),
            ChaosInput(field_name, "array", [None, None, None], "Array of nulls"),
            ChaosInput(
                field_name, "array",
                list(range(10000)),
                "Very large array (10K elements)",
            ),
            ChaosInput(
                field_name, "array",
                [[[[[[[[[[1]]]]]]]]]],
                "Deeply nested array (10 levels)",
            ),
            ChaosInput(field_name, "array", "not_an_array", "String instead of array"),
            ChaosInput(field_name, "array", [1, "two", True, None, 3.14], "Mixed type array"),
            ChaosInput(field_name, "array", [-1], "Array with negative index value"),
        ]
        return inputs

    def _generate_object_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate chaotic object inputs."""
        inputs = [
            ChaosInput(field_name, "object", {}, "Empty object"),
            ChaosInput(field_name, "object", {"": ""}, "Empty key-value pair"),
            ChaosInput(
                field_name, "object",
                {"__proto__": {"isAdmin": True}},
                "Prototype pollution attempt",
            ),
            ChaosInput(
                field_name, "object",
                {"constructor": {"prototype": {"isAdmin": True}}},
                "Constructor prototype pollution",
            ),
            ChaosInput(
                field_name, "object",
                {str(i): i for i in range(1000)},
                "Object with 1000 keys",
            ),
            ChaosInput(field_name, "object", "not_an_object", "String instead of object"),
            ChaosInput(field_name, "object", [1, 2, 3], "Array instead of object"),
            ChaosInput(
                field_name, "object",
                {"\x00key": "value"},
                "Null byte in key name",
            ),
        ]
        return inputs

    def _generate_null_chaos(self, field_name: str) -> List[ChaosInput]:
        """Generate null/missing value inputs."""
        inputs = [
            ChaosInput(field_name, "null", None, "Null value"),
            ChaosInput(field_name, "null", "null", "String null"),
            ChaosInput(field_name, "null", "undefined", "String undefined"),
        ]
        return inputs

    def _generate_type_mismatch(
        self, field_name: str, original_type: str
    ) -> List[ChaosInput]:
        """Generate inputs of a completely wrong type."""
        mismatches = {
            "integer": [
                ChaosInput(field_name, "integer", "not_a_number", "String instead of int"),
                ChaosInput(field_name, "integer", [1, 2, 3], "Array instead of int"),
                ChaosInput(field_name, "integer", {"value": 42}, "Object instead of int"),
            ],
            "float": [
                ChaosInput(field_name, "float", "not_a_float", "String instead of float"),
                ChaosInput(field_name, "float", True, "Boolean instead of float"),
            ],
            "string": [
                ChaosInput(field_name, "string", 12345, "Integer instead of string"),
                ChaosInput(field_name, "string", True, "Boolean instead of string"),
                ChaosInput(field_name, "string", [1, 2], "Array instead of string"),
            ],
            "boolean": [
                ChaosInput(field_name, "boolean", "maybe", "Invalid boolean string"),
                ChaosInput(field_name, "boolean", [True], "Array instead of boolean"),
            ],
            "array": [
                ChaosInput(field_name, "array", 42, "Integer instead of array"),
                ChaosInput(field_name, "array", True, "Boolean instead of array"),
            ],
            "object": [
                ChaosInput(field_name, "object", 42, "Integer instead of object"),
                ChaosInput(field_name, "object", True, "Boolean instead of object"),
            ],
        }
        return mismatches.get(original_type.lower(), [])

    def generate_missing_fields_payload(
        self, fields: List[str], required_fields: List[str]
    ) -> List[Tuple[Dict[str, Any], str]]:
        """Generate payloads with missing required fields.

        Args:
            fields: All field names in the schema.
            required_fields: Fields marked as required.

        Returns:
            List of (payload_dict, description) tuples with missing fields.
        """
        payloads = []

        # Remove each required field one at a time
        for field in required_fields:
            payload = {f: "test_value" for f in fields if f != field}
            payloads.append((payload, "Missing required field: {}".format(field)))

        # Remove ALL fields
        payloads.append(({}, "Empty payload — all fields missing"))

        # Send only unknown fields
        payloads.append(
            (
                {"__unknown_field__": "chaos", "x-custom": 123},
                "Payload with only unknown fields",
            )
        )

        return payloads

    def generate_header_chaos(self) -> List[Tuple[Dict[str, str], str]]:
        """Generate chaotic HTTP headers to test server behavior.

        Returns:
            List of (headers_dict, description) tuples.
        """
        headers_list = [
            ({}, "No Content-Type header"),
            ({"Content-Type": "text/xml"}, "XML Content-Type (potential XXE)"),
            ({"Content-Type": "application/xml"}, "XML Content-Type variant"),
            (
                {"Content-Type": "multipart/form-data"},
                "Multipart without boundary",
            ),
            (
                {"Content-Type": "application/json; charset=utf-7"},
                "UTF-7 charset (encoding attack)",
            ),
            (
                {"Content-Type": "application/x-www-form-urlencoded"},
                "Form encoding instead of JSON",
            ),
            (
                {"X-Forwarded-For": "127.0.0.1"},
                "X-Forwarded-For localhost (SSRF bypass)",
            ),
            (
                {"Transfer-Encoding": "chunked"},
                "Chunked transfer encoding",
            ),
            (
                {"Content-Length": "0"},
                "Zero content length with body",
            ),
            (
                {"Content-Length": "999999"},
                "Mismatched content length",
            ),
        ]
        return headers_list


class AnomalyDetector:
    """Detects anomalies in API responses during chaos testing."""

    def __init__(self) -> None:
        self.baseline_times: List[float] = []
        self._baseline_mean: float = 0.0
        self._baseline_std: float = 0.0

    def set_baseline(self, response_times: List[float]) -> None:
        """Set baseline response times for anomaly detection.

        Args:
            response_times: List of normal response times in seconds.
        """
        if not response_times:
            self._baseline_mean = 1.0
            self._baseline_std = 0.5
            return

        self.baseline_times = response_times
        self._baseline_mean = sum(response_times) / len(response_times)

        if len(response_times) > 1:
            variance = sum(
                (t - self._baseline_mean) ** 2 for t in response_times
            ) / (len(response_times) - 1)
            self._baseline_std = math.sqrt(variance)
        else:
            self._baseline_std = self._baseline_mean * 0.5

    def detect_anomalies(
        self,
        status_code: int,
        response_time: float,
        response_body: str,
        endpoint: str,
        method: str,
        chaos_input: ChaosInput,
    ) -> List[AnomalyResult]:
        """Detect anomalies in a chaos test response.

        Args:
            status_code: HTTP response status code.
            response_time: Response time in seconds.
            response_body: Response body as string.
            endpoint: API endpoint path.
            method: HTTP method.
            chaos_input: The chaos input that was sent.

        Returns:
            List of detected anomalies.
        """
        anomalies = []

        # Check for 5xx server errors
        if status_code >= 500:
            severity = "critical" if status_code == 500 else "high"
            anomalies.append(
                AnomalyResult(
                    anomaly_type="server_error",
                    endpoint=endpoint,
                    method=method,
                    chaos_input=chaos_input,
                    status_code=status_code,
                    response_time=response_time,
                    response_body=response_body,
                    severity=severity,
                )
            )

        # Check for response time outlier (> 3 sigma from baseline)
        if self._baseline_std > 0:
            threshold = self._baseline_mean + (3 * self._baseline_std)
            if response_time > threshold and response_time > 3 * self._baseline_mean:
                anomalies.append(
                    AnomalyResult(
                        anomaly_type="response_time_outlier",
                        endpoint=endpoint,
                        method=method,
                        chaos_input=chaos_input,
                        status_code=status_code,
                        response_time=response_time,
                        response_body=response_body,
                        severity="high",
                    )
                )

        # Check for error messages that leak information
        leak_patterns = [
            "stack trace",
            "traceback",
            "exception",
            "NullReferenceException",
            "NullPointerException",
            "segmentation fault",
            "SQLSTATE",
            "syntax error",
            "undefined method",
            "at line",
            "file not found",
            "permission denied",
        ]
        body_lower = response_body.lower()
        for pattern in leak_patterns:
            if pattern.lower() in body_lower:
                anomalies.append(
                    AnomalyResult(
                        anomaly_type="information_leak",
                        endpoint=endpoint,
                        method=method,
                        chaos_input=chaos_input,
                        status_code=status_code,
                        response_time=response_time,
                        response_body=response_body,
                        severity="high",
                    )
                )
                break  # Only report once per response

        return anomalies

    def detect_connection_error(
        self,
        endpoint: str,
        method: str,
        chaos_input: ChaosInput,
        error_message: str,
    ) -> AnomalyResult:
        """Create an anomaly result for connection errors (potential crash).

        Args:
            endpoint: API endpoint path.
            method: HTTP method.
            chaos_input: The chaos input that was sent.
            error_message: The connection error message.

        Returns:
            AnomalyResult for the connection error.
        """
        return AnomalyResult(
            anomaly_type="connection_error",
            endpoint=endpoint,
            method=method,
            chaos_input=chaos_input,
            status_code=0,
            response_time=0.0,
            response_body=error_message,
            severity="critical",
        )


class ChaosEngine:
    """Main chaos testing engine that coordinates generators and detectors.

    Chaos Mode goes beyond known attack signatures by generating structurally
    invalid inputs to discover unknown vulnerabilities, crashes, and hidden
    behaviors.
    """

    def __init__(self, chaos_level: int = 3) -> None:
        """Initialize the chaos engine.

        Args:
            chaos_level: Intensity from 1 (gentle) to 5 (maximum carnage).
        """
        self.chaos_level = max(1, min(5, chaos_level))
        self.generator = ChaosGenerator(chaos_level=self.chaos_level)
        self.detector = AnomalyDetector()
        self.findings: List[AnomalyResult] = []

    def generate_chaos_payloads(
        self,
        endpoint: str,
        method: str,
        fields: Optional[Dict[str, str]] = None,
        required_fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Generate all chaos test payloads for an endpoint.

        Args:
            endpoint: API endpoint path.
            method: HTTP method.
            fields: Dictionary mapping field names to their types.
            required_fields: List of required field names.

        Returns:
            List of test case dicts with 'payload', 'headers', 'description'.
        """
        test_cases = []

        # Generate per-field chaos inputs
        if fields:
            for field_name, field_type in fields.items():
                chaos_inputs = self.generator.generate_for_field(
                    field_name, field_type
                )
                for ci in chaos_inputs:
                    # Build a payload with the chaos value for this field
                    # and normal values for other fields
                    payload = {}
                    for f, _ in fields.items():
                        if f == field_name:
                            payload[f] = ci.chaos_value
                        else:
                            payload[f] = "normal_test_value"

                    test_cases.append(
                        {
                            "payload": payload,
                            "headers": {"Content-Type": "application/json"},
                            "description": "[CHAOS] {} on field '{}': {}".format(
                                ci.original_type, field_name, ci.description
                            ),
                            "chaos_input": ci,
                            "endpoint": endpoint,
                            "method": method,
                        }
                    )

        # Generate missing field cases
        if fields and required_fields:
            missing_payloads = self.generator.generate_missing_fields_payload(
                list(fields.keys()), required_fields
            )
            for payload, desc in missing_payloads:
                test_cases.append(
                    {
                        "payload": payload,
                        "headers": {"Content-Type": "application/json"},
                        "description": "[CHAOS] {}".format(desc),
                        "chaos_input": ChaosInput(
                            "payload", "object", payload, desc
                        ),
                        "endpoint": endpoint,
                        "method": method,
                    }
                )

        # Generate header chaos
        header_cases = self.generator.generate_header_chaos()
        for headers, desc in header_cases:
            sample_payload = {}
            if fields:
                sample_payload = {f: "test_value" for f in fields}

            test_cases.append(
                {
                    "payload": sample_payload,
                    "headers": headers,
                    "description": "[CHAOS] Header mutation: {}".format(desc),
                    "chaos_input": ChaosInput(
                        "headers", "object", headers, desc
                    ),
                    "endpoint": endpoint,
                    "method": method,
                }
            )

        return test_cases

    async def run_chaos_tests(
        self,
        target_url: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Run chaos tests against target endpoints.

        This is a simulation that demonstrates the chaos testing flow.
        When the executor is fully implemented, this will make real requests.

        Args:
            target_url: Base URL of the target.
            endpoints: List of endpoint definitions with fields and types.

        Returns:
            List of chaos findings as dicts.
        """
        import asyncio

        print("\n🌪️  [CHAOS MODE] Starting chaos testing...")
        print("   Chaos Level: {} / 5".format(self.chaos_level))

        level_labels = {
            1: "Gentle (basic type mismatches)",
            2: "Moderate (boundary values + nulls)",
            3: "Aggressive (Unicode + control chars + large inputs)",
            4: "Destructive (overflow + injection + nested attacks)",
            5: "Maximum Carnage (everything at once)",
        }
        print("   Mode: {}".format(level_labels.get(self.chaos_level, "Unknown")))

        # Use simulated endpoints if none provided
        if not endpoints:
            endpoints = self._get_simulated_endpoints()

        # Set baseline response times (simulated)
        self.detector.set_baseline([0.1, 0.15, 0.12, 0.11, 0.13])

        total_tests = 0
        total_anomalies = 0

        for ep in endpoints:
            endpoint_path = ep.get("path", "/unknown")
            method = ep.get("method", "POST")
            fields = ep.get("fields", {})
            required = ep.get("required_fields", [])

            test_cases = self.generate_chaos_payloads(
                endpoint_path, method, fields, required
            )

            print("\n   🎯 Testing {} {} ({} chaos inputs)".format(
                method, endpoint_path, len(test_cases)
            ))

            for tc in test_cases:
                total_tests += 1
                # Simulate sending the request and getting a response
                result = await self._simulate_chaos_request(tc)

                if result:
                    for anomaly in result:
                        self.findings.append(anomaly)
                        total_anomalies += 1
                        print(
                            "   🔥 [CHAOS] {} on {} {} — {}".format(
                                anomaly.anomaly_type,
                                anomaly.method,
                                anomaly.endpoint,
                                anomaly.chaos_input.description,
                            )
                        )

                # Small delay to avoid overwhelming output
                await asyncio.sleep(0.01)

        print("\n   📊 Chaos testing complete!")
        print("   Total tests: {}".format(total_tests))
        print("   Anomalies found: {}".format(total_anomalies))

        return [f.to_dict() for f in self.findings]

    async def _simulate_chaos_request(
        self, test_case: Dict[str, Any]
    ) -> Optional[List[AnomalyResult]]:
        """Simulate a chaos request and detect anomalies.

        In production, this will use the Executor to make real HTTP calls.
        For now, it simulates realistic server behavior.
        """
        import random

        chaos_input = test_case["chaos_input"]
        endpoint = test_case["endpoint"]
        method = test_case["method"]

        # Simulate different server behaviors based on chaos input
        roll = random.random()

        if chaos_input.description in [
            "Null value",
            "Null byte",
            "Very large integer",
        ] and roll < 0.4:
            # Simulate a 500 error
            return self.detector.detect_anomalies(
                status_code=500,
                response_time=0.2,
                response_body='{"error": "Internal Server Error", "traceback": "NullReferenceException at line 42"}',
                endpoint=endpoint,
                method=method,
                chaos_input=chaos_input,
            )

        if "long string" in chaos_input.description.lower() and roll < 0.3:
            # Simulate slow response (potential ReDoS)
            return self.detector.detect_anomalies(
                status_code=200,
                response_time=15.0,
                response_body='{"status": "ok"}',
                endpoint=endpoint,
                method=method,
                chaos_input=chaos_input,
            )

        if "overflow" in chaos_input.description.lower() and roll < 0.35:
            # Simulate server error on overflow
            return self.detector.detect_anomalies(
                status_code=500,
                response_time=0.1,
                response_body='{"error": "ArithmeticException: overflow"}',
                endpoint=endpoint,
                method=method,
                chaos_input=chaos_input,
            )

        if "Content-Type" in str(chaos_input.chaos_value) and "xml" in str(
            chaos_input.chaos_value
        ).lower() and roll < 0.25:
            # Simulate XXE vulnerability indicator
            return self.detector.detect_anomalies(
                status_code=200,
                response_time=0.3,
                response_body="<?xml version='1.0'?><!DOCTYPE root>file not found: /etc/passwd",
                endpoint=endpoint,
                method=method,
                chaos_input=chaos_input,
            )

        # Most requests get a normal 400 (expected for invalid input)
        return None

    def _get_simulated_endpoints(self) -> List[Dict[str, Any]]:
        """Return simulated endpoints for demonstration."""
        return [
            {
                "path": "/api/users",
                "method": "POST",
                "fields": {
                    "name": "string",
                    "age": "integer",
                    "email": "string",
                    "is_active": "boolean",
                },
                "required_fields": ["name", "email"],
            },
            {
                "path": "/api/products",
                "method": "POST",
                "fields": {
                    "title": "string",
                    "price": "float",
                    "quantity": "integer",
                    "tags": "array",
                },
                "required_fields": ["title", "price"],
            },
            {
                "path": "/api/orders",
                "method": "POST",
                "fields": {
                    "user_id": "integer",
                    "items": "array",
                    "metadata": "object",
                    "total": "float",
                },
                "required_fields": ["user_id", "items"],
            },
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Return a summary of chaos testing results."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = {}  # type: Dict[str, int]

        for finding in self.findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )
            type_counts[finding.anomaly_type] = (
                type_counts.get(finding.anomaly_type, 0) + 1
            )

        return {
            "chaos_level": self.chaos_level,
            "total_findings": len(self.findings),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "findings": [f.to_dict() for f in self.findings],
        }
