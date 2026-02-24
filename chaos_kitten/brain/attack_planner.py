"""Attack planning logic for Chaos Kitten."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml
from langchain_anthropic import ChatAnthropic
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)


@dataclass
class AttackProfile:
    """Represents a loaded attack profile from a YAML file."""

    name: str
    category: str
    severity: str
    description: str
    payloads: list[str]
    target_fields: list[str]
    success_indicators: dict[str, Any]
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    
    # Business Logic Attack specific fields
    attack_type: str = ""  # Type of attack: state-transition, race-condition, authorization, payment, workflow
    requires_state: bool = False  # Whether the attack requires tracking state
    requires_concurrency: bool = False  # Whether the attack requires concurrent requests
    state_transitions: list[dict[str, Any]] = field(default_factory=list)  # State machine for workflow attacks
    concurrent_requests: int = 1  # Number of concurrent requests needed
    timing_sensitive: bool = False  # Whether timing is critical for the attack


ATTACK_PLANNING_PROMPT = """You are a security expert analyzing an API endpoint for vulnerabilities.
Endpoint: {method} {path}
Parameters: {parameters}
Request Body: {body}

Analyze this endpoint and suggest attack vectors. Consider:
1. Parameter types and names (id, user, query suggest different attacks)
2. HTTP method (POST/PUT more likely to have injection points)
3. Authentication requirements

Return a prioritized list of attacks to try.
You must respond ONLY with a valid JSON array of objects. Do not include markdown formatting or explanations outside the JSON.
Each object must have the following keys:
- "type" (string, e.g., "sql_injection", "xss", "idor", "path_traversal")
- "name" (string, short name of the attack)
- "description" (string, what the attack does)
- "payload" (dict or string, the actual payload to send)
- "target_param" (string, the parameter or body field to target)
- "expected_status" (integer, expected HTTP status if vulnerable, e.g., 500)
- "priority" (string, "high", "medium", or "low")
"""

PAYLOAD_SUGGESTION_PROMPT = """You are an expert penetration tester.
Given the attack type '{attack_type}' and the context of the endpoint '{context}',
suggest a list of 5 specific, creative payloads to test for vulnerabilities.

Respond ONLY with a valid JSON array of strings representing the payloads. Do not include markdown blocks.
"""

REASONING_PROMPT = """You are an API security tester.
How would you test a field named '{field_name}' of type '{field_type}' for vulnerabilities?
Provide a concise, 1-2 sentence reasoning."""


class AttackPlanner:
    """Plan attacks based on API structure and context."""

    def __init__(
        self,
        endpoints: list[dict[str, Any]],
        toys_path: str = "toys/",
        llm_provider: str = "anthropic",
        temperature: float = 0.7,
    ) -> None:
        self.endpoints = endpoints
        self.toys_path = toys_path
        self.attack_profiles: list[AttackProfile] = []
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self.llm_provider = llm_provider.lower()
        self.temperature = temperature
        self.llm = self._init_llm()
        self.load_attack_profiles()

    def _init_llm(self) -> Any:
        if self.llm_provider == "anthropic":
            return ChatAnthropic(
                model="claude-3-5-sonnet-20241022", temperature=self.temperature
            )
        if self.llm_provider == "openai":
            return ChatOpenAI(model="gpt-4", temperature=self.temperature)
        if self.llm_provider == "ollama":
            return ChatOllama(model="llama3.1", temperature=self.temperature)

        logger.warning(
            "Unknown LLM provider %s. Falling back to Claude.", self.llm_provider
        )
        return ChatAnthropic(
            model="claude-3-5-sonnet-20241022", temperature=self.temperature
        )

    def load_attack_profiles(self) -> None:
        """Load all attack profiles from the toys directory."""
        search_path = os.path.join(self.toys_path, "*.yaml")
        yaml_files = sorted(glob.glob(search_path))

        # Keep this method idempotent when called multiple times.
        self.attack_profiles = []
        self._cache.clear()

        if not yaml_files:
            logger.warning("No attack profiles found in %s", self.toys_path)
            return

        for file_path in yaml_files:
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data:
                    logger.warning("Skipping empty file: %s", file_path)
                    continue

                required_fields = [
                    "name",
                    "category",
                    "severity",
                    "payloads",
                    "target_fields",
                ]
                missing = [field_name for field_name in required_fields if field_name not in data]

                if missing:
                    logger.warning(
                        "Skipping %s: Missing required fields %s", file_path, missing
                    )
                    continue

                payloads = data.get("payloads") or []
                target_fields = data.get("target_fields") or []
                if not isinstance(payloads, list) or not isinstance(target_fields, list):
                    logger.warning(
                        "Skipping %s: 'payloads' and 'target_fields' must be lists",
                        file_path,
                    )
                    continue

                profile = AttackProfile(
                    name=str(data["name"]),
                    category=str(data["category"]),
                    severity=str(data["severity"]).lower(),
                    description=str(data.get("description", "")),
                    payloads=[str(p) for p in payloads],
                    target_fields=[str(tf).lower() for tf in target_fields],
                    success_indicators=data.get("success_indicators", {}) or {},
                    remediation=str(data.get("remediation", "")),
                    references=[str(r) for r in (data.get("references", []) or [])],
                    attack_type=str(data.get("attack_type", "")),
                    requires_state=bool(data.get("requires_state", False)),
                    requires_concurrency=bool(data.get("requires_concurrency", False)),
                    state_transitions=data.get("state_transitions", []) or [],
                    concurrent_requests=int(data.get("concurrent_requests", 1)),
                    timing_sensitive=bool(data.get("timing_sensitive", False)),
                )
                self.attack_profiles.append(profile)
                logger.debug("Loaded attack profile: %s", profile.name)
            except Exception as exc:
                logger.error(
                    "Failed to load attack profile from %s: %s", file_path, exc
                )

        logger.info("Loaded %d attack profiles", len(self.attack_profiles))

    def plan_attacks(self, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        """Plan attacks for a specific endpoint."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        params = endpoint.get("parameters", [])
        body = endpoint.get("requestBody", {})

        cache_key = (
            f"{method}:{path}:"
            f"{json.dumps(params, sort_keys=True, default=str)}:"
            f"{json.dumps(body, sort_keys=True, default=str)}"
        )
        if cache_key in self._cache:
            return self._cache[cache_key]

        attacks: list[dict[str, Any]] = []
        try:
            prompt = ChatPromptTemplate.from_template(ATTACK_PLANNING_PROMPT)
            chain = prompt | self.llm | JsonOutputParser()
            generated = chain.invoke(
                {
                    "method": method,
                    "path": path,
                    "parameters": json.dumps(params),
                    "body": json.dumps(body),
                }
            )
            if isinstance(generated, list) and generated:
                attacks = self._normalize_llm_attacks(generated, endpoint)
                if attacks:
                    logger.info(
                        "LLM generated %d attack vectors for %s %s",
                        len(attacks),
                        method,
                        path,
                    )
        except Exception as exc:
            logger.warning(
                "LLM attack planning failed for %s: %s. Falling back to rule-based profiles.",
                path,
                exc,
            )

        if not attacks:
            attacks = self._plan_rule_based(endpoint)

        self._cache[cache_key] = attacks
        return attacks

    def _normalize_llm_attacks(
        self, generated_attacks: list[dict[str, Any]], endpoint: dict[str, Any]
    ) -> list[dict[str, Any]]:
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "")
        normalized: list[dict[str, Any]] = []

        for raw_attack in generated_attacks:
            if not isinstance(raw_attack, dict):
                continue

            target_param = (
                raw_attack.get("target_param")
                or raw_attack.get("field")
                or raw_attack.get("target")
                or "q"
            )
            payload = raw_attack.get("payload")
            if payload is None:
                payloads = raw_attack.get("payloads")
                if isinstance(payloads, list) and payloads:
                    payload = {target_param: payloads[0]}
                else:
                    payload = {target_param: "' OR 1=1 --"}
            elif isinstance(payload, str):
                payload = {target_param: payload}

            payload_values: list[str]
            raw_payloads = raw_attack.get("payloads")
            if isinstance(raw_payloads, list) and raw_payloads:
                payload_values = [str(item) for item in raw_payloads]
            else:
                payload_values = [self._payload_preview(payload)]

            severity = str(
                raw_attack.get("severity")
                or self._priority_to_severity(str(raw_attack.get("priority", "medium")))
            ).lower()

            indicators = (
                raw_attack.get("success_indicators")
                or raw_attack.get("expected_indicators")
                or {}
            )
            if not isinstance(indicators, dict):
                indicators = {}

            normalized.append(
                {
                    "type": raw_attack.get("type", "generic"),
                    "name": raw_attack.get("name", "LLM Attack"),
                    "profile_name": raw_attack.get(
                        "profile_name", raw_attack.get("name", "LLM Attack")
                    ),
                    "description": raw_attack.get("description", ""),
                    "endpoint": path,
                    "method": method,
                    "field": raw_attack.get("field", str(target_param)),
                    "location": raw_attack.get("location", "query"),
                    "payloads": payload_values,
                    "payload": payload,
                    "target_param": str(target_param),
                    "expected_status": int(raw_attack.get("expected_status", 500)),
                    "priority": raw_attack.get("priority", self._severity_to_priority(severity)),
                    "severity": severity,
                    "success_indicators": indicators,
                    "expected_indicators": indicators,
                    "remediation": raw_attack.get("remediation", ""),
                    "references": raw_attack.get("references", []),
                }
            )

        normalized.sort(key=self._attack_sort_key)
        return normalized

    def _plan_rule_based(self, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "")
        fields = self._extract_endpoint_fields(endpoint)

        attacks: list[dict[str, Any]] = []
        
        
        for profile in self.attack_profiles:
            for field_name, location in fields:
                if any(
                    self._field_matches_target(field_name, target)
                    for target in profile.target_fields
                ):
                    first_payload = (
                        profile.payloads[0] if profile.payloads else "' OR 1=1 --"
                    )
                    payload = self._build_payload(field_name, location, first_payload)
                    indicators = profile.success_indicators or {}
                    attacks.append(
                        {
                            "type": profile.category,
                            "name": profile.name,
                            "profile_name": profile.name,
                            "description": profile.description,
                            "endpoint": path,
                            "method": method,
                            "field": field_name,
                            "location": location,
                            "payloads": profile.payloads or [first_payload],
                            "payload": payload,
                            "target_param": field_name,
                            "expected_status": self._expected_status(indicators),
                            "priority": self._severity_to_priority(profile.severity),
                            "severity": profile.severity,
                            "success_indicators": indicators,
                            "expected_indicators": indicators,
                            "remediation": profile.remediation,
                            "references": profile.references,
                        }
                    )

        if not attacks:
            fallback_field, fallback_location = fields[0] if fields else ("q", "query")
            fallback_payload = self._build_payload(
                fallback_field, fallback_location, "' OR 1=1 --"
            )
            attacks.append(
                {
                    "type": "sql_injection",
                    "name": "Fallback SQLi Probe",
                    "profile_name": "Fallback SQLi Probe",
                    "description": "Basic SQL injection test (no profile match)",
                    "endpoint": path,
                    "method": method,
                    "field": fallback_field,
                    "location": fallback_location,
                    "payloads": ["' OR 1=1 --"],
                    "payload": fallback_payload,
                    "target_param": fallback_field,
                    "expected_status": 500,
                    "priority": "high",
                    "severity": "high",
                    "success_indicators": {"status_codes": [500]},
                    "expected_indicators": {"status_codes": [500]},
                    "remediation": "",
                    "references": [],
                }
            )

        unique_attacks: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for attack in attacks:
            key = (
                str(attack.get("profile_name", "")),
                str(attack.get("field", "")),
                str(attack.get("location", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            unique_attacks.append(attack)

        unique_attacks.sort(key=self._attack_sort_key)
        return unique_attacks

    def _extract_endpoint_fields(self, endpoint: dict[str, Any]) -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = []

        for param in endpoint.get("parameters", []):
            if not isinstance(param, dict):
                continue
            name = param.get("name")
            if not name:
                continue
            location = str(param.get("in", "query")).lower()
            fields.append((str(name), location))

        request_body = endpoint.get("requestBody") or {}
        content = request_body.get("content", {})
        for content_type, media_type in content.items():
            schema = media_type.get("schema", {})
            properties = schema.get("properties", {})
            for prop_name, prop_details in properties.items():
                p_type = prop_details.get("type", "string")
                targetable_fields.append({"name": prop_name, "location": "body", "type": p_type})

        # Iterate through loaded profiles and find matches
        for profile in self.attack_profiles:
            # Special handling for GraphQL Security profile
            if profile.name == "GraphQL Security":
                # Check if endpoint path ends with /graphql
                if endpoint_path.endswith("/graphql") or "graphql" in endpoint_path.lower():
                    # Plan attacks for this endpoint
                    # GraphQL usually has a single entry point, so we attack the 'query' or body
                    attack_plan = {
                        "profile_name": profile.name,
                        "endpoint": endpoint_path,
                        "method": method,
                        "field": "query", # Virtual field name
                        "location": "graphql", # Special location for executor
                        "payloads": profile.payloads,
                        "expected_indicators": profile.success_indicators,
                        "severity": profile.severity
                    }
                    planned_attacks.append(attack_plan)
                continue

            # Special handling for file upload profile
            if profile.name == "File Upload Bypass":
                # Check if endpoint accepts multipart/form-data
                request_body = endpoint.get("requestBody") or {}
                content = request_body.get("content", {})
                if "multipart/form-data" in content or "application/octet-stream" in content:
                    # Find file fields
                    schema = content.get("multipart/form-data", {}).get("schema", {}) or \
                             content.get("application/octet-stream", {}).get("schema", {})
                    
                    properties = schema.get("properties", {})
                    for prop_name, prop_details in properties.items():
                        # Heuristic: verify if it looks like a file upload
                        # OpenAPI 3.0: type: string, format: binary
                        p_type = prop_details.get("type")
                        p_format = prop_details.get("format")
                        
                        is_file = (p_type == "string" and p_format in ("binary", "base64")) or \
                                  (prop_name.lower() in profile.target_fields)

                        if is_file:
                            attack_plan = {
                                "profile_name": profile.name,
                                "endpoint": endpoint_path,
                                "method": method,
                                "field": prop_name,
                                "location": "file", # Special location for executor
                                "payloads": profile.payloads,
                                "expected_indicators": profile.success_indicators,
                                "severity": profile.severity
                            }
                            planned_attacks.append(attack_plan)
                continue

            # ... (Standard logic for other profiles)
            
            for field_info in targetable_fields:
                field_name = field_info["name"]
                _ = field_info["type"] # Unused for now, but keeping for future type awareness
                
                # Check 1: Field name match (Exact or Fuzzy)
                # Exact match
                is_match = field_name in profile.target_fields
                
                # Fuzzy match (e.g., "user_email" matches "email" if "email" is a distinct word part)
                if not is_match:
                    # properly handle snake_case and other delimiters
                    parts = re.split(r'[^a-zA-Z0-9]', field_name.lower())
                    for target in profile.target_fields:
                        if target.lower() in parts:
                            is_match = True
                            break
                            
                if is_match:
                    # Check 2: Type compatibility (Basic)
                    # Use categories to determine if type mismatch is critical
                    # e.g., SQLi (string) vs ID (integer) - sometimes valid, sometimes not.
                    # For now, we'll be permissive but prioritize string fields for injections.
                    
                    # Logic for filtering based on method/category
                    # e.g. Don't test body interactions on GET requests unless strictly specific
                    if field_info["location"] == "body" and method == "get":
                        continue
                    schema = media_obj.get("schema") or {}
                    properties = schema.get("properties") if isinstance(schema, dict) else None
                    if isinstance(properties, dict):
                        for field_name in properties.keys():
                            fields.append((str(field_name), "body"))

        if not fields:
            fields.append(("q", "query"))

        deduped: list[tuple[str, str]] = []
        seen_fields: set[tuple[str, str]] = set()
        for field_name, location in fields:
            key = (field_name, location)
            if key not in seen_fields:
                seen_fields.add(key)
                deduped.append(key)

        return deduped

    def _field_matches_target(self, field_name: str, target_field: str) -> bool:
        field_norm = self._normalize_name(field_name)
        target_norm = self._normalize_name(target_field)

        if not field_norm or not target_norm:
            return False

        if field_norm == target_norm:
            return True

        if target_norm in field_norm or field_norm in target_norm:
            return True

        field_tokens = set(token for token in field_norm.split("_") if token)
        target_tokens = set(token for token in target_norm.split("_") if token)
        if field_tokens.intersection(target_tokens):
            return True

        for field_token in field_tokens:
            for target_token in target_tokens:
                min_len = min(len(field_token), len(target_token))
                if min_len < 2:
                    continue
                if field_token.endswith(target_token) or target_token.endswith(field_token):
                    return True

        return False

    def _normalize_name(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
        normalized = re.sub(r"_+", "_", normalized).strip("_")
        return normalized

    def _build_payload(self, field_name: str, location: str, payload: str) -> dict[str, Any]:
        # Executor handles GET payload as query params and POST/PUT/PATCH payload as JSON.
        # Keeping a dict shape across locations is the most compatible contract here.
        return {field_name: payload}

    def _expected_status(self, indicators: dict[str, Any]) -> int:
        status_codes = indicators.get("status_codes") if isinstance(indicators, dict) else None
        if isinstance(status_codes, list):
            for status_code in status_codes:
                try:
                    return int(status_code)
                except (TypeError, ValueError):
                    continue
        return 500

    def _severity_rank(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return order.get(str(severity).lower(), 4)

    def _attack_sort_key(self, attack: dict[str, Any]) -> tuple[int, str]:
        severity = str(
            attack.get("severity")
            or self._priority_to_severity(str(attack.get("priority", "medium")))
        ).lower()
        return (self._severity_rank(severity), str(attack.get("profile_name", "")))

    def _severity_to_priority(self, severity: str) -> str:
        severity = str(severity).lower()
        if severity in {"critical", "high"}:
            return "high"
        if severity == "low":
            return "low"
        return "medium"

    def _priority_to_severity(self, priority: str) -> str:
        priority = str(priority).lower()
        if priority == "high":
            return "high"
        if priority == "low":
            return "low"
        return "medium"

    def _payload_preview(self, payload: Any) -> str:
        if isinstance(payload, dict) and len(payload) == 1:
            only_value = next(iter(payload.values()))
            return str(only_value)
        return str(payload)

    def suggest_payloads(self, attack_type: str, context: dict[str, Any]) -> list[str]:
        """Generate context-specific payloads using LLM intelligence."""
        prompt = ChatPromptTemplate.from_template(PAYLOAD_SUGGESTION_PROMPT)
        chain = prompt | self.llm | JsonOutputParser()

        try:
            payloads = chain.invoke({"attack_type": attack_type, "context": json.dumps(context)})
            if isinstance(payloads, list):
                return [str(payload) for payload in payloads]
        except Exception as exc:
            logger.warning("LLM payload suggestion failed: %s", exc)

        return ["' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd"]

    def reason_about_field(self, field_name: str, field_type: str) -> str:
        """Use LLM to reason about potential vulnerabilities for a field."""
        prompt = ChatPromptTemplate.from_template(REASONING_PROMPT)
        chain = prompt | self.llm

        try:
            response = chain.invoke({"field_name": field_name, "field_type": field_type})
            return str(response.content)
        except Exception as exc:
            logger.warning("LLM field reasoning failed: %s", exc)
            return (
                f"Test '{field_name}' of type '{field_type}' "
                "with boundary values and injection strings."
            )

    def _is_file_upload_endpoint(self, endpoint: dict[str, Any]) -> bool:
        """Detect if an endpoint is likely a file upload endpoint.
        
        Heuristics:
        - POST/PUT/PATCH method
        - Parameter names like: file, upload, attachment, document, image, media, avatar, profile_picture
        - Content-Type: multipart/form-data in request body
        """
        method = str(endpoint.get("method", "GET")).upper()
        if method not in ("POST", "PUT", "PATCH"):
            return False
        
        path = str(endpoint.get("path", "")).lower()
        upload_keywords = ["upload", "file", "attachment", "media", "image", "document", "form", "profile"]
        if any(keyword in path for keyword in upload_keywords):
            return True
        
        fields = self._extract_endpoint_fields(endpoint)
        file_field_names = ["file", "upload", "attachment", "document", "image", "media", "avatar", "profile_picture"]
        
        for field_name, _ in fields:
            if any(self._field_matches_target(field_name, file_field) for file_field in file_field_names):
                return True
        
        # Check request body for multipart/form-data
        request_body = endpoint.get("requestBody") or {}
        if isinstance(request_body, dict):
            content = request_body.get("content") or {}
            if "multipart/form-data" in content:
                return True
        
        return False

    def _is_deserialization_endpoint(self, endpoint: dict[str, Any]) -> bool:
        """Detect if an endpoint is likely a deserialization endpoint.
        
        Heuristics:
        - Content-Type headers indicating serialization formats
        - Path and parameter names suggesting serialization
        - Common deserialization-related keywords
        """
        method = str(endpoint.get("method", "GET")).upper()
        if method not in ("POST", "PUT", "PATCH"):
            return False
        
        path = str(endpoint.get("path", "")).lower()
        
        # Check path for deserialization-related keywords
        deserialization_path_keywords = [
            "deserialize", "serialize", "serial", "unserialize", 
            "pickle", "marshal", "decode", "hydrate", "object",
            "restored", "reconstruct", "import", "load", "save",
            "cache", "session", "state", "persist"
        ]
        if any(keyword in path for keyword in deserialization_path_keywords):
            return True
        
        # Check fields for deserialization-related names
        fields = self._extract_endpoint_fields(endpoint)
        deserialization_field_names = [
            "serialized", "pickle", "marshalled", "marshal", "object_data",
            "encoded_object", "encoded", "yaml", "yml", "phar", "json_object",
            "json_obj", "pojo", "entity", "dto", "model", "class",
            "unserialize", "deserialize", "restore", "hydrate", "inject"
        ]
        
        for field_name, _ in fields:
            if any(self._field_matches_target(field_name, name) for name in deserialization_field_names):
                return True
        
        # Check request body for serialization Content-Types
        request_body = endpoint.get("requestBody") or {}
        if isinstance(request_body, dict):
            content = request_body.get("content") or {}
            serialization_content_types = [
                "application/x-java-serialized-object",
                "application/x-python-pickle",
                "application/x-marshal",
                "application/x-php-serialize",
                "application/x-ruby-marshal",
                "application/x-json-object",
                "application/x-kryo",
                "application/x-hessian",
                "application/x-avro",
                "application/x-protobuf",
                "application/x-protocol-buffers"
            ]
            for content_type in serialization_content_types:
                if content_type in content:
                    return True
        
        return False

    def _plan_deserialization_attacks(self, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        """Plan deserialization attacks based on detected language/format.
        
        Tests for:
        - Java deserialization (ysoserial gadget chains)
        - Python pickle/YAML unsafe loading
        - PHP unserialize() vulnerabilities
        """
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        fields = self._extract_endpoint_fields(endpoint)
        
        attacks: list[dict[str, Any]] = []
        
        # Get all deserialization profiles
        deserialization_profiles = [
            p for p in self.attack_profiles 
            if p.category == "deserialization"
        ]
        
        if not deserialization_profiles:
            logger.debug("No deserialization profiles loaded, skipping deserialization attack planning")
            return attacks
        
        # Determine which languages/formats to test based on endpoint characteristics
        languages_to_test = self._detect_deserialization_languages(endpoint)
        
        for language in languages_to_test:
            # Find matching profiles for this language
            lang_profiles = [
                p for p in deserialization_profiles 
                if language.lower() in p.name.lower()
            ]
            
            if not lang_profiles:
                # Use all deserialization profiles if no language-specific one found
                lang_profiles = deserialization_profiles
            
            for profile in lang_profiles:
                for field_name, location in fields:
                    # Check if field matches target fields for this profile
                    if not any(
                        self._field_matches_target(field_name, target)
                        for target in profile.target_fields
                    ):
                        continue
                    
                    # Select appropriate payloads based on language
                    selected_payloads = self._select_deserialization_payloads(
                        language, profile.payloads
                    )
                    
                    for payload in selected_payloads[:5]:  # Limit to 5 payloads per profile
                        payload_dict = self._build_payload(field_name, location, payload)
                        
                        attacks.append({
                            "type": "deserialization",
                            "name": f"{profile.name} - {language}",
                            "profile_name": profile.name,
                            "description": f"Test {language} deserialization with gadget: {payload[:50]}...",
                            "endpoint": path,
                            "method": method,
                            "field": field_name,
                            "location": location,
                            "payloads": selected_payloads[:10],
                            "payload": payload_dict,
                            "target_param": field_name,
                            "expected_status": 500,
                            "priority": "critical",
                            "severity": "critical",
                            "success_indicators": profile.success_indicators,
                            "expected_indicators": profile.success_indicators,
                            "remediation": profile.remediation,
                            "references": profile.references,
                            "attack_subtype": f"{language}_deserialization",
                            "target_language": language
                        })
        
        # Limit to top high-severity attacks
        attacks.sort(key=self._attack_sort_key)
        return attacks[:15]

    def _detect_deserialization_languages(self, endpoint: dict[str, Any]) -> list[str]:
        """Detect which programming languages/formats might be used based on endpoint characteristics."""
        languages = []
        
        path = str(endpoint.get("path", "")).lower()
        
        # Check for language-specific keywords in path
        java_indicators = ["java", "jvm", "spring", "jackson", "fastjson", "xstream", "hibernate"]
        python_indicators = ["python", "django", "flask", "py", "pickle", "yaml", "pyyaml"]
        php_indicators = ["php", "laravel", "symfony", "wordpress", "drupal"]
        
        for indicator in java_indicators:
            if indicator in path:
                languages.append("Java")
                break
        
        for indicator in python_indicators:
            if indicator in path:
                languages.append("Python")
                break
        
        for indicator in php_indicators:
            if indicator in path:
                languages.append("PHP")
                break
        
        # Check Content-Type headers
        request_body = endpoint.get("requestBody") or {}
        if isinstance(request_body, dict):
            content = request_body.get("content") or {}
            
            if "application/x-java-serialized-object" in content and "Java" not in languages:
                languages.append("Java")
            if any(t in content for t in ["application/x-python-pickle", "application/x-yaml"]) and "Python" not in languages:
                languages.append("Python")
            if "application/x-php-serialize" in content and "PHP" not in languages:
                languages.append("PHP")
        
        # Default to all if no specific language detected
        if not languages:
            languages = ["Java", "Python", "PHP"]
        
        return languages

    def _select_deserialization_payloads(self, language: str, all_payloads: list[str]) -> list[str]:
        """Select appropriate payloads based on the target language.
        
        Filter payloads to match the specific language's serialization format.
        """
        if not all_payloads:
            return []
        
        language = language.lower()
        filtered_payloads: list[str] = []
        
        for payload in all_payloads:
            # Java payloads: base64, JSON gadget chains, XML, JNDI
            if language == "java":
                # Base64 encoded (typical ysoserial)
                if payload.startswith(("rO0AB", "rO0AC")):
                    filtered_payloads.append(payload)
                # JSON/Fastjson gadget chains
                elif payload.startswith("{") or payload.startswith("<"):
                    filtered_payloads.append(payload)
                # JNDI, JRMP, etc.
                elif any(x in payload for x in ["jndi:", "jrmp:", "ldap://", "rmi://"]):
                    filtered_payloads.append(payload)
            
            # Python payloads: pickle, YAML, jsonpickle
            elif language == "python":
                # Pickle protocol markers or YAML tags
                if payload.startswith(("80", "(S", "gASV", "!!")):
                    filtered_payloads.append(payload)
                # YAML tags
                elif "!!python" in payload or "!!yaml" in payload:
                    filtered_payloads.append(payload)
                # jsonpickle format
                elif "py/object" in payload or "py/args" in payload:
                    filtered_payloads.append(payload)
                # Python string execution
                elif "os.system" in payload or "subprocess" in payload:
                    filtered_payloads.append(payload)
            
            # PHP payloads: serialized format
            elif language == "php":
                # PHP serialize format: O: (object), s: (string), a: (array), etc.
                if any(x in payload for x in ["O:", "s:", "a:", "i:", "b:", "d:", "N;"]):
                    filtered_payloads.append(payload)
                # Basic PHP strings
                elif not payload.startswith(("{", "rO0AB", "80", "!!")):
                    filtered_payloads.append(payload)
        
        # If we filtered out everything, return all payloads (fallback)
        if not filtered_payloads:
            return all_payloads[:10]  # Limit to 10 to prevent explosion
        
        return filtered_payloads

    def _plan_file_upload_attacks(self, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        """Plan file upload bypass attacks for upload endpoints.
        
        Tests for:
        - MIME type spoofing
        - Extension filtering bypass
        - Path traversal in filenames
        - File size validation bypass
        - Polyglot files
        """
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        fields = self._extract_endpoint_fields(endpoint)
        
        # Find file upload fields
        file_field_names = ["file", "upload", "attachment", "document", "image", "media", "avatar", "profile_picture"]
        file_fields = [
            (field_name, location)
            for field_name, location in fields
            if any(self._field_matches_target(field_name, file_field) for file_field in file_field_names)
        ]
        
        # If no specific file fields found, use first field as upload field
        if not file_fields and fields:
            file_fields = [fields[0]]
        
        attacks: list[dict[str, Any]] = []
        
        # File upload profile
        file_upload_profile = next(
            (p for p in self.attack_profiles if p.category == "file_upload"),
            None
        )
        
        if not file_upload_profile:
            logger.debug("File upload profile not loaded, skipping file upload attack planning")
            return attacks
        
        for field_name, location in file_fields:
            # MIME type spoofing attacks
            mime_types = ["image/jpeg", "image/png", "text/plain", "application/pdf"]
            for mime_type in mime_types:
                attacks.append({
                    "type": "file_upload",
                    "name": "MIME Type Spoofing",
                    "profile_name": file_upload_profile.name,
                    "description": f"Attempt to bypass MIME type validation by spoofing as {mime_type}",
                    "endpoint": path,
                    "method": method,
                    "field": field_name,
                    "location": location,
                    "payloads": [f"shell.php (as {mime_type})"],
                    "payload": {
                        field_name: "shell.php",
                        "mime_type": mime_type
                    },
                    "target_param": field_name,
                    "expected_status": 201,
                    "priority": "high",
                    "severity": "high",
                    "success_indicators": {"status_codes": [200, 201]},
                    "expected_indicators": {"status_codes": [200, 201]},
                    "remediation": file_upload_profile.remediation,
                    "references": file_upload_profile.references,
                    "attack_subtype": "mime_type_bypass"
                })
            
            # Extension filtering bypass attacks
            extension_bypasses = [
                "shell.php.jpg",
                "shell.jpg.php",
                "shell.php%00.jpg",
                "shell.php.",
                "shell.php%20",
                "shell.php5",
                "shell.phtml"
            ]
            for filename in extension_bypasses:
                attacks.append({
                    "type": "file_upload",
                    "name": "Extension Filtering Bypass",
                    "profile_name": file_upload_profile.name,
                    "description": f"Attempt to bypass extension filter using filename: {filename}",
                    "endpoint": path,
                    "method": method,
                    "field": field_name,
                    "location": location,
                    "payloads": [filename],
                    "payload": {field_name: filename},
                    "target_param": field_name,
                    "expected_status": 200,
                    "priority": "high",
                    "severity": "high",
                    "success_indicators": {"status_codes": [200, 201]},
                    "expected_indicators": {"status_codes": [200, 201]},
                    "remediation": file_upload_profile.remediation,
                    "references": file_upload_profile.references,
                    "attack_subtype": "extension_bypass"
                })
            
            # Path traversal attacks
            traversal_paths = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd"
            ]
            for traversal in traversal_paths:
                attacks.append({
                    "type": "file_upload",
                    "name": "Path Traversal in Upload",
                    "profile_name": file_upload_profile.name,
                    "description": f"Attempt path traversal in upload filename: {traversal}",
                    "endpoint": path,
                    "method": method,
                    "field": field_name,
                    "location": location,
                    "payloads": [traversal],
                    "payload": {field_name: traversal},
                    "target_param": field_name,
                    "expected_status": 500,
                    "priority": "critical",
                    "severity": "critical",
                    "success_indicators": {"status_codes": [200, 500]},
                    "expected_indicators": {"status_codes": [200, 500]},
                    "remediation": file_upload_profile.remediation,
                    "references": file_upload_profile.references,
                    "attack_subtype": "path_traversal"
                })
            
            # Null byte injection
            attacks.append({
                "type": "file_upload",
                "name": "Null Byte Injection",
                "profile_name": file_upload_profile.name,
                "description": "Attempt to bypass extension filters using null byte injection",
                "endpoint": path,
                "method": method,
                "field": field_name,
                "location": location,
                "payloads": ["shell.php%00.jpg"],
                "payload": {field_name: "shell.php%00.jpg"},
                "target_param": field_name,
                "expected_status": [200, 201],
                "priority": "high",
                "severity": "high",
                "success_indicators": {"status_codes": [200, 201]},
                "expected_indicators": {"status_codes": [200, 201]},
                "remediation": file_upload_profile.remediation,
                "references": file_upload_profile.references,
                "attack_subtype": "null_byte"
            })
            
            # File size validation bypass
            attacks.append({
                "type": "file_upload",
                "name": "File Size Validation Bypass",
                "profile_name": file_upload_profile.name,
                "description": "Attempt to bypass file size validation limits",
                "endpoint": path,
                "method": method,
                "field": field_name,
                "location": location,
                "payloads": ["oversized_file"],
                "payload": {field_name: "oversized_file"},
                "target_param": field_name,
                "expected_status": 413,
                "priority": "medium",
                "severity": "medium",
                "success_indicators": {"status_codes": [200, 201]},
                "expected_indicators": {"status_codes": [200, 201]},
                "remediation": file_upload_profile.remediation,
                "references": file_upload_profile.references,
                "attack_subtype": "size_bypass"
            })
        
        # Limit to top high-severity attacks
        attacks.sort(key=self._attack_sort_key)
        return attacks[:10]
