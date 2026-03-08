"""Attack planning logic for Chaos Kitten."""

from __future__ import annotations

import glob
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Set

import yaml
# Moving langchain imports to local scope to prevent crashes during pre-flight checks

logger = logging.getLogger(__name__)


@dataclass
class AttackProfile:
    """Represents a loaded attack profile from a YAML file."""

    name: str
    category: str
    severity: str
    description: str
    payloads: List[str]
    target_fields: List[str]
    success_indicators: Dict[str, Any]
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    workflow: List[Dict[str, Any]] = field(default_factory=list)
    concurrency: Dict[str, Any] = field(default_factory=dict)
    target_paths: List[str] = field(default_factory=list)
    supported_languages: List[str] = field(default_factory=list)


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
        endpoints: List[Dict[str, Any]],
        toys_path: str = "toys/",
        llm_provider: str = "anthropic",
        temperature: float = 0.7,
    ) -> None:
        self.endpoints = endpoints
        self.toys_path = toys_path
        self.attack_profiles: List[AttackProfile] = []
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self.llm_provider = llm_provider.lower()
        self.temperature = temperature
        self.llm = self._init_llm()
        self.load_attack_profiles()

    def _init_llm(self) -> Any:
        from langchain_anthropic import ChatAnthropic
        from langchain_openai import ChatOpenAI
        from langchain_ollama import ChatOllama

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
                ]
                missing = [field_name for field_name in required_fields if field_name not in data]

                if missing:
                    logger.warning(
                        "Skipping %s: Missing required fields %s", file_path, missing
                    )
                    continue

                payloads = data.get("payloads") or []
                target_fields = data.get("target_fields") or []
                workflow = data.get("workflow") or []
                concurrency = data.get("concurrency") or {}

                if not (payloads and target_fields) and not workflow and not concurrency:
                    logger.warning(
                        "Skipping %s: Must contain either payloads/target_fields or workflow or concurrency definition",
                        file_path,
                    )
                    continue

                if (payloads and not isinstance(payloads, list)) or (target_fields and not isinstance(target_fields, list)):
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
                    workflow=workflow,
                    concurrency=concurrency,
                    target_paths=data.get("target_paths") or [],
                    supported_languages=[str(lang).lower() for lang in (data.get("supported_languages", []) or [])],
                )
                self.attack_profiles.append(profile)
                logger.debug("Loaded attack profile: %s", profile.name)
            except Exception as exc:
                logger.error(
                    "Failed to load attack profile from %s: %s", file_path, exc
                )

        logger.info("Loaded %d attack profiles", len(self.attack_profiles))

    def plan_attacks(self, endpoint: Dict[str, Any], allowed_profiles: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Plan attacks for a specific endpoint.
        
        Args:
            endpoint: The API endpoint to plan attacks for
            allowed_profiles: Optional list of profile names to filter attacks by
        
        Returns:
            List of planned attack dictionaries
        """
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

        attacks: List[Dict[str, Any]] = []
        try:
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import JsonOutputParser
            
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
        
        # Filter by allowed profiles if specified
        if allowed_profiles:
            attacks = [
                a for a in attacks
                if a.get("profile_name") in allowed_profiles
            ]
        
        return attacks

    def _normalize_llm_attacks(
        self, generated_attacks: List[Dict[str, Any]], endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "")
        normalized: List[Dict[str, Any]] = []

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

            payload_values: List[str]
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

    def _plan_rule_based(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "")
        fields = self._extract_endpoint_fields(endpoint)
        detected_languages = self._detect_serialization_languages(endpoint)

        attacks: List[Dict[str, Any]] = []
        for profile in self.attack_profiles:
            # If the profile defines supported languages and the endpoint doesn't match, skip it
            if profile.supported_languages:
                if not detected_languages.intersection(profile.supported_languages):
                    continue

            # Special handling for Business Logic / Workflow / Concurrency
            if profile.workflow or profile.concurrency:
                # Check path match
                path_match = False
                if profile.target_paths:
                    for tp in profile.target_paths:
                        try:
                            if re.search(tp, path):
                                path_match = True
                                break
                        except re.error:
                            if tp in path:
                                path_match = True
                                break
                
                # Check field match
                field_match = False
                matched_field = None
                matched_location = None
                
                if not path_match and profile.target_fields:
                    for field_name, location in fields:
                        if any(
                            self._field_matches_target(field_name, target)
                            for target in profile.target_fields
                        ):
                            field_match = True
                            matched_field = field_name
                            matched_location = location
                            break
                
                if path_match or field_match:
                    indicators = profile.success_indicators or {}
                    attacks.append({
                        "type": profile.category,
                        "name": profile.name,
                        "profile_name": profile.name,
                        "description": profile.description,
                        "endpoint": path,
                        "path": path,
                        "method": method,
                        "field": matched_field or "N/A",  # Might be N/A for path-based
                        "location": matched_location or "N/A",
                        "workflow": profile.workflow,
                        "concurrency": profile.concurrency,
                        "payloads": [], # No payloads for logic attacks usually
                        "payload": {},
                        "target_param": matched_field or "N/A",
                        "expected_status": self._expected_status(indicators),
                        "priority": self._severity_to_priority(profile.severity),
                        "severity": profile.severity,
                        "success_indicators": indicators,
                        "expected_indicators": indicators,
                        "remediation": profile.remediation,
                        "references": profile.references,
                    })
                continue

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

        unique_attacks: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str, str]] = set()
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

    def _detect_serialization_languages(self, endpoint: Dict[str, Any]) -> Set[str]:
        languages = set()
        
        # Check overall path for language extensions
        path = str(endpoint.get("path", "")).lower()
        if path.endswith(".php"):
            languages.add("php")
        elif path.endswith(".jsp") or path.endswith(".do") or path.endswith(".action"):
            languages.add("java")
        elif path.endswith(".py"):
            languages.add("python")
        elif path.endswith(".rb") or "rails" in path:
            languages.add("ruby")

        # Check Content-Type headers in requestBody
        request_body = endpoint.get("requestBody") or {}
        content = request_body.get("content", {})
        for content_type, _ in content.items():
            ct_lower = content_type.lower()
            if "java-serialized" in ct_lower:
                languages.add("java")
            elif "python-pickle" in ct_lower or "x-python" in ct_lower:
                languages.add("python")
            elif "php-serialized" in ct_lower or "x-php" in ct_lower:
                languages.add("php")
            elif "ruby-marshal" in ct_lower or "x-ruby" in ct_lower:
                languages.add("ruby")
                
        # Check specific parameter names indicating serialization
        for param in endpoint.get("parameters", []):
            if isinstance(param, dict):
                name = str(param.get("name", "")).lower()
                if "java" in name and ("obj" in name or "serial" in name):
                    languages.add("java")
                if "pickle" in name:
                    languages.add("python")
                if "php" in name and ("serial" in name or "obj" in name):
                    languages.add("php")
                if "marshal" in name:
                    languages.add("ruby")
                
        return languages

    def _extract_endpoint_fields(self, endpoint: Dict[str, Any]) -> List[Tuple[str, str]]:
        fields: List[Tuple[str, str]] = []

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
                # Removed broken logic that tried to use targetable_fields before definition
                fields.append((str(prop_name), "body"))

        if not fields:
            fields.append(("q", "query"))

        deduped: List[Tuple[str, str]] = []
        seen_fields: set[Tuple[str, str]] = set()
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

    def _build_payload(self, field_name: str, location: str, payload: str) -> Dict[str, Any]:
        # Executor handles GET payload as query params and POST/PUT/PATCH payload as JSON.
        # Keeping a dict shape across locations is the most compatible contract here.
        return {field_name: payload}

    def _expected_status(self, indicators: Dict[str, Any]) -> int:
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

    def _attack_sort_key(self, attack: Dict[str, Any]) -> Tuple[int, str]:
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

    def suggest_payloads(self, attack_type: str, context: Dict[str, Any]) -> List[str]:
        """Generate context-specific payloads using LLM intelligence."""
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import JsonOutputParser
        
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
        from langchain_core.prompts import ChatPromptTemplate
        
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


# Default profile list for fallback when toys directory is not accessible
default_profiles = [
    "SQL Injection - Basic",
    "XSS - Reflected",
    "IDOR - Basic",
    "BOLA - Broken Object Level Authorization",
    "Command Injection",
    "Path Traversal",
    "XXE Injection",
    "SSRF"
]

# Natural Language Attack Targeting Prompt
NATURAL_LANGUAGE_PLANNING_PROMPT = """You are a security expert tasked with identifying which API endpoints are most relevant to test for a specific security goal.

User's Goal: {goal}

Available Endpoints:
{endpoints}

Available Attack Profiles:
{profiles}

Analyze the user's goal and identify:
1. Which endpoints are most relevant to this goal (ranked by relevance)
2. Which attack profiles should be applied to these endpoints
3. Custom payload focus areas or testing priorities specific to this goal

You must respond ONLY with valid JSON (no markdown, no explanations outside JSON):
{{
    "endpoints": [
        {{
            "method": "POST",
            "path": "/api/checkout",
            "relevance_score": 0.95,
            "reason": "Handles payment processing, critical for price manipulation testing"
        }}
    ],
    "profiles": ["IDOR - Basic", "Mass Assignment / Parameter Pollution", "BOLA - Broken Object Level Authorization"],
    "focus": "Test for price/quantity manipulation in cart and checkout flows. Pay special attention to total calculation bypass and discount abuse."
}}

Remember: respond only with valid JSON matching the schema above. Do not include any explanatory text.
"""


class NaturalLanguagePlanner:
    """Plans attacks based on natural language goals."""

    def __init__(self, endpoints: List[Dict[str, Any]], config: Dict[str, Any]):
        """Initialize the NL planner.

        Args:
            endpoints: List of all available API endpoints
            config: Application configuration with LLM settings
        """
        self.endpoints = endpoints
        self.config = config
        self.llm = self._init_llm()

    def _init_llm(self):
        """Initialize the LLM based on config."""
        agent_config = self.config.get("agent", {})
        provider = agent_config.get("llm_provider", "anthropic").lower()
        temperature = agent_config.get("temperature", 0.7)
        
        # Provider-specific default models
        default_models = {
            "openai": "gpt-4o",
            "anthropic": "claude-3-5-sonnet-20241022",
            "ollama": "llama3",
        }
        model = agent_config.get("model", default_models.get(provider, "claude-3-5-sonnet-20241022"))

        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model, temperature=temperature)
        elif provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=model, temperature=temperature)
        elif provider == "ollama":
            from langchain_ollama import ChatOllama
            return ChatOllama(model=model, temperature=temperature)
        else:
            logger.warning("Unknown provider %s, defaulting to Anthropic", provider)
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model, temperature=temperature)

    def plan(self, goal: str) -> Dict[str, Any]:
        """Plan attacks based on natural language goal.

        Args:
            goal: User's natural language security goal

        Returns:
            Dictionary with:
                - endpoints: List of relevant endpoints with relevance scores
                - profiles: List of attack profile names to apply
                - focus: Custom payload focus description
                - reasoning: LLM's reasoning (for logging)
        """
        # Load available attack profiles
        attack_profiles = self._load_available_profiles()

        # Format endpoints for LLM
        endpoints_str = json.dumps(
            [
                {
                    "method": ep.get("method", "GET"),
                    "path": ep.get("path", ""),
                    "params": [p.get("name", "") for p in ep.get("parameters", []) if isinstance(p, dict)],
                    "body": list(((ep.get("requestBody") or {}).get("content", {}).get("application/json", {}).get("schema", {}).get("properties", {})).keys()),
                }
                for ep in self.endpoints
            ],
            indent=2
        )

        profiles_str = json.dumps(attack_profiles, indent=2)

        # Create prompt
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import JsonOutputParser
        
        prompt = ChatPromptTemplate.from_template(NATURAL_LANGUAGE_PLANNING_PROMPT)
        parser = JsonOutputParser()
        chain = prompt | self.llm | parser

        try:
            logger.info(f"[GOAL] Planning attacks for goal: {goal}")
            result = chain.invoke({
                "goal": goal,
                "endpoints": endpoints_str,
                "profiles": profiles_str
            })

            # Log the reasoning
            if result.get("endpoints"):
                logger.info(f"[GOAL] LLM selected {len(result['endpoints'])} relevant endpoints")
                for ep in result.get("endpoints", [])[:3]:  # Log top 3
                    score = ep.get('relevance_score', 0)
                    # Convert to float safely
                    try:
                        score_val = float(score)
                    except (TypeError, ValueError):
                        score_val = 0.0
                    logger.info(
                        f"[GOAL]   - {ep.get('method')} {ep.get('path')} "
                        f"(score: {score_val:.2f})"
                    )

            if result.get("focus"):
                logger.info(f"[GOAL] Focus area: {result['focus']}")

            # Add reasoning for return
            result["reasoning"] = f"LLM analysis for goal: '{goal}'"

            return result

        except Exception:
            logger.exception("[GOAL] Natural language planning failed")
            # Fallback: return all endpoints with no filtering
            return {
                "endpoints": [
                    {
                        "method": ep.get("method", "GET"),
                        "path": ep.get("path", ""),
                        "relevance_score": 0.5,
                        "reason": "Fallback: LLM planning failed"
                    }
                    for ep in self.endpoints
                ],
                "profiles": ["SQL Injection - Basic", "XSS - Reflected", "IDOR - Basic"],
                "focus": "Standard security testing (LLM planning unavailable)",
                "reasoning": "Fallback: LLM planning failed"
            }

    def _load_available_profiles(self) -> List[str]:
        """Load list of available attack profile names."""
        try:
            import os as _os
            module_dir = _os.path.dirname(_os.path.abspath(__file__))
            package_root = _os.path.dirname(_os.path.dirname(module_dir))
            toys_dir = _os.path.join(package_root, "toys")
            profile_files = glob.glob(_os.path.join(toys_dir, "*.yaml"))
            if not profile_files:
                return default_profiles
            
            # Load YAML name fields to match attack dict profile_name values
            profile_names = []
            for profile_file in profile_files:
                try:
                    with open(profile_file, 'r') as f:
                        profile_data = yaml.safe_load(f)
                        name = profile_data.get("name", _os.path.basename(profile_file).replace(".yaml", ""))
                        profile_names.append(name)
                except Exception:
                    # Fallback to file-stem if YAML read fails
                    profile_names.append(_os.path.basename(profile_file).replace(".yaml", ""))
            
            return profile_names if profile_names else default_profiles
        except Exception:
            return default_profiles


