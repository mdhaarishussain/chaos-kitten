import glob

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
import logging
import json
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
import yaml

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
    """Plan attacks based on API structure and context.

    Uses LLM reasoning to:
    - Understand endpoint semantics
    - Select appropriate attack profiles
    - Plan multi-step attack chains
    - Adapt based on responses
    """
    
    def __init__(self, endpoints: list[dict[str, Any]], toys_path: str = "toys/",llm_provider: str = "anthropic",temperature: float = 0.7) -> None:
        """Initialize the attack planner.

        Args:
            endpoints: List of parsed API endpoints
            toys_path: Path to the attack profiles directory
        """
        self.endpoints = endpoints
        self.toys_path = toys_path
        self.attack_profiles: list[dict[str, Any]] = []
        self._cache: dict[str, Any] = {}
        self.llm_provider=llm_provider.lower()
        self.temperature=temperature
        self.llm=self._init_llm()
        self.load_attack_profiles()
    def _init_llm(self)->Any:
        if self.llm_provider=='anthropic':
            return ChatAnthropic(model="claude-3-5-sonnet-20241022",temperature=self.temperature)
        elif self.llm_provider=='openai':
            return ChatOpenAI(model="gpt-4",temperature=self.temperature)
        elif self.llm_provider == "ollama":
            return ChatOllama(model="llama3.1", temperature=self.temperature)
        else:
            logger.warning(f"Unknown LLM provider {self.llm_provider}. Falling back to Claude.")
            return ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=self.temperature)
        
    
    def load_attack_profiles(self) -> None:
        """Load all attack profiles from the toys directory."""
        search_path = os.path.join(self.toys_path, "*.yaml")
        yaml_files = glob.glob(search_path)

        if not yaml_files:
            logger.warning(f"No attack profiles found in {self.toys_path}")
            return

        for file_path in yaml_files:
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data:
                    logger.warning(f"Skipping empty file: {file_path}")
                    continue

                # Basic validation of required fields
                required_fields = [
                    "name",
                    "category",
                    "severity",
                    "payloads",
                    "target_fields",
                ]
                missing = [field for field in required_fields if field not in data]

                if missing:
                    logger.warning(
                        f"Skipping {file_path}: Missing required fields {missing}"
                    )
                    continue

                profile = AttackProfile(
                    name=data["name"],
                    category=data["category"],
                    severity=data["severity"],
                    description=data.get("description", ""),
                    payloads=data["payloads"],
                    target_fields=data["target_fields"],
                    success_indicators=data.get("success_indicators", {}),
                    remediation=data.get("remediation", ""),
                    references=data.get("references", []),
                )
                self.attack_profiles.append(profile)
                logger.debug(f"Loaded attack profile: {profile.name}")

            except Exception as e:
                logger.error(f"Failed to load attack profile from {file_path}: {e}")

        logger.info(f"Loaded {len(self.attack_profiles)} attack profiles")

    def plan_attacks(self, endpoint: dict[str, Any]) -> list[dict[str, Any]]:
        """Plan attacks for a specific endpoint.

        Args:
            endpoint: Endpoint definition from OpenAPI parser.
                      Expected structure:
                      {
                          "path": "/api/login",
                          "method": "post",
                          "parameters": [...],
                          "requestBody": {...}
                      }

        Returns:
            List of planned attacks with payloads and expected behaviors:
            [
                {
                    "profile_name": str,
                    "endpoint": str,
                    "method": str,
                    "field": str,
                    "location": str (query/path/body),
                    "payloads": list[str],
                    "expected_indicators": dict,
                    "severity": str
                },
                ...
            ]
        """
        
        
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        params = endpoint.get("parameters", [])
        body = endpoint.get("requestBody", {})
        cache_key = f"{method}:{path}:{json.dumps(params, sort_keys=True)}:{json.dumps(body, sort_keys=True)}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        prompt = ChatPromptTemplate.from_template(ATTACK_PLANNING_PROMPT)
        parser=JsonOutputParser()
        chain = prompt | self.llm | parser
        attacks = []
        
        # 1. Attempt LLM Planning
        try:
            prompt = ChatPromptTemplate.from_template(ATTACK_PLANNING_PROMPT)
            parser = JsonOutputParser()
            chain = prompt | self.llm | parser
            
            generated_attacks = chain.invoke({
                "method": method,
                "path": path,
                "parameters": json.dumps(params),
                "body": json.dumps(body)
            })
            
            if isinstance(generated_attacks, list):
                priority_map = {"high": 0, "medium": 1, "low": 2}
                generated_attacks.sort(key=lambda x: priority_map.get(str(x.get("priority", "low")).lower(), 3))
                attacks = generated_attacks
                logger.info(f"LLM generated {len(attacks)} attack vectors for {method} {path}")
                
        except Exception as e:
            logger.warning(f"LLM attack planning failed for {path}: {str(e)}. Falling back to rule-based profiles.")
            
            if not self.attack_profiles:
                target = "q" if params else "body"
                attacks.append({
                    "type": "sql_injection",
                    "name": "Fallback SQLi Probe",
                    "description": "Basic SQL injection test (No profiles loaded)",
                    "payload": {target: "' OR 1=1 --"},
                    "target_param": target,
                    "expected_status": 500,
                    "priority": "high"
                })
            else:
                param_names = [p.get("name") for p in params if isinstance(p, dict)]
                
                for profile in self.attack_profiles:
                    payload_target = None
                    
                    if params and "query" in profile.target_fields:
                        payload_target = param_names[0] if param_names else "q"
                    elif body and "body" in profile.target_fields:
                        payload_target = "body"
                        
                    if payload_target:
                        attacks.append({
                            "type": profile.category,
                            "name": profile.name,
                            "description": profile.description,
                            "payload": {payload_target: profile.payloads[0] if profile.payloads else "TEST"},
                            "target_param": payload_target,
                            "expected_status": 400,
                            "priority": profile.severity
                        })

        self._cache[cache_key] = attacks  
        return attacks
    def suggest_payloads(self, attack_type: str, context: dict[str, Any]) -> list[str]:
        """Generate context-specific payloads using LLM intelligence."""
        prompt = ChatPromptTemplate.from_template(PAYLOAD_SUGGESTION_PROMPT)
        chain = prompt | self.llm | JsonOutputParser()
        
        try:
            payloads = chain.invoke({
                "attack_type": attack_type,
                "context": json.dumps(context)
            })
            if isinstance(payloads, list):
                return payloads
        except Exception as e:
            logger.warning(f"LLM payload suggestion failed: {e}")
            
        # fallback
        return ["' OR 1=1 --", "<script>alert(1)</script>", "../../../etc/passwd"]
    def reason_about_field(self, field_name: str, field_type: str) -> str:
        """Use LLM to reason about potential vulnerabilities for a field.

        Example:
            field_name="age", field_type="integer"
            Returns: "I'll test negative numbers, zero, extremely large values, and strings"

        Args:
            field_name: Name of the field
            field_type: Data type of the field

        Returns:
            Reasoning about what to test"""
        
        prompt = ChatPromptTemplate.from_template(REASONING_PROMPT)
        chain = prompt | self.llm
        
        try:
            response = chain.invoke({
                "field_name": field_name,
                "field_type": field_type
            })
            return response.content
        except Exception as e:
            logger.warning(f"LLM field reasoning failed: {e}")
            return f"Test '{field_name}' of type '{field_type}' with boundary values and injection strings."
