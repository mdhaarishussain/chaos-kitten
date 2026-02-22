"""Adaptive payload generation using LLM based on response analysis."""

import json
import logging
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate

logger = logging.getLogger(__name__)

ADAPTIVE_GENERATION_PROMPT = """You are an expert penetration tester performing adaptive fuzzing.
Target Endpoint: {method} {path}
Previous Payload: {previous_payload}
Response Status: {status_code}
Response Body (truncated): {response_body}

The previous payload resulted in the detailed response above.
Analyze this response (headers, body structure, field types, error messages) and dynamically generate 5 more targeted attack payloads.
Focus on:
1. Adaptive mutation: If you see "price": 9.99, try negative values, large numbers, strings, SQLi, etc.
2. Escalation: If you see a specific error message (e.g., "SQL syntax error"), target that vulnerability specifically.
3. Context: potential implementation details leaked in the response.

Return ONLY a JSON array of 5 payload strings. Example:
["{\"price\": -100}", "{\"quantity\": 0}"]
"""


class AdaptivePayloadGenerator:
    """Generates adaptive payloads based on probe responses."""

    def __init__(self, llm: BaseChatModel, max_rounds: int = 3):
        """Initialize the generator.

        Args:
            llm: The language model to use.
            max_rounds: Maximum number of adaptive rounds (not strictly enforced here, but good context).
        """
        self.llm = llm
        self.max_rounds = max_rounds

    async def generate_payloads(
        self,
        endpoint: Dict[str, Any],
        previous_payload: Any,
        response: Dict[str, Any],
    ) -> List[str]:
        """Generate adaptive payloads based on the response to a previous payload.

        Args:
            endpoint: Endpoint definition (method, path).
            previous_payload: The payload that caused the response.
            response: The response data (status_code, body).

        Returns:
            List of generated payloads (strings).
        """
        try:
            prompt = ChatPromptTemplate.from_template(ADAPTIVE_GENERATION_PROMPT)
            chain = prompt | self.llm | JsonOutputParser()

            # Truncate response body if too long
            body_str = str(response.get("body", ""))
            if len(body_str) > 2000:
                body_str = body_str[:2000] + "... (truncated)"

            payload_str = str(previous_payload)
            
            result = await chain.ainvoke(
                {
                    "method": endpoint.get("method", "GET"),
                    "path": endpoint.get("path", ""),
                    "previous_payload": payload_str,
                    "status_code": response.get("status_code", 0),
                    "response_body": body_str,
                }
            )

            if isinstance(result, list):
                 # Ensure all items are strings
                return [str(item) for item in result]
            
            logger.warning("Adaptive generation returned non-list format: %s", type(result))
            return []

        except Exception as e:
            logger.error("Failed to generate adaptive payloads: %s", e)
            return []
