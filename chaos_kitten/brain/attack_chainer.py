"""Multi-Endpoint Attack Chain Orchestration."""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from langchain_core.language_models import BaseChatModel
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate

logger = logging.getLogger(__name__)

class EndpointGraph:
    """Builds a directed graph of endpoints based on shared parameters and response fields."""
    
    def __init__(self, endpoints: List[Dict[str, Any]]):
        self.endpoints = endpoints
        self.graph = defaultdict(list)
        self._build_graph()
        
    def _build_graph(self):
        """Build the graph by finding endpoints that output fields required by other endpoints."""
        # Map field names to endpoints that produce them in responses
        producers = defaultdict(list)
        # Map field names to endpoints that consume them in requests
        consumers = defaultdict(list)
        
        for i, ep in enumerate(self.endpoints):
            # Find consumed fields
            for param in ep.get("parameters", []):
                name = param.get("name")
                if name:
                    consumers[name.lower()].append(i)
            
            req_body = ep.get("requestBody", {})
            if req_body:
                content = req_body.get("content", {})
                for _media_type, media_obj in content.items():
                    schema = media_obj.get("schema", {})
                    properties = schema.get("properties", {})
                    for prop_name in properties.keys():
                        consumers[prop_name.lower()].append(i)
            
            # Find produced fields
            responses = ep.get("responses", {})
            for status, resp_obj in responses.items():
                if not str(status).startswith("2"):
                    continue
                content = resp_obj.get("content", {})
                for _media_type, media_obj in content.items():
                    schema = media_obj.get("schema", {})
                    properties = schema.get("properties", {})
                    for prop_name in properties.keys():
                        producers[prop_name.lower()].append(i)
                        
        # Create edges from producers to consumers
        # Use a set to avoid duplicate edges if multiple fields map between the same endpoints
        seen_edges = set()
        for field, prod_list in producers.items():
            if field in consumers:
                for p in prod_list:
                    for c in consumers[field]:
                        if p != c:
                            edge_key = (p, c, field)
                            if edge_key not in seen_edges:
                                seen_edges.add(edge_key)
                                # Add edge p -> c with the shared field
                                self.graph[p].append({"target": c, "field": field})

    def get_graph_summary(self) -> str:
        """Return a string summary of the graph for the LLM."""
        summary = []
        for i, ep in enumerate(self.endpoints):
            summary.append(f"[{i}] {ep.get('method', 'UNKNOWN')} {ep.get('path', '/')}")
            edges = self.graph.get(i, [])
            if edges:
                targets = set(f"[{e['target']}] (via {e['field']})" for e in edges)
                summary.append(f"  -> Feeds into: {', '.join(targets)}")
        return "\n".join(summary)


CHAIN_PLANNER_PROMPT = """You are an expert penetration tester.
Given the following API endpoints and their data flow graph, propose {max_chain_depth}-step attack chains that could expose authorization flaws or business logic vulnerabilities.
A chain is a sequence of up to {max_chain_depth} endpoints where the output of one step is used as input for the next.

API Graph:
{graph_summary}

Endpoints Details:
{endpoints_details}

Return ONLY a JSON array of attack chains. Each chain must have:
- "name": A short name for the attack chain.
- "description": What the chain attempts to achieve.
- "steps": An array of up to {max_chain_depth} objects, each containing:
  - "endpoint_index": The integer index of the endpoint.
  - "method": The HTTP method.
  - "path": The endpoint path.
  - "extracts": A dictionary mapping a response field name to a variable name (e.g., {{"id": "user_id"}}).
  - "injects": A dictionary mapping a variable name to a request parameter/body field (e.g., {{"user_id": "id"}}).

Example:
[
  {{
    "name": "IDOR via User Creation",
    "description": "Create a user, get their ID, and try to access another user's orders.",
    "steps": [
      {{
        "endpoint_index": 0,
        "method": "POST",
        "path": "/users",
        "extracts": {{"id": "user_id"}},
        "injects": {{}}
      }},
      {{
        "endpoint_index": 1,
        "method": "GET",
        "path": "/users/{{user_id}}/orders",
        "extracts": {{"order_id": "order_id"}},
        "injects": {{"user_id": "user_id"}}
      }},
      {{
        "endpoint_index": 2,
        "method": "DELETE",
        "path": "/orders/{{order_id}}",
        "extracts": {{}},
        "injects": {{"order_id": "order_id"}}
      }}
    ]
  }}
]
"""

class AttackChainPlanner:
    """Plans multi-step attack chains using an LLM."""
    
    def __init__(self, llm: BaseChatModel):
        self.llm = llm
        
    async def plan_chains(self, endpoints: List[Dict[str, Any]], max_chain_depth: int = 4) -> List[Dict[str, Any]]:
        """Generate attack chains based on the endpoint graph."""
        graph = EndpointGraph(endpoints)
        graph_summary = graph.get_graph_summary()
        
        endpoints_details = []
        for i, ep in enumerate(endpoints):
            endpoints_details.append(f"[{i}] {ep.get('method', 'UNKNOWN')} {ep.get('path', '/')}")
            
        prompt = ChatPromptTemplate.from_template(CHAIN_PLANNER_PROMPT)
        chain = prompt | self.llm | JsonOutputParser()
        
        try:
            result = await chain.ainvoke({
                "graph_summary": graph_summary,
                "endpoints_details": "\n".join(endpoints_details),
                "max_chain_depth": max_chain_depth
            })
            if isinstance(result, list):
                return result
            return []
        except Exception as e:
            logger.exception("Failed to plan attack chains")
            return []

class ChainExecutor:
    """Executes a planned attack chain, substituting variables."""
    
    def __init__(self, executor):
        self.executor = executor
        
    async def execute_chain(self, chain: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        """Execute a chain of attacks."""
        variables = {}
        results = []
        errors = []
        
        for i, step in enumerate(chain.get("steps", [])):
            try:
                method = step.get("method")
                path = step.get("path")
                
                # Substitute variables in path
                for var_name, var_value in variables.items():
                    path = path.replace(f"{{{var_name}}}", str(var_value))
                    
                # Prepend base_url if path is relative
                if base_url and path.startswith("/"):
                    full_url = f"{base_url.rstrip('/')}{path}"
                else:
                    full_url = path
                    
                # Prepare payload with injected variables
                payload = {}
                for var_name, field_name in step.get("injects", {}).items():
                    if var_name in variables:
                        payload[field_name] = variables[var_name]
                    else:
                        logger.warning(f"Missing variable '{var_name}' for step {i}, payload may be incomplete")
                        
                # Execute attack
                response = await self.executor.execute_attack(method, full_url, payload)
                
                # Check for execution error
                if response.get("error"):
                    errors.append({
                        "step_index": i,
                        "status": "failed",
                        "step": step,
                        "error": response["error"]
                    })
                    continue

                # Extract variables from response
                body = response.get("body", {})
                if isinstance(body, str):
                    try:
                        body = json.loads(body)
                    except json.JSONDecodeError:
                        body = {}
                        
                if isinstance(body, dict):
                    for field_name, var_name in step.get("extracts", {}).items():
                        if field_name in body:
                            variables[var_name] = body[field_name]
                            
                results.append({
                    "step_index": i,
                    "status": "success",
                    "step": step,
                    "request": {"method": method, "path": full_url, "payload": payload},
                    "response": response
                })
            except Exception as e:
                errors.append({
                    "step_index": i,
                    "status": "failed",
                    "step": step,
                    "error": str(e)
                })
                # Continue to next step instead of aborting
                continue
            
        return {
            "chain": chain,
            "successful": results,
            "failed": errors,
            "partial_success": len(results) > 0 and len(errors) > 0
        }
