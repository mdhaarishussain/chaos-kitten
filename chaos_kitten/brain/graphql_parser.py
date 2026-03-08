"""GraphQL Schema Parser.

This module provides the `GraphQLParser` class, which parses GraphQL schemas
from live endpoints (introspection) or local files (.graphql/.json) and
converts them into a format compatible with the Chaos Kitten Attack Planner.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple
from urllib.parse import urlparse
import httpx

# Try to import graphql for SDL parsing
try:
    from graphql import build_schema, introspection_from_schema
    HAS_GRAPHQL_CORE = True
except ImportError:
    HAS_GRAPHQL_CORE = False

logger = logging.getLogger(__name__)


class GraphQLParser:
    """Parses GraphQL schemas from endpoints or local files."""

    # Standard Introspection Query to retrieve the full schema
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(self, endpoint_url: Optional[str] = None, schema_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize with either a live endpoint or local schema file.

        Args:
            endpoint_url: URL of the GraphQL API endpoint.
            schema_path: Path to a local .graphql or .json schema file.
        """
        self.endpoint_url = endpoint_url
        self.schema_path = Path(schema_path) if schema_path else None
        self.schema: Dict[str, Any] = {}

        if not self.endpoint_url and not self.schema_path:
            # We allow init without args technically if we plan to set late, 
            # but usually for this tool we want one. 
            # Requirements don't strictly forbid it, but let's be safe.
            pass

    def introspect(self) -> Dict[str, Any]:
        """Send introspection query to live endpoint, return schema.
        
        Returns:
            The introspection result (dict with __schema key).
        """
        if not self.endpoint_url:
            raise ValueError("No endpoint_url provided for introspection")

        try:
            logger.info(f"Introspecting GraphQL endpoint: {self.endpoint_url}")
            response = httpx.post(
                self.endpoint_url,
                json={"query": self.INTROSPECTION_QUERY},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data and data["errors"]:
                raise ValueError(f"GraphQL Introspection returned errors: {data['errors']}")

            if "data" not in data or "__schema" not in data["data"]:
                raise ValueError("Invalid introspection response: missing __schema")

            self.schema = data["data"]
            return self.schema

        except httpx.RequestError as e:
            logger.error(f"Network error interacting with GraphQL endpoint: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to introspect GraphQL endpoint: {e}")
            raise

    def parse_schema(self) -> Dict[str, Any]:
        """Parse a local .graphql or .json schema file.
        
        Returns:
            The parsed schema dictionary.
        """
        if not self.schema_path or not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")

        try:
            content = self.schema_path.read_text(encoding="utf-8")

            if self.schema_path.suffix == ".json":
                data = json.loads(content)
                # Check if it's wrapped in data or just schema
                if "data" in data and "__schema" in data["data"]:
                    self.schema = data["data"]
                elif "__schema" in data:
                    self.schema = data
                else:
                    raise ValueError("JSON file does not appear to be a standard introspection result (missing __schema)")

            elif self.schema_path.suffix in [".graphql", ".gql"]:
                if not HAS_GRAPHQL_CORE:
                    raise ImportError(
                        "graphql-core library is required to parse .graphql files. "
                        "Install it with 'pip install graphql-core'"
                    )

                # Parse SDL to schema object, then convert to introspection dict for consistency
                graphql_schema = build_schema(content)
                introspection_result = introspection_from_schema(graphql_schema)
                # introspection_from_schema returns the dict matching __schema structure directly?
                # Actually it typically returns {'__schema': ...} or just the schema obj.
                # Let's verify standard behavior. usually `introspection_from_schema` returns the schema part.
                # But to be safe and consistent with our self.schema expectation (containing __schema key at root?)
                # Wait, self.schema = data["data"] where data["data"] has "__schema".
                # So self.schema should contain "__schema".
                
                # introspection_from_schema returns a dict with "__schema" key?
                # No, it returns the schema dict. let's check.
                # Check `graphql.utilities.introspection_from_schema` doc or assume standard.
                # Assuming it returns the Dict that usually goes under "data".
                
                self.schema = introspection_result

            else:
                raise ValueError(f"Unsupported file extension: {self.schema_path.suffix}")

            return self.schema

        except Exception as e:
            logger.error(f"Failed to parse schema file: {e}")
            raise

    def get_queries(self) -> List[Dict[str, Any]]:
        """Extract all Query type fields with arguments."""
        if not self.schema:
            return []

        query_type_name = self.schema["__schema"].get("queryType", {}).get("name", "Query")
        return self._get_fields_for_type(query_type_name)

    def get_mutations(self) -> List[Dict[str, Any]]:
        """Extract all Mutation type fields with arguments."""
        if not self.schema:
            return []

        mutation_type_obj = self.schema["__schema"].get("mutationType")
        if not mutation_type_obj:
            return []

        mutation_type_name = mutation_type_obj.get("name", "Mutation")
        return self._get_fields_for_type(mutation_type_name)

    def get_types(self) -> List[Dict[str, Any]]:
        """Extract all custom types with their fields."""
        if not self.schema:
            return []

        types = []
        for type_def in self.schema["__schema"]["types"]:
            if type_def["kind"] == "OBJECT" and not type_def["name"].startswith("__"):
                types.append(type_def)
        return types

    def _get_fields_for_type(self, type_name: str) -> List[Dict[str, Any]]:
        fields = []
        types = self.schema["__schema"]["types"]

        target_type = next((t for t in types if t["name"] == type_name), None)
        if not target_type or "fields" not in target_type or not target_type["fields"]:
            return []

        for field in target_type["fields"]:
            fields.append({
                "name": field["name"],
                "description": field.get("description"),
                "args": [
                    {
                        "name": arg["name"],
                        "type": self._resolve_type_name(arg["type"]),
                        "required": arg["type"]["kind"] == "NON_NULL"
                    }
                    for arg in field.get("args", [])
                ],
                "type": self._resolve_type_name(field["type"])
            })
        return fields

    def _resolve_type_name(self, type_ref: Optional[Dict[str, Any]]) -> str:
        """Helper to reconstruct type signature (e.g. String!, [User])."""
        if not type_ref:
            return "Unknown"

        kind = type_ref.get("kind")
        name = type_ref.get("name")
        of_type = type_ref.get("ofType")

        if kind == "NON_NULL":
            return f"{self._resolve_type_name(of_type)}!"
        elif kind == "LIST":
            return f"[{self._resolve_type_name(of_type)}]"
        else:
            return name if name else "Unknown"

    def to_endpoints(self) -> List[Dict[str, Any]]:
        """Convert GraphQL operations to endpoint-like format for the AttackPlanner."""
        endpoints = []

        path = "/graphql"
        if self.endpoint_url:
            parsed = urlparse(self.endpoint_url)
            path = parsed.path

        # Add Mutation operations
        mutations = self.get_mutations()
        for op in mutations:
            endpoints.append({
                "path": path,
                "method": "POST",
                "operation": f"mutation {op['name']}",
                "fields": op["args"]  # Already has name, type, required
            })

        # Add Query operations
        queries = self.get_queries()
        for op in queries:
            endpoints.append({
                "path": path,
                "method": "POST",  # Queries are typically POSTed
                "operation": f"query {op['name']}",
                "fields": op["args"]
            })

        return endpoints
