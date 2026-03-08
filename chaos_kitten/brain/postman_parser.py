from __future__ import annotations

"""Postman Collection v2.1.0 parser.

This module provides the `PostmanParser` class, which parses Postman Collection
JSON files into a normalized format for downstream use by the attack planner 
and orchestrator, mimicking the output of OpenAPIParser.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PostmanParser:
    """Parse Postman Collections to understand API structure.
    
    Supports Postman Collection v2.1.0 format.
    """

    def __init__(self, collection_path: Union[str, Path], environment_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize the parser.
        
        Args:
            collection_path (Union[str, Path]): Path to the Postman collection JSON file.
            environment_path (Optional[Union[str, Path]]): Path to the Postman environment JSON file.
        """
        self.collection_path = Path(collection_path)
        self.environment_path = Path(environment_path) if environment_path else None
        self.collection = {}
        self.environment = {}
        self._endpoints = []
        self._variables = {}

    def parse(self) -> Dict[str, Any]:
        """Parse the Postman collection file.
        
        Returns:
            Dict[str, Any]: The parsed collection dictionary.
        
        Raises:
            FileNotFoundError: If the collection file does not exist.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        if not self.collection_path.exists():
            raise FileNotFoundError(f"Collection file not found: {self.collection_path}")
        
        # Reset variables and endpoints before parsing to avoid stale data
        self._endpoints = []
        self._variables = {}
        
        try:
            with open(self.collection_path, 'r', encoding='utf-8') as f:
                self.collection = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Postman collection JSON: {e}")
            raise

        # 1. Load Collection Variables (defaults)
        if 'variable' in self.collection:
            for item in self.collection['variable']:
                if not item.get('disabled') and item.get('key'):
                    self._variables[item['key']] = item.get('value', '')
            
        if self.environment_path:
            if self.environment_path.exists():
                try:
                    with open(self.environment_path, 'r', encoding='utf-8') as f:
                        self.environment = json.load(f)
                        self._load_variables()
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse environment JSON: {e}")
            else:
                logger.warning(f"Environment file not found: {self.environment_path}")

        self._endpoints = [] # Reset endpoints
        self._extract_endpoints(self.collection.get('item', []))
        return self.collection

    def _load_variables(self) -> None:
        """Load variables from environment file."""
        if 'values' in self.environment:
            for item in self.environment['values']:
                if item.get('enabled', True):
                    self._variables[item['key']] = item['value']

    def _resolve_variables(self, text: str) -> str:
        """Resolve {{variable}} placeholders."""
        if not isinstance(text, str):
            return str(text) if text is not None else ""
        
        # Simple string replacement for known variables
        result = text
        for key, value in self._variables.items():
            pattern = f"{{{{{key}}}}}"
            if pattern in result:
                result = result.replace(pattern, str(value))
        
        return result

    def _extract_endpoints(self, items: List[Dict[str, Any]], parent_auth: Optional[Dict] = None, tags: Optional[List[str]] = None) -> None:
        """Recursively extract endpoints from Postman items.
        
        Args:
            items (List[Dict[str, Any]]): List of items (folders or requests).
            parent_auth (Optional[Dict]): Authorization inherited from parent folder.
            tags (Optional[List[str]]): List of parent folder names to use as tags.
        """
        if tags is None:
            tags = []

        for item in items:
            # Handle folder-level authentication if present
            current_auth = item.get('auth') or parent_auth
            name = item.get('name', '')
            
            if 'item' in item:
                # This is a folder
                new_tags = tags + [name] if name else tags
                self._extract_endpoints(item['item'], parent_auth=current_auth, tags=new_tags)
            elif 'request' in item:
                # This is a request
                endpoint = self._parse_request_item(item, current_auth, tags)
                if endpoint:
                    self._endpoints.append(endpoint)

    def _parse_request_item(self, item: Dict[str, Any], auth: Optional[Dict], tags: List[str]) -> Optional[Dict[str, Any]]:
        request = item['request']
        name = item.get('name', 'Untitled Request')
        
        # Method
        method = request.get('method', 'GET')
        
        # URL parsing
        url_obj = request.get('url', {})
        path = ""
        query_params = []
        variable_params = []
        
        if isinstance(url_obj, str):
            # Parse string URL
            resolved_url = self._resolve_variables(url_obj)
            parsed = urlparse(resolved_url)
            path = parsed.path
            # Parse query params from string URL
            if parsed.query:
                for pair in parsed.query.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query_params.append({
                            "name": k,
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "default": v}
                        })
                    else:
                        query_params.append({
                            "name": pair,
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "default": ""}
                        })
        else:
            # Parse object URL
            raw_url = url_obj.get('raw', '')
            path_segments = url_obj.get('path', [])
            
            if path_segments:
                # Reconstruct path from segments to avoid issues with host variables
                resolved_segments = [self._resolve_variables(seg) for seg in path_segments]
                path = "/" + "/".join(resolved_segments)
            else:
                resolved_url = self._resolve_variables(raw_url)
                parsed = urlparse(resolved_url)
                path = parsed.path

            # Extract query params
            for q in url_obj.get('query', []):
                if not q.get('disabled'):
                    query_params.append({
                        "name": q['key'],
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string", "default": self._resolve_variables(q.get('value', ''))}
                    })
            
            # Extract path variables
            for v in url_obj.get('variable', []):
                if not v.get('disabled') and v.get('key'):
                    variable_params.append({
                        "name": v['key'],
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "default": self._resolve_variables(v.get('value', ''))}
                    })

        # Postman often uses :param in path, convert to {param} for consistency with OpenAPI pattern
        path = re.sub(r':([a-zA-Z0-9_]+)', r'{\1}', path)

        # Infer any new path params that weren't explicitly defined in variables
        path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}', path)
        existing_params = {p['name'] for p in variable_params}
        for param in path_params:
            if param not in existing_params:
                variable_params.append({
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"}
                })

        # Headers
        header_params = []
        headers = request.get('header', [])
        # If headers is a string (rare but possible in some versions), ignore it or parse
        if isinstance(headers, list):
            for h in headers:
                if not h.get('disabled') and h['key'].lower() != "content-type": # Content-Type is handled in requestBody
                    header_params.append({
                        "name": h['key'],
                        "in": "header",
                        "required": False,
                        "schema": {"type": "string", "default": self._resolve_variables(h['value'])}
                    })
        
        # Body
        request_body = None
        if 'body' in request and request['body'].get('mode'):
            mode = request['body']['mode']
            content = {}
            
            if mode == 'raw':
                language = request['body'].get('options', {}).get('raw', {}).get('language', 'json')
                raw_data = self._resolve_variables(request['body'].get('raw', ''))
                
                # Default to text/plain, try to infer json
                content_type = "text/plain"
                schema = {"type": "string"}
                
                if language == "json":
                    content_type = "application/json"
                    # Try to parse example as schema if it's valid json
                    try:
                        json_data = json.loads(raw_data)
                        raw_data = json_data # Use parsed JSON object for example
                        # We won't generate a full schema from example here, just pass it as example
                        # Or use basic type inference if needed. For now, empty schema.
                        schema = {"type": "object"} 
                    except json.JSONDecodeError:
                        pass
                
                content[content_type] = {
                    "schema": schema, 
                    "example": raw_data
                }
            elif mode == 'urlencoded':
                data = request['body'].get('urlencoded', [])
                schema_props = {}
                for d in data:
                    if not d.get('disabled'):
                        schema_props[d['key']] = {"type": "string", "default": self._resolve_variables(d.get('value', ''))}
                content["application/x-www-form-urlencoded"] = {
                    "schema": {"type": "object", "properties": schema_props}
                }
            elif mode == 'formdata':
                data = request['body'].get('formdata', [])
                schema_props = {}
                for d in data:
                    if not d.get('disabled'):
                        param_type = d.get('type', 'text')
                        schema_props[d['key']] = {
                            "type": "string", 
                            "format": "binary" if param_type == "file" else "default",
                            "default": self._resolve_variables(d.get('value', '')) if param_type == 'text' else None
                        }
                content["multipart/form-data"] = {
                    "schema": {"type": "object", "properties": schema_props}
                }

            if content:
                request_body = {
                    "content": content
                }

        parameters = query_params + variable_params + header_params
        
        # Security
        security = []
        if auth:
            # Simple mapping of auth type
            auth_type = auth.get('type')
            if auth_type:
                security.append({auth_type: []})

        return {
            "path": self._resolve_variables(path),
            "method": method.upper(),
            "summary": name,
            "description": request.get('description', ''),
            "parameters": parameters,
            "requestBody": request_body,
            "tags": tags,
            "responses": {}, # Postman examples could be mapped to responses
            "security": security
        }
        
    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Get the list of extracted endpoints.
        
        Returns:
            List[Dict[str, Any]]: List of normalized endpoint objects.
        """
        if not self._endpoints:
             try:
                self.parse()
             except (FileNotFoundError, json.JSONDecodeError):
                 # Re-raise critical file/format errors
                 raise
             except Exception as e:
                 logger.error(f"Error getting endpoints: {e}")
                 return []
        return self._endpoints

    def get_servers(self) -> List[str]:
        """Extract base URLs from the collection variables or structure.
        
        Returns:
            List[str]: List of server URLs.
        """
        # Best effort: check variables for base_url or similar
        servers = []
        candidates = ["base_url", "baseUrl", "host", "url"]
        
        for key in candidates:
            if key in self._variables:
                servers.append(str(self._variables[key]))
                
        # Also check inside the first request if no variables found
        if not servers and self._endpoints:
            # This is hard because full URL is not always reconstructed easily if variables are missing
            pass
            
        return list(set(servers))
