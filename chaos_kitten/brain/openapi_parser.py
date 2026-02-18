"""OpenAPI/Swagger specification parser.

This module provides the `OpenAPIParser` class, which parses OpenAPI 3.x and 
Swagger 2.0 specifications into a normalized format for downstream use by 
the attack planner and orchestrator.

Examples:
    >>> from chaos_kitten.brain.openapi_parser import OpenAPIParser
    >>> parser = OpenAPIParser("path/to/openapi.yaml")
    >>> try:
    ...     spec = parser.parse()
    ...     endpoints = parser.get_endpoints(methods=["GET", "POST"])
    ...     for ep in endpoints:
    ...         print(f"{ep['method']} {ep['path']}")
    ... except FileNotFoundError:
    ...     print("Spec file not found")
    ... except ValueError as e:
    ...     print(f"Error: {e}")

    # Extracting server URLs
    >>> servers = parser.get_servers()
    >>> print(servers)
    ['https://api.example.com/v1']

    # Extracting security schemes
    >>> auth_schemes = parser.get_security_schemes()
    >>> print(auth_schemes.keys())
    dict_keys(['BearerAuth', 'ApiKey'])
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from prance import ResolvingParser

logger = logging.getLogger(__name__)


class OpenAPIParser:
    """Parse OpenAPI specifications to understand API structure.
    
    Supports both OpenAPI 3.x and Swagger 2.0 specifications
    in JSON and YAML formats.
    """
    
    def __init__(self, spec_path: Union[str, Path]) -> None:
        """Initialize the parser.
        
        Args:
            spec_path (Union[str, Path]): Path to the OpenAPI spec file (JSON or YAML).
        """
        self.spec_path = Path(spec_path)
        self.spec: Dict[str, Any] = {}
        self.version: Optional[str] = None
        self._endpoints: List[Dict[str, Any]] = []
    
    def parse(self) -> Dict[str, Any]:
        """Parse the OpenAPI specification.
        
        Loads the specification file, validates it against the schema, and 
        resolves internal and external references ($ref).
        Detects the specification version (Swagger 2.0 or OpenAPI 3.x) and
        dispatches to the appropriate internal parser.
        
        Returns:
            Dict[str, Any]: The fully parsed and resolved specification dictionary.
            
        Raises:
            FileNotFoundError: If the specification file does not exist.
            ValueError: If spec format is invalid, version is unsupported, 
                        or parsing fails validation.
        """
        if not self.spec_path.exists():
            error_msg = f"OpenAPI spec file not found: {self.spec_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        try:
            # ResolvingParser handles load, parse, validate, and ref resolution
            # Use default strict behavior; validation runs by default
            parser = ResolvingParser(
                str(self.spec_path),
                backend='openapi-spec-validator'
            )
            self.spec = parser.specification
            
            # Detect version
            if 'openapi' in self.spec:
                self.version = self.spec['openapi']
                if self.version.startswith('3.'):
                    logger.info(f"Detected OpenAPI {self.version} spec")
                    self._parse_openapi_3x()
                else:
                    raise ValueError(f"Unsupported OpenAPI version: {self.version}")
            elif 'swagger' in self.spec:
                self.version = self.spec['swagger']
                if self.version == '2.0':
                    logger.info(f"Detected Swagger {self.version} spec")
                    self._parse_swagger_2()
                else:
                    raise ValueError(f"Unsupported Swagger version: {self.version}")
            else:
                raise ValueError("Unknown specification format. Missing 'openapi' or 'swagger' field.")
                
            return self.spec

        except (ValueError, KeyError) as e:
            # Re-raise known errors with context
            logger.error(f"Invalid OpenAPI spec: {e}")
            raise ValueError(f"Invalid OpenAPI spec: {e}") from e
        except Exception as e:
            # Catch-all for parsing library errors (e.g. prance validation errors)
            logger.error(f"Failed to parse OpenAPI spec: {e}")
            raise ValueError(f"Failed to parse OpenAPI spec: {e}") from e

    def _parse_openapi_3x(self) -> None:
        """Extract endpoints from OpenAPI 3.x paths."""
        paths = self.spec.get('paths', {})
        self._endpoints = self._extract_endpoints(paths)

    def _parse_swagger_2(self) -> None:
        """Extract endpoints from Swagger 2.0 paths."""
        paths = self.spec.get('paths', {})
        self._endpoints = self._extract_endpoints(paths)

    def _extract_endpoints(self, paths: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize endpoints from paths object.
        
        Args:
            paths (Dict[str, Any]): The 'paths' dictionary from the spec.
            
        Returns:
            List[Dict[str, Any]]: List of normalized endpoint objects containing
            path, method, parameters, requestBody, responses, etc.
        """
        endpoints = []
        http_methods = {'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace'}
        
        for path, path_item in paths.items():
            # Handle path-level parameters (apply to all operations)
            path_params = path_item.get('parameters', [])
            
            for method, operation in path_item.items():
                if method.lower() not in http_methods:
                    continue
                
                # Merge path-level and operation-level parameters
                # Operation-level params override path-level by (name, in)
                op_params = operation.get('parameters', [])
                merged_params = {}
                for param in path_params:
                    key = (param.get('name'), param.get('in'))
                    merged_params[key] = param
                for param in op_params:
                    key = (param.get('name'), param.get('in'))
                    merged_params[key] = param
                all_params = list(merged_params.values())
                
                # Normalize parameters
                consumes = operation.get('consumes', self.spec.get('consumes', []))
                normalized_params, request_body = self._normalize_parameters(all_params, consumes)
                
                # If explicitly defined requestBody (OpenAPI 3), use it
                if 'requestBody' in operation:
                    request_body = operation['requestBody']
                
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "operationId": operation.get('operationId'),
                    "summary": operation.get('summary'),
                    "description": operation.get('description'),
                    "parameters": normalized_params,
                    "tags": operation.get('tags', []),
                    "responses": operation.get('responses', {}),
                    "security": operation.get('security', self.spec.get('security', [])),
                    "requestBody": request_body
                }
                
                endpoints.append(endpoint)
                
        return endpoints

    def _normalize_parameters(
        self,
        parameters: List[Dict[str, Any]],
        consumes: Optional[List[str]] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Normalize parameters and extract body for Swagger 2.0 backward compatibility.
        
        Args:
            parameters (List[Dict[str, Any]]): List of parameter definitions.
            consumes (List[str] | None): Swagger 2.0 consumes list for media type selection.
            
        Returns:
            Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]: 
                A tuple containing:
                - List of normalized parameters (excluding body/formData)
                - Extracted request body dictionary (if any found)
        """
        normalized = []
        request_body = None
        
        for param in parameters:
            # Prance resolves references, so we can assume we have the full object
            
            if param.get('in') == 'body':
                # Convert Swagger 2.0 body param to OpenAPI 3.0 requestBody structure
                request_body = {
                    "required": param.get('required', False),
                    "description": param.get('description', ''),
                    "content": {
                        "application/json": {
                            "schema": param.get('schema', {})
                        }
                    }
                }
            elif param.get('in') == 'formData':
                # Handle Swagger 2.0 formData as requestBody
                # Note: This is a simplification; handling multiple formData params requires
                # merging them into one schema properties object.
                if request_body is None:
                    media_type = "application/x-www-form-urlencoded"
                    if consumes:
                        if "multipart/form-data" in consumes:
                            media_type = "multipart/form-data"
                        elif "application/x-www-form-urlencoded" in consumes:
                            media_type = "application/x-www-form-urlencoded"
                    request_body = {
                        "content": {
                            media_type: {
                                "schema": {
                                    "type": "object",
                                    "properties": {},
                                    "required": []
                                }
                            }
                        }
                    }
                
                # Add this field to the schema
                media_type = list(request_body['content'].keys())[0]
                schema = request_body['content'][media_type]['schema']
                param_name = param.get('name')
                
                if param_name:
                    schema['properties'][param_name] = {
                        "type": param.get('type', 'string'),
                        "description": param.get('description', '')
                    }
                    # Add other schema attributes like default, enum, etc.
                    for field in ['default', 'enum', 'minimum', 'maximum', 'pattern']:
                        if field in param:
                            schema['properties'][param_name][field] = param[field]
                            
                    if param.get('required', False):
                        if 'required' not in schema:
                            schema['required'] = []
                        schema['required'].append(param_name)
            else:
                # Keep standard parameters (path, query, header, cookie)
                normalized.append(param)
                
        return normalized, request_body

    def get_endpoints(self, tags: Optional[List[str]] = None, methods: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extract all API endpoints from the spec with optional filtering.
        
        Args:
            tags (Optional[List[str]]): Filter endpoints by tag (case-insensitive).
            methods (Optional[List[str]]): Filter endpoints by HTTP method (case-insensitive).
        
        Returns:
            List[Dict[str, Any]]: List of endpoint definitions. Each endpoint dict contains
            full details including path, method, parameters, and schema information.
        """
        if not self.spec:
            self.parse()
            
        endpoints = list(self._endpoints)
        
        if tags:
            tags_lower = {t.lower() for t in tags}
            endpoints = [
                ep for ep in endpoints 
                if any(t.lower() in tags_lower for t in ep.get("tags", []))
            ]
            
        if methods:
            methods_upper = {m.upper() for m in methods}
            endpoints = [
                ep for ep in endpoints
                if ep.get("method") in methods_upper
            ]
            
        return endpoints

    def get_servers(self) -> List[str]:
        """Extract server URLs from the specification.

        Handles both OpenAPI 3.x `servers` array (with variable substitution)
        and Swagger 2.0 `schemes`, `host`, and `basePath`.

        Returns:
            List[str]: List of full server URLs. e.g. ["https://api.example.com/v1"]
        """
        if not self.spec:
            self.parse()

        servers = []

        if 'servers' in self.spec:
            # OpenAPI 3.x
            for server_obj in self.spec['servers']:
                url = server_obj.get('url', '/')
                variables = server_obj.get('variables', {})
                
                # Perform variable substitution
                # Uses default value if available
                for var_name, var_info in variables.items():
                    default_val = var_info.get('default', '')
                    url = url.replace(f"{{{var_name}}}", str(default_val))
                
                servers.append(url)
        
        elif 'host' in self.spec:
            # Swagger 2.0
            schemes = self.spec.get('schemes', ['https'])
            host = self.spec.get('host')
            base_path = self.spec.get('basePath', '')
            
            # Ensure basePath starts with / if present
            if base_path and not base_path.startswith('/'):
                base_path = '/' + base_path
            
            # Construct URLs for each scheme
            for scheme in schemes:
                servers.append(f"{scheme}://{host}{base_path}")
        
        return servers

    def get_security_schemes(self) -> Dict[str, Any]:
        """Extract and normalize security schemes from the spec.
        
        Extracts schemes from OpenAPI 3.x `components.securitySchemes` or 
        Swagger 2.0 `securityDefinitions`. Normalizes older formats to 
        closely match OpenAPI 3.x structure.
        
        Returns:
            Dict[str, Any]: Dictionary of security scheme definitions keyed by scheme name.
        """
        if not self.spec:
            self.parse()
            
        schemes = {}
        
        # OpenAPI 3.x location
        if 'components' in self.spec and 'securitySchemes' in self.spec['components']:
            schemes = self.spec['components']['securitySchemes']
            
        # Swagger 2.0 location
        elif 'securityDefinitions' in self.spec:
            # Normalize Swagger 2.0 to match OpenAPI 3 structure roughly
            # Swagger: type=basic -> OAI3: type=http, scheme=basic
            # Swagger: type=apiKey -> OAI3: type=apiKey (same)
            # Swagger: type=oauth2 -> OAI3: type=oauth2 (flows structure slightly different)
            
            swagger_schemes = self.spec['securityDefinitions']
            for name, definition in swagger_schemes.items():
                scheme_type = definition.get('type')
                normalized = definition.copy()
                
                if scheme_type == 'basic':
                    normalized['type'] = 'http'
                    normalized['scheme'] = 'basic'
                
                # For oauth2 and apiKey, the structure is close enough for our
                # purposes to pass through as-is, or we can add more specific
                # mapping logic here if needed.
                
                schemes[name] = normalized
                
        return schemes


