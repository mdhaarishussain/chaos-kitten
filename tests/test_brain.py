"""Tests for the Brain module."""

import json
import pytest
from pathlib import Path
from chaos_kitten.brain.openapi_parser import OpenAPIParser


class TestOrchestrator:
    """Tests for the Orchestrator."""
    
    def test_orchestrator_initialization(self):
        """Test that orchestrator initializes correctly."""
        # TODO: Implement test
        pass


class TestOpenAPIParser:
    """Tests for the OpenAPI parser."""

    # -------------------------------------------------------------------------
    # Fixtures
    # -------------------------------------------------------------------------

    @pytest.fixture
    def openapi_3_spec(self, tmp_path):
        """Create a temporary OpenAPI 3.0 specification file."""
        spec_content = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com/v1", "variables": {}}],
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "summary": "List users",
                        "responses": {"200": {"description": "OK"}}
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "get": {
                        "operationId": "getUserById",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
                }
            }
        }
        file_path = tmp_path / "openapi_3.json"
        file_path.write_text(json.dumps(spec_content))
        return file_path

    @pytest.fixture
    def swagger_2_spec(self, tmp_path):
        """Create a temporary Swagger 2.0 specification file."""
        spec_content = {
            "swagger": "2.0",
            "info": {"title": "Legacy API", "version": "1.0.0"},
            "host": "api.legacy.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/products": {
                    "get": {
                        "operationId": "listProducts",
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/products/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "type": "integer"}
                    ],
                    "put": {
                        "operationId": "updateProduct",
                        "parameters": [
                            {
                                "in": "body",
                                "name": "body",
                                "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                            }
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            },
            "securityDefinitions": {
                "BasicAuth": {"type": "basic"}
            }
        }
        file_path = tmp_path / "swagger_2.json"
        file_path.write_text(json.dumps(spec_content))
        return file_path

    @pytest.fixture
    def invalid_spec_file(self, tmp_path):
        """Create a syntactically valid JSON that is not a valid OpenAPI spec."""
        spec_content = {"foo": "bar"}
        file_path = tmp_path / "invalid.json"
        file_path.write_text(json.dumps(spec_content))
        return file_path

    @pytest.fixture
    def malformed_file(self, tmp_path):
        """Create a file with invalid JSON."""
        file_path = tmp_path / "malformed.json"
        file_path.write_text("{ not valid json }")
        return file_path

    @pytest.fixture
    def real_world_spec_path(self):
        """Return path to existing sample if available."""
        # Assuming the project structure has examples/sample_openapi.json
        path = Path("examples/sample_openapi.json")
        if path.exists():
            return path
        # If not found, skip tests using this fixture
        pytest.skip("examples/sample_openapi.json not found")
        return None

    # -------------------------------------------------------------------------
    # Tests
    # -------------------------------------------------------------------------

    def test_initialization(self, openapi_3_spec):
        """Test parser initialization."""
        parser = OpenAPIParser(openapi_3_spec)
        assert parser.spec_path == openapi_3_spec
        assert parser.spec == {}
        assert parser._endpoints == []

    def test_file_not_found(self):
        """Test behavior when file does not exist."""
        parser = OpenAPIParser("non_existent_file.json")
        with pytest.raises(FileNotFoundError):
            parser.parse()

    def test_parse_invalid_json(self, malformed_file):
        """Test parsing a malformed JSON file."""
        parser = OpenAPIParser(malformed_file)
        with pytest.raises(ValueError) as excinfo:
            parser.parse()
        assert "Invalid OpenAPI spec" in str(excinfo.value) or "Failed to parse" in str(excinfo.value)

    def test_parse_unknown_version(self, invalid_spec_file):
        """Test parsing a JSON file that is not OpenAPI/Swagger."""
        parser = OpenAPIParser(invalid_spec_file)
        with pytest.raises(ValueError) as excinfo:
            parser.parse()
        err_msg = str(excinfo.value)
        assert "Missing 'openapi' or 'swagger' field" in err_msg or \
               "Could not determine specification schema version" in err_msg

    def test_parse_openapi_3_success(self, openapi_3_spec):
        """Test successful parsing of OpenAPI 3 spec."""
        parser = OpenAPIParser(openapi_3_spec)
        spec = parser.parse()
        assert spec["openapi"] == "3.0.0"
        assert parser.version == "3.0.0"
        assert len(parser._endpoints) > 0

    def test_parse_swagger_2_success(self, swagger_2_spec):
        """Test successful parsing of Swagger 2.0 spec."""
        parser = OpenAPIParser(swagger_2_spec)
        spec = parser.parse()
        assert spec["swagger"] == "2.0"
        assert parser.version == "2.0"
        assert len(parser._endpoints) > 0

    def test_get_endpoints_openapi_3(self, openapi_3_spec):
        """Test endpoint extraction for OpenAPI 3."""
        parser = OpenAPIParser(openapi_3_spec)
        endpoints = parser.get_endpoints()
        
        # We expect 3 endpoints: GET /users, POST /users, GET /users/{id}
        assert len(endpoints) == 3
        
        # Verify specific endpoint details
        get_user = next(ep for ep in endpoints if ep["operationId"] == "getUsers")
        assert get_user["method"] == "GET"
        assert get_user["path"] == "/users"
        
        post_user = next(ep for ep in endpoints if ep["operationId"] == "createUser")
        assert post_user["method"] == "POST"
        assert "requestBody" in post_user
        
        get_user_id = next(ep for ep in endpoints if ep["operationId"] == "getUserById")
        # Check path parameter normalization
        assert len(get_user_id["parameters"]) == 1
        assert get_user_id["parameters"][0]["name"] == "id"
        assert get_user_id["parameters"][0]["in"] == "path"

    def test_get_endpoints_swagger_2(self, swagger_2_spec):
        """Test endpoint extraction and normalization for Swagger 2."""
        parser = OpenAPIParser(swagger_2_spec)
        endpoints = parser.get_endpoints()
        
        assert len(endpoints) == 2
        
        update_prod = next(ep for ep in endpoints if ep["operationId"] == "updateProduct")
        # Check body parameter normalization to requestBody
        assert "requestBody" in update_prod
        assert update_prod["requestBody"]["content"]["application/json"]["schema"]["properties"]["name"]["type"] == "string"

    def test_swagger_formdata_normalization(self, tmp_path):
        """Test Swagger 2.0 formData parameters normalize to requestBody."""
        spec_content = {
            "swagger": "2.0",
            "info": {"title": "Upload API", "version": "1.0.0"},
            "consumes": ["multipart/form-data"],
            "paths": {
                "/upload": {
                    "post": {
                        "operationId": "uploadFile",
                        "parameters": [
                            {"name": "file", "in": "formData", "required": True, "type": "file"},
                            {"name": "description", "in": "formData", "required": False, "type": "string"}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        file_path = tmp_path / "swagger_formdata.json"
        file_path.write_text(json.dumps(spec_content))

        parser = OpenAPIParser(file_path)
        endpoints = parser.get_endpoints()

        assert len(endpoints) == 1
        upload = endpoints[0]
        assert "requestBody" in upload
        assert "multipart/form-data" in upload["requestBody"]["content"]
        schema = upload["requestBody"]["content"]["multipart/form-data"]["schema"]
        assert schema["properties"]["file"]["type"] == "file"
        assert schema["properties"]["description"]["type"] == "string"
        assert "file" in schema["required"]

    def test_filter_endpoints_by_method(self, openapi_3_spec):
        """Test filtering endpoints by HTTP method."""
        parser = OpenAPIParser(openapi_3_spec)
        # Only GET methods
        get_eps = parser.get_endpoints(methods=["GET"])
        assert len(get_eps) == 2
        assert all(ep["method"] == "GET" for ep in get_eps)
        
        # Case insensitive
        get_eps_lower = parser.get_endpoints(methods=["get"])
        assert len(get_eps_lower) == 2

    def test_filter_endpoints_by_tags(self, tmp_path):
        """Test filtering endpoints by tags."""
        spec_content = {
            "openapi": "3.0.0",
            "info": {"title": "Tagged API", "version": "1.0.0"},
            "paths": {
                "/public": {
                    "get": {
                        "operationId": "getPublic",
                        "tags": ["public"],
                        "responses": {"200": {"description": "OK"}}
                    }
                },
                "/admin": {
                    "get": {
                        "operationId": "getAdmin",
                        "tags": ["admin"],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        file_path = tmp_path / "openapi_tags.json"
        file_path.write_text(json.dumps(spec_content))

        parser = OpenAPIParser(file_path)
        public_eps = parser.get_endpoints(tags=["public"])

        assert len(public_eps) == 1
        assert public_eps[0]["operationId"] == "getPublic"

    def test_get_servers_openapi_3(self, openapi_3_spec):
        """Test server extraction for OpenAPI 3."""
        parser = OpenAPIParser(openapi_3_spec)
        servers = parser.get_servers()
        assert "https://api.example.com/v1" in servers

    def test_get_servers_openapi_3_with_variables(self, tmp_path):
        """Test server variable substitution for OpenAPI 3."""
        spec_content = {
            "openapi": "3.0.0",
            "info": {"title": "Server Vars API", "version": "1.0.0"},
            "servers": [
                {
                    "url": "https://{environment}.example.com",
                    "variables": {
                        "environment": {"default": "api"}
                    }
                }
            ],
            "paths": {
                "/health": {
                    "get": {
                        "operationId": "getHealth",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        file_path = tmp_path / "openapi_servers.json"
        file_path.write_text(json.dumps(spec_content))

        parser = OpenAPIParser(file_path)
        servers = parser.get_servers()
        assert servers == ["https://api.example.com"]

    def test_get_servers_swagger_2(self, swagger_2_spec):
        """Test server extraction for Swagger 2."""
        parser = OpenAPIParser(swagger_2_spec)
        servers = parser.get_servers()
        assert "https://api.legacy.com/v1" in servers

    def test_get_security_schemes(self, openapi_3_spec, swagger_2_spec):
        """Test security scheme extraction."""
        # OpenAPI 3
        parser_3 = OpenAPIParser(openapi_3_spec)
        schemes_3 = parser_3.get_security_schemes()
        assert "ApiKeyAuth" in schemes_3
        assert schemes_3["ApiKeyAuth"]["type"] == "apiKey"
        
        # Swagger 2
        parser_2 = OpenAPIParser(swagger_2_spec)
        schemes_2 = parser_2.get_security_schemes()
        assert "BasicAuth" in schemes_2
        # Should be normalized to http/basic or similar
        assert schemes_2["BasicAuth"]["type"] == "http"
        assert schemes_2["BasicAuth"]["scheme"] == "basic"

    def test_real_world_example(self, real_world_spec_path):
        """Integration test with the provided sample file."""
        if real_world_spec_path is None:
            return
            
        parser = OpenAPIParser(real_world_spec_path)
        parser.parse()
        endpoints = parser.get_endpoints()
        
        assert len(endpoints) > 0
        assert parser.version is not None
        # Basic sanity check regarding structure
        for ep in endpoints:
            assert "path" in ep
            assert "method" in ep
            assert "responses" in ep


class TestAttackPlanner:
    """Tests for the attack planner."""
    
    def test_load_attack_profiles(self):
        """Test loading attack profiles from toys/."""
        # TODO: Implement test
        pass
    
    def test_plan_attacks_for_login_endpoint(self):
        """Test attack planning for a login endpoint."""
        # TODO: Implement test
        pass
