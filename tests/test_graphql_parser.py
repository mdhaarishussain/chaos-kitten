"""Tests for the GraphQL Parser."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from chaos_kitten.brain.graphql_parser import GraphQLParser


class TestGraphQLParser:
    """Tests for GraphQLParser."""

    @pytest.fixture
    def mock_introspection_response(self):
        return {
            "data": {
                "__schema": {
                    "queryType": {"name": "RootQuery"},
                    "mutationType": {"name": "RootMutation"},
                    "types": [
                        {
                            "kind": "OBJECT",
                            "name": "RootQuery",
                            "fields": [
                                {
                                    "name": "getUser",
                                    "description": "Get user by ID",
                                    "args": [
                                        {
                                            "name": "id",
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": None,
                                                "ofType": {
                                                    "kind": "SCALAR",
                                                    "name": "ID",
                                                },
                                            },
                                        }
                                    ],
                                    "type": {"kind": "OBJECT", "name": "User"},
                                }
                            ],
                        },
                        {
                            "kind": "OBJECT",
                            "name": "RootMutation",
                            "fields": [
                                {
                                    "name": "createUser",
                                    "args": [
                                        {
                                            "name": "username",
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": None,
                                                "ofType": {
                                                    "kind": "SCALAR",
                                                    "name": "String",
                                                },
                                            },
                                        }
                                    ],
                                    "type": {"kind": "OBJECT", "name": "User"},
                                }
                            ],
                        },
                        {
                            "kind": "OBJECT",
                            "name": "User",
                            "fields": [
                                {
                                    "name": "id",
                                    "type": {"kind": "SCALAR", "name": "ID"},
                                },
                                {
                                    "name": "username",
                                    "type": {"kind": "SCALAR", "name": "String"},
                                },
                            ],
                        },
                    ],
                }
            }
        }

    @patch("httpx.post")
    def test_introspect_success(self, mock_post, mock_introspection_response):
        """Test successful introspection from an endpoint."""
        mock_response = MagicMock()
        mock_response.json.return_value = mock_introspection_response
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        parser = GraphQLParser(endpoint_url="http://example.com/graphql")
        schema = parser.introspect()

        assert schema == mock_introspection_response["data"]
        mock_post.assert_called_once()

    @patch("httpx.post")
    def test_introspect_failure(self, mock_post):
        """Test introspection failure handling."""
        mock_post.side_effect = httpx.RequestError("Network error")
        parser = GraphQLParser(endpoint_url="http://example.com/graphql")

        with pytest.raises(httpx.RequestError):
            parser.introspect()

    def test_parse_schema_json(self, mock_introspection_response):
        """Test parsing a local JSON schema file."""

        json_content = json.dumps(mock_introspection_response["data"])

        with (
            patch("pathlib.Path.read_text", return_value=json_content),
            patch("pathlib.Path.exists", return_value=True),
        ):

            parser = GraphQLParser(schema_path="schema.json")
            schema = parser.parse_schema()
            assert schema["__schema"]["queryType"]["name"] == "RootQuery"

    def test_to_endpoints(self, mock_introspection_response):
        """Test conversion of schema to endpoint list."""
        parser = GraphQLParser(endpoint_url="http://example.com/api/graphql")
        # Manually set schema to avoid introspection call
        parser.schema = mock_introspection_response["data"]

        endpoints = parser.to_endpoints()

        assert len(endpoints) == 2

        # Check Mutation
        mutation = next(e for e in endpoints if "createUser" in e["operation"])
        assert mutation["path"] == "/api/graphql"
        assert mutation["method"] == "POST"
        assert mutation["fields"][0]["name"] == "username"
        assert mutation["fields"][0]["type"] == "String!"
        assert mutation["fields"][0]["required"] is True

        # Check Query
        query = next(e for e in endpoints if "getUser" in e["operation"])
        assert query["fields"][0]["name"] == "id"
        assert query["fields"][0]["type"] == "ID!"

    def test_resolve_type_name(self):
        """Test type name resolution helper."""
        parser = GraphQLParser()
        # Test List
        type_ref = {"kind": "LIST", "ofType": {"kind": "SCALAR", "name": "String"}}
        assert parser._resolve_type_name(type_ref) == "[String]"

        # Test Non-Null
        type_ref = {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Int"}}
        assert parser._resolve_type_name(type_ref) == "Int!"

        # Test Simple
        type_ref = {"kind": "SCALAR", "name": "Boolean", "ofType": None}
        assert parser._resolve_type_name(type_ref) == "Boolean"
