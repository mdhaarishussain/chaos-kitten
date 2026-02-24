"""Tests for OpenAPI Spec Differ."""

import pytest
from chaos_kitten.brain.spec_differ import SpecDiffer, EndpointChange


def test_spec_differ_empty_specs():
    """Test diff with empty specs."""
    old_spec = {"paths": {}}
    new_spec = {"paths": {}}

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["modified_count"] == 0
    assert result["summary"]["unchanged_count"] == 0
    assert len(result["critical_findings"]) == 0


def test_spec_differ_identical_specs():
    """Test diff with identical specs (no changes)."""
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }

    differ = SpecDiffer(spec, spec)
    result = differ.compute_diff()

    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["modified_count"] == 0
    assert result["summary"]["unchanged_count"] == 1


def test_spec_differ_added_endpoints():
    """Test detection of newly added endpoints."""
    old_spec = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "responses": {"200": {"description": "Success"}}
                }
            },
            "/orders": {
                "post": {
                    "summary": "Create order",
                    "responses": {"201": {"description": "Created"}}
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["added_count"] == 1
    assert result["summary"]["removed_count"] == 0
    assert result["summary"]["modified_count"] == 0
    assert result["summary"]["unchanged_count"] == 1

    added_endpoint = result["added"][0]
    assert added_endpoint.change_type == "added"
    assert added_endpoint.method == "POST"
    assert added_endpoint.path == "/orders"


def test_spec_differ_removed_endpoints():
    """Test detection of removed endpoints."""
    old_spec = {
        "paths": {
            "/users": {"get": {"summary": "List users"}},
            "/admin": {"delete": {"summary": "Admin endpoint"}}
        }
    }

    new_spec = {
        "paths": {
            "/users": {"get": {"summary": "List users"}}
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["added_count"] == 0
    assert result["summary"]["removed_count"] == 1
    assert result["summary"]["modified_count"] == 0

    removed = result["removed"][0]
    assert removed.change_type == "removed"
    assert removed.method == "DELETE"
    assert removed.path == "/admin"


def test_spec_differ_parameter_changes():
    """Test detection of parameter modifications."""
    old_spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ]
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "include_deleted", "in": "query", "schema": {"type": "boolean"}}
                    ]
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["modified_count"] == 1
    modified = result["modified"][0]
    assert modified.change_type == "modified"
    assert "Added parameters:" in modified.modifications[0]
    assert "include_deleted" in modified.modifications[0]


def test_spec_differ_auth_removal_critical():
    """Test CRITICAL detection when authentication is removed."""
    old_spec = {
        "paths": {
            "/admin": {
                "get": {
                    "summary": "Admin panel",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/admin": {
                "get": {
                    "summary": "Admin panel",
                    "security": [],  # Auth removed!
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["modified_count"] == 1
    assert result["summary"]["critical_count"] == 1

    critical = result["critical_findings"][0]
    assert critical.severity == "critical"
    assert "authentication" in critical.reason.lower()
    assert any("CRITICAL" in mod for mod in critical.modifications)


def test_spec_differ_request_body_changes():
    """Test detection of request body schema changes."""
    old_spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "name": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "name": {"type": "string"},
                                        "role": {"type": "string"}  # New field
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["modified_count"] == 1
    modified = result["modified"][0]
    assert any("body" in mod.lower() for mod in modified.modifications)


def test_spec_differ_response_code_changes():
    """Test detection of response code changes."""
    old_spec = {
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {"description": "Success"},
                        "404": {"description": "Not found"}
                    }
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/users": {
                "get": {
                    "responses": {
                        "200": {"description": "Success"},
                        "403": {"description": "Forbidden"}  # Changed
                    }
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["modified_count"] == 1
    modified = result["modified"][0]
    assert any("response codes" in mod.lower() for mod in modified.modifications)


def test_spec_differ_get_delta_endpoints():
    """Test retrieval of endpoints needing testing (added + modified)."""
    old_spec = {
        "paths": {
            "/users": {
                "get": {"summary": "List users", "security": [{"bearerAuth": []}]}
            },
            "/old-api": {
                "get": {"summary": "Old endpoint"}
            }
        }
    }

    new_spec = {
        "paths": {
            "/users": {
                "get": {"summary": "List users", "security": []}  # Modified (auth removed)
            },
            "/new-api": {
                "post": {"summary": "New endpoint"}  # Added
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    delta_endpoints = differ.get_delta_endpoints()

    # Should return 2 endpoints: 1 modified + 1 added (not the removed one)
    assert len(delta_endpoints) == 2
    paths = [ep["path"] for ep in delta_endpoints]
    assert "/users" in paths
    assert "/new-api" in paths
    assert "/old-api" not in paths


def test_spec_differ_multiple_http_methods():
    """Test diff handles multiple HTTP methods on same path."""
    old_spec = {
        "paths": {
            "/items": {
                "get": {"summary": "List items"},
                "post": {"summary": "Create item"}
            }
        }
    }

    new_spec = {
        "paths": {
            "/items": {
                "get": {"summary": "List items"},
                "post": {"summary": "Create item"},
                "delete": {"summary": "Delete all items"}  # Added method
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["added_count"] == 1
    assert result["summary"]["unchanged_count"] == 2

    added = result["added"][0]
    assert added.method == "DELETE"
    assert added.path == "/items"


def test_spec_differ_complex_scenario():
    """Test complex scenario with multiple types of changes."""
    old_spec = {
        "security": [{"apiKey": []}],
        "paths": {
            "/users": {
                "get": {
                    "security": [{"apiKey": []}],
                    "parameters": [{"name": "limit", "in": "query"}]
                }
            },
            "/admin": {
                "get": {"security": [{"bearerAuth": []}]}
            },
            "/deprecated": {
                "get": {"summary": "Old endpoint"}
            }
        }
    }

    new_spec = {
        "security": [{"apiKey": []}],
        "paths": {
            "/users": {
                "get": {
                    "security": [{"apiKey": []}],
                    "parameters": [
                        {"name": "limit", "in": "query"},
                        {"name": "offset", "in": "query"}  # New param
                    ]
                }
            },
            "/admin": {
                "get": {"security": []}  # Auth removed - CRITICAL!
            },
            "/v2/payments": {
                "post": {"summary": "New payment endpoint"}  # New endpoint
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    # Check summary
    assert result["summary"]["added_count"] == 1  # /v2/payments
    assert result["summary"]["removed_count"] == 1  # /deprecated
    assert result["summary"]["modified_count"] == 2  # /users, /admin
    assert result["summary"]["critical_count"] == 1  # /admin auth removal

    # Verify critical finding
    critical = result["critical_findings"][0]
    assert critical.path == "/admin"
    assert critical.severity == "critical"


def test_spec_differ_parameter_type_change():
    """Test detection when parameter type changes."""
    old_spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "string"}}
                    ]
                }
            }
        }
    }

    new_spec = {
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer"}}  # Type changed
                    ]
                }
            }
        }
    }

    differ = SpecDiffer(old_spec, new_spec)
    result = differ.compute_diff()

    assert result["summary"]["modified_count"] == 1
    modified = result["modified"][0]
    assert any("parameters" in mod.lower() for mod in modified.modifications)
