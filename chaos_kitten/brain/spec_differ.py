"""OpenAPI Spec Differ for detecting API changes between versions."""

from dataclasses import dataclass
from typing import Any


@dataclass
class EndpointChange:
    """Represents a change to an endpoint."""

    change_type: str  # 'added', 'removed', 'modified'
    method: str
    path: str
    old_endpoint: dict[str, Any] | None = None
    new_endpoint: dict[str, Any] | None = None
    modifications: list[str] | None = None
    severity: str = "info"  # 'critical', 'high', 'medium', 'info'
    reason: str = ""


class SpecDiffer:
    """Computes structural diff between two OpenAPI specifications."""

    def __init__(self, old_spec: dict[str, Any], new_spec: dict[str, Any]):
        """Initialize the spec differ.

        Args:
            old_spec: The original OpenAPI specification
            new_spec: The new OpenAPI specification to compare
        """
        self.old_spec = old_spec
        self.new_spec = new_spec
        self.changes: list[EndpointChange] = []

    def compute_diff(self) -> dict[str, Any]:
        """Compute structural diff between specs.

        Returns:
            Dict with added, removed, modified endpoints and summary stats
        """
        old_endpoints = self._extract_endpoints(self.old_spec)
        new_endpoints = self._extract_endpoints(self.new_spec)

        # Create endpoint keys: (method, path)
        old_keys = {(ep["method"], ep["path"]): ep for ep in old_endpoints}
        new_keys = {(ep["method"], ep["path"]): ep for ep in new_endpoints}

        added = []
        removed = []
        modified = []
        critical_findings = []

        # Find added endpoints
        for key in new_keys.keys() - old_keys.keys():
            method, path = key
            change = EndpointChange(
                change_type="added",
                method=method,
                path=path,
                new_endpoint=new_keys[key],
                severity="info",
                reason="New endpoint added to API"
            )
            added.append(change)
            self.changes.append(change)

        # Find removed endpoints
        for key in old_keys.keys() - new_keys.keys():
            method, path = key
            change = EndpointChange(
                change_type="removed",
                method=method,
                path=path,
                old_endpoint=old_keys[key],
                severity="medium",
                reason="Endpoint removed from API"
            )
            removed.append(change)
            self.changes.append(change)

        # Find modified endpoints
        for key in old_keys.keys() & new_keys.keys():
            method, path = key
            old_ep = old_keys[key]
            new_ep = new_keys[key]

            modifications = self._detect_modifications(old_ep, new_ep)

            if modifications:
                # Check for auth removal (CRITICAL) — use ranking to prevent downgrade
                _SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                current_rank = _SEVERITY_RANK["info"]
                reason = "Endpoint modified"

                for mod in modifications:
                    if "authentication removed" in mod.lower() or "security requirement removed" in mod.lower():
                        current_rank = max(current_rank, _SEVERITY_RANK["critical"])
                        reason = "Authentication requirement removed — potential security regression"
                        break
                    elif "parameter" in mod.lower():
                        current_rank = max(current_rank, _SEVERITY_RANK["medium"])
                        if current_rank == _SEVERITY_RANK["medium"]:
                            reason = "Parameters modified"
                    elif "response" in mod.lower():
                        current_rank = max(current_rank, _SEVERITY_RANK["low"])

                # Invert back to name
                severity = next(k for k, v in _SEVERITY_RANK.items() if v == current_rank)

                change = EndpointChange(
                    change_type="modified",
                    method=method,
                    path=path,
                    old_endpoint=old_ep,
                    new_endpoint=new_ep,
                    modifications=modifications,
                    severity=severity,
                    reason=reason
                )
                modified.append(change)
                self.changes.append(change)

                if severity == "critical":
                    critical_findings.append(change)

        unchanged_count = len(old_keys & new_keys) - len(modified)

        return {
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged_count": unchanged_count,
            "critical_findings": critical_findings,
            "summary": {
                "total_old": len(old_endpoints),
                "total_new": len(new_endpoints),
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified),
                "unchanged_count": unchanged_count,
                "critical_count": len(critical_findings)
            }
        }

    def _extract_endpoints(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract all endpoints from an OpenAPI spec.

        Args:
            spec: OpenAPI specification dict

        Returns:
            List of endpoint dicts with method, path, and metadata
        """
        endpoints = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            # Skip non-HTTP methods
            for method in ["get", "post", "put", "patch", "delete", "options", "head", "trace"]:
                if method in path_item:
                    operation = path_item[method]
                    
                    # Properly handle security inheritance (avoid or which treats [] as falsy)
                    op_security = operation.get("security")
                    if op_security is None:
                        op_security = path_item.get("security")
                    if op_security is None:
                        op_security = spec.get("security", [])
                    
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "operation": operation,
                        "parameters": operation.get("parameters", []),
                        "requestBody": operation.get("requestBody"),
                        "responses": operation.get("responses", {}),
                        "security": op_security,
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", "")
                    })

        return endpoints

    def _detect_modifications(self, old_ep: dict[str, Any], new_ep: dict[str, Any]) -> list[str]:
        """Detect what changed between two endpoint versions.

        Args:
            old_ep: Old endpoint dict
            new_ep: New endpoint dict

        Returns:
            List of modification descriptions
        """
        modifications = []

        # Check parameters
        old_params = self._normalize_parameters(old_ep.get("parameters", []))
        new_params = self._normalize_parameters(new_ep.get("parameters", []))

        added_params = new_params.keys() - old_params.keys()
        removed_params = old_params.keys() - new_params.keys()
        changed_params = []

        for param_name in old_params.keys() & new_params.keys():
            if old_params[param_name] != new_params[param_name]:
                changed_params.append(param_name)

        if added_params:
            modifications.append(f"Added parameters: {', '.join(sorted(added_params))}")
        if removed_params:
            modifications.append(f"Removed parameters: {', '.join(sorted(removed_params))}")
        if changed_params:
            modifications.append(f"Modified parameters: {', '.join(sorted(changed_params))}")

        # Check requestBody schema
        old_body = old_ep.get("requestBody")
        new_body = new_ep.get("requestBody")

        if old_body != new_body:
            if old_body is None and new_body is not None:
                modifications.append("Request body schema added")
            elif old_body is not None and new_body is None:
                modifications.append("Request body schema removed")
            elif old_body is not None and new_body is not None:
                modifications.append("Request body schema modified")

        # Check security requirements (AUTH REMOVAL = CRITICAL)
        old_security = old_ep.get("security", [])
        new_security = new_ep.get("security", [])

        if old_security and not new_security:
            modifications.append("🚨 CRITICAL: Authentication requirement removed")
        elif old_security != new_security:
            modifications.append("Security requirements modified")

        # Check responses
        old_responses = set(old_ep.get("responses", {}).keys())
        new_responses = set(new_ep.get("responses", {}).keys())

        added_responses = new_responses - old_responses
        removed_responses = old_responses - new_responses

        if added_responses:
            modifications.append(f"Added response codes: {', '.join(str(c) for c in sorted(added_responses, key=lambda x: int(x) if str(x).isdigit() else 0))}")
        if removed_responses:
            modifications.append(f"Removed response codes: {', '.join(str(c) for c in sorted(removed_responses, key=lambda x: int(x) if str(x).isdigit() else 0))}")

        return modifications

    def _normalize_parameters(self, params: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Normalize parameter list to dict keyed by (name, in).

        Args:
            params: List of parameter objects

        Returns:
            Dict mapping parameter key to param object
        """
        normalized = {}
        for param in params:
            name = param.get("name", "")
            location = param.get("in", "")
            key = f"{name}::{location}"
            normalized[key] = {
                "required": param.get("required", False),
                "schema": param.get("schema", {}),
                "type": param.get("type", param.get("schema", {}).get("type"))
            }
        return normalized

    def get_delta_endpoints(self) -> list[dict[str, Any]]:
        """Get list of endpoints that need testing (added + modified).

        Returns:
            List of endpoint dicts to test
        """
        if not self.changes:
            self.compute_diff()

        delta_endpoints = []

        for change in self.changes:
            if change.change_type in ["added", "modified"]:
                # Use new_endpoint for both added and modified
                endpoint = change.new_endpoint
                if endpoint:
                    delta_endpoints.append({
                        "method": change.method,
                        "path": change.path,
                        **endpoint,  # spread in summary, parameters, responses, security, etc.
                    })

        return delta_endpoints
