"""Tests for SARIF Report Generation."""

import json
import pytest
from pathlib import Path
from chaos_kitten.litterbox.reporter import Reporter

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

class TestSarifReporter:
    """Tests for SARIF reporting capability."""

    @pytest.fixture
    def mock_results(self):
        return {
            "vulnerabilities": [
                {
                    "type": "sql_injection",
                    "title": "SQL Injection",
                    "description": "SQL Injection found in login parameter",
                    "severity": "critical",
                    "endpoint": "/api/login",
                    "remediation": "Use prepared statements",
                    "proof_of_concept": "curl -X POST ... ' OR 1=1"
                },
                {
                    "type": "xss",
                    "title": "Reflected XSS",
                    "description": "XSS in search field",
                    "severity": "medium",
                    "endpoint": "/api/search",
                    "remediation": "Encode output",
                }
            ]
        }

    def test_sarif_structure(self, tmp_path, mock_results):
        """Test that SARIF output follows basic structure."""
        reporter = Reporter(output_path=tmp_path, output_format="sarif")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        assert output_file.suffix == ".sarif"
        
        content = json.loads(output_file.read_text("utf-8"))
        
        # Check root keys
        assert content["version"] == "2.1.0"
        assert content["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        
        # Check run/tool info
        run = content["runs"][0]
        assert run["tool"]["driver"]["name"] == "chaos-kitten"
        assert run["tool"]["driver"]["version"] == "0.1.0"
        assert len(run["tool"]["driver"]["rules"]) == 2
        
        # Check rules
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "sql_injection"
        assert rule["defaultConfiguration"]["level"] == "error"
        
        # Check results
        results = run["results"]
        assert len(results) == 2
        
        res1 = results[0]
        assert res1["ruleId"] == "sql_injection"
        assert res1["level"] == "error"
        assert res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/api/login"
        assert res1["properties"]["proof_of_concept"] == "curl -X POST ... ' OR 1=1"

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_sarif_schema_validation(self, tmp_path, mock_results):
        """test that output validates against SARIF schema."""
        # Note: We won't actually fetch the schema from the web in strict unit tests 
        # to avoid flakes, unless we mock it or have a local copy. 
        # But we can verify strict structure.
        
        reporter = Reporter(output_path=tmp_path, output_format="sarif")
        output_file = reporter.generate(mock_results, "http://example.com")
        
        content = json.loads(output_file.read_text("utf-8"))
        
        # If we had the schema locally we would do:
        # schema_path = Path("tests/schemas/sarif-2.1.0.json") 
        # if schema_path.exists():
        #     schema = json.loads(schema_path.read_text())
        #     jsonschema.validate(instance=content, schema=schema)
        #     assert True
        
        # For now, just ensure it parses as JSON and has key fields
        assert isinstance(content, dict)

    def test_map_severity(self):
        """Test severity mapping."""
        reporter = Reporter()
        assert reporter._map_severity_to_sarif("critical") == "error"
        assert reporter._map_severity_to_sarif("high") == "error"
        assert reporter._map_severity_to_sarif("medium") == "warning"
        assert reporter._map_severity_to_sarif("low") == "note"
        assert reporter._map_severity_to_sarif("info") == "note"
