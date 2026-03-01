"""Tests for CI/CD Pipeline Integration Features."""

import pytest
import xml.etree.ElementTree as ET
from typer.testing import CliRunner
from chaos_kitten.cli import app
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten.brain.orchestrator import Orchestrator  # Added for import resolution
from unittest.mock import MagicMock, patch

runner = CliRunner()

class TestCicdIntegration:
    """Test suite for CI/CD integration features."""

    @pytest.fixture
    def mock_scan_results(self):
        return {
            "vulnerabilities": [
                {
                    "id": "vuln_1",
                    "title": "Critical SQL Injection",
                    "description": "SQL Injection in parameter id",
                    "severity": "critical",
                    "endpoint": "/api/users",
                    "type": "sql_injection"
                },
                {
                    "id": "vuln_2",
                    "title": "Low Information Disclosure",
                    "description": "Server version exposed",
                    "severity": "low",
                    "endpoint": "/api/version",
                    "type": "info_disclosure"
                }
            ],
            "status": "completed"
        }

    @pytest.fixture(autouse=True)
    def mock_env(self, monkeypatch):
        """Mock environment variables to bypass API key check."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy_key")

    @patch("chaos_kitten.brain.orchestrator.Orchestrator.run")
    def test_fail_on_critical_flag(self, mock_run, mock_scan_results):
        """Test that --fail-on critical exits with 1 when critical vuln found."""
        mock_run.return_value = mock_scan_results
        
        # Should fail because we have a critical vulnerability
        result = runner.invoke(app, ["scan", "--target", "http://test", "--fail-on", "critical"])
        assert result.exit_code == 1
        assert "Failing pipeline" in result.stdout

    @patch("chaos_kitten.brain.orchestrator.Orchestrator.run")
    def test_fail_on_high_flag(self, mock_run, mock_scan_results):
        """Test that --fail-on high exits with 1 when critical vuln found (critical > high)."""
        mock_run.return_value = mock_scan_results
        
        # Should fail
        result = runner.invoke(app, ["scan", "--target", "http://test", "--fail-on", "high"])
        assert result.exit_code == 1

    @patch("chaos_kitten.brain.orchestrator.Orchestrator.run")
    def test_fail_on_threshold_not_met(self, mock_run, mock_scan_results):
        """Test that --fail-on doesn't exit with 1 when threshold not met."""
        # Only low vuln here
        results = {"vulnerabilities": [{"severity": "low", "title": "Low Issue", "description": "desc"}]}
        mock_run.return_value = results
        
        # Threshold is critical, found is low. Should pass (exit code 0)
        result = runner.invoke(app, ["scan", "--target", "http://test", "--fail-on", "critical"])
        assert result.exit_code == 0
        assert "No vulnerabilities found exceeding" in result.stdout

    @patch("chaos_kitten.brain.orchestrator.Orchestrator.run")
    def test_silent_mode(self, mock_run, mock_scan_results):
        """Test that --silent suppresses console output."""
        mock_run.return_value = mock_scan_results
        
        result = runner.invoke(app, ["scan", "--target", "http://test", "--silent"])
        assert result.exit_code == 0
        # Should not see standard banners
        assert "🐱 Chaos Kitten" not in result.stdout
        assert "Target:" not in result.stdout

    def test_junit_reporter_output(self, tmp_path, mock_scan_results):
        """Test JUnit XML report generation."""
        reporter = Reporter(output_path=tmp_path, output_format="junit")
        output_file = reporter.generate(mock_scan_results, "http://test-api.com")
        
        assert output_file.exists()
        assert output_file.suffix == ".xml"
        
        # Parse XML to verify structure
        tree = ET.parse(output_file)
        root = tree.getroot()
        
        assert root.tag == "testsuites"
        assert int(root.attrib["tests"]) == 2  # Total vulns
        assert int(root.attrib["failures"]) == 1 # Only critical/high count as failure in root summary logic
        
        # Check testsuites
        suites = root.findall("testsuite")
        assert len(suites) > 0
        
        # Check specific suite for critical
        critical_suite = next((s for s in suites if "Critical" in s.attrib["name"]), None)
        assert critical_suite is not None
        assert int(critical_suite.attrib["failures"]) == 1
        
        # Check failure message
        case = critical_suite.find("testcase")
        failure = case.find("failure")
        assert failure is not None
        assert "SQL Injection" in failure.text or "SQL Injection" in failure.attrib["message"]

