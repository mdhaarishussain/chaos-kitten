import pytest
from unittest.mock import patch, Mock
import logging
from chaos_kitten.litterbox import reporter

@pytest.fixture
def mock_scan_results():
    return {
        "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        "vulnerabilities": [
            {
                "title": "SQL Injection",
                "type": "sqli",
                "severity": "critical",
                "url": "http://example.com/api/users",
                "method": "POST",
                "evidence": "' OR 1=1--",
                "description": "SQL Injection found",
                "remediation": "Use parameterized queries",
                "poc": "curl -X POST ..."
            }
        ]
    }

def test_pdf_format_support(mock_scan_results, tmp_path):
    """Test that PDF format triggers the right methods."""
    
    # We patch HTML and WEASYPRINT_AVAILABLE in the reporter module
    with patch("chaos_kitten.litterbox.reporter.HTML") as mock_html_class:
        with patch.object(reporter, "WEASYPRINT_AVAILABLE", True):
            
            # Configure the mock HTML instance
            mock_html_instance = Mock()
            mock_html_class.return_value = mock_html_instance
            
            rep = reporter.Reporter(output_path=tmp_path, output_format="pdf")
            
            # Mock _generate_html to return dummy content
            with patch.object(rep, "_generate_html", return_value="<html>TEST SPEC</html>"):
                rep.generate(mock_scan_results, "http://test.com")
                
                # Check HTML class was instantiated with correct content
                assert mock_html_class.called
                call_kwargs = mock_html_class.call_args.kwargs
                
                content_arg = call_kwargs.get("string")
                assert content_arg == "<html>TEST SPEC</html>"
                
                # Verify base_url passed
                assert "base_url" in call_kwargs
                
                # Check write_pdf called
                mock_html_instance.write_pdf.assert_called_once()


def test_missing_weasyprint_warning(mock_scan_results, tmp_path, caplog):
    """Test safe fallback when weasyprint is missing."""
    
    with patch.object(reporter, "WEASYPRINT_AVAILABLE", False):
        rep = reporter.Reporter(output_path=tmp_path, output_format="pdf")
        
        with caplog.at_level(logging.WARNING):
            rep.generate(mock_scan_results, "http://test.com")
            
        assert "WeasyPrint not installed" in caplog.text
