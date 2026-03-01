
import pytest
from chaos_kitten.brain.response_analyzer import ResponseAnalyzer, Severity, VulnerabilityFinding

@pytest.fixture
def analyzer():
    return ResponseAnalyzer()

# Original Tests for analyze() method

def test_detect_sql_injection_mysql(analyzer):
    response = "<html><body>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</body></html>"
    finding = analyzer.analyze(
        response_body=response,
        status_code=500,
        response_time_ms=100,
        payload_used="' OR 1=1 --",
        endpoint="/api/users"
    )
    assert finding is not None
    assert finding.vulnerability_type == "SQL Injection"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 1.0

def test_detect_xss_reflection(analyzer):
    payload = "<script>alert(1)</script>"
    response = f"<html><body>Search results for: {payload}</body></html>"
    finding = analyzer.analyze(
        response_body=response,
        status_code=200,
        response_time_ms=50,
        payload_used=payload,
        endpoint="/api/search"
    )
    assert finding is not None
    assert finding.vulnerability_type == "Reflected XSS"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9

def test_detect_path_traversal_linux(analyzer):
    response = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    finding = analyzer.analyze(
        response_body=response,
        status_code=200,
        response_time_ms=50,
        payload_used="../../../etc/passwd",
        endpoint="/api/files"
    )
    assert finding is not None
    assert finding.vulnerability_type == "Path Traversal"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 1.0

def test_no_vulnerability_found(analyzer):
    response = "<html><body>Login Failed</body></html>"
    finding = analyzer.analyze(
        response_body=response,
        status_code=401,
        response_time_ms=50,
        payload_used="' OR 1=1 --",
        endpoint="/api/login"
    )
    assert finding is None

def test_timing_attack_detection(analyzer):
    response = "<html><body>Success</body></html>"
    finding = analyzer.analyze(
        response_body=response,
        status_code=200,
        response_time_ms=6000, # > 5000ms
        payload_used="'; WAITFOR DELAY '0:0:5'--",
        endpoint="/api/products"
    )
    assert finding is not None
    assert finding.vulnerability_type == "Potential Timing Attack / DoS"
    assert finding.severity == Severity.MEDIUM

# New Tests for analyze_error_messages()

def test_analyze_error_sqli(analyzer):
    """Test detection of SQL Injection error messages."""
    response = {
        "status_code": 500,
        "body": "Uncaught exception: ORA-00933: SQL command not properly ended"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "sql_injection"
    assert result["confidence"] >= 0.7
    assert len(result["indicators"]) > 0
    # Use any() to check if "ORA-" is contained in any indicator if indicator is the matched pattern
    # Wait, the 'indicators' list contains the regex pattern string that matched, not the matched text.
    # Ah, implementation details.
    # Implementation: indicators.append(pattern)
    # The pattern for ORA is 'ORA-[0-9]{5}'.
    # So we check if the pattern is in the indicators list.
    orcl_pattern = r"ORA-[0-9]{5}"
    assert orcl_pattern in result["indicators"]

def test_analyze_error_nosqli(analyzer):
    """Test detection of NoSQL Injection error messages."""
    response = {
        "status_code": 500,
        "body": "MongoError: E11000 duplicate key error collection"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "nosql_injection"
    assert result["confidence"] >= 0.7

def test_analyze_error_command_injection(analyzer):
    """Test detection of Command Injection error messages."""
    response = {
        "status_code": 200,
        "body": "/bin/sh: command not found\nTotal 0"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "command_injection"
    # Check for new specific pattern
    expected_pattern = r"(?:/bin/sh|bash): .*command not found"
    assert expected_pattern in result["indicators"]

def test_analyze_error_xxe(analyzer):
    """Test detection of XXE error messages."""
    response = {
        "status_code": 400,
        "body": "XML parser: external entity not defined"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "xxe"
    expected_pattern = r"XML parser.*external entity"
    assert expected_pattern in result["indicators"]

def test_analyze_error_path_traversal(analyzer):
    """Test detection of Path Traversal error messages."""
    response = {
        "status_code": 403,
        "body": "Warning: fopen(../../etc/passwd): failed to open stream: Permission denied"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "path_traversal"
    expected_pattern = r"(?:fopen|include|readfile)\(.*\): .*Permission denied"
    assert expected_pattern in result["indicators"]

def test_analyze_error_multiple_indicators(analyzer):
    """Test confidence calculation/handling when multiple patterns match."""
    # Matches "SQL syntax" (MySQL) and "MySQL"
    # Patterns: r"SQL syntax.*MySQL", r"valid MySQL result" etc.
    # Let's construct a string matching at least two distinct patterns.
    # 1. r"SQL syntax.*MySQL"
    # 2. r"Warning.*mysql_"
    response = {
        "body": "Warning: mysql_connect(): SQL syntax error near MySQL server version"
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] == "sql_injection"
    # Should contain multiple matches
    assert len(result["indicators"]) >= 2
    # Confidence should be higher for multiple hits (0.9 vs 0.7)
    assert result["confidence"] == 0.9

def test_analyze_error_no_match(analyzer):
    """Test when no error patterns are found."""
    response = {
        "status_code": 200,
        "body": "Operation completed successfully."
    }
    result = analyzer.analyze_error_messages(response)
    
    assert result["error_category"] is None
    assert result["confidence"] == 0.0
    assert result["indicators"] == []

def test_analyze_error_non_string_body(analyzer):
    """Test handling of non-string bodies (e.g. None or Dict/JSON object)."""
    response = {
        "body": {"error": "unknown_error_code_123"} # Simulating JSON response body parsed as dict
    }
    # Should convert dict to string and analyze
    # String repr: "{'error': 'unknown_error_code_123'}"
    # No pattern matches simple dict structure unless malicious
    result = analyzer.analyze_error_messages(response)
    assert result["error_category"] is None
    
    # Test None
    response_none = {"body": None}
    result_none = analyzer.analyze_error_messages(response_none)
    assert result_none["error_category"] is None
