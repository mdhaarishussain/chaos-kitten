
import pytest
from chaos_kitten.brain.response_analyzer import ResponseAnalyzer, Severity, VulnerabilityFinding

@pytest.fixture
def analyzer():
    return ResponseAnalyzer()

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
