import pytest
from chaos_kitten.paws.analyzer import ResponseAnalyzer, Severity, Finding

@pytest.fixture
def analyzer():
    return ResponseAnalyzer()

def test_cache_poisoning_header_reflection(analyzer):
    """Test cache poisoning when injected header is reflected in response headers."""
    payload = "evil.com"
    response = {
        "body": "<html></html>",
        "status_code": 200,
        "elapsed_ms": 100,
        "headers": {
            "Content-Type": "text/html",
            "Cache-Control": "public, max-age=3600",
            "Location": f"http://{payload}/login"
        }
    }
    
    attack_profile = {"name": "Test Attack"}
    
    finding = analyzer.analyze(response, attack_profile, endpoint="GET /", payload=payload)
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.8
    assert "reflected in header" in finding.evidence

def test_cache_poisoning_body_reflection(analyzer):
    """Test cache poisoning when injected header is reflected in response body."""
    payload = "evil.com"
    response = {
        "body": f"<html><script src='http://{payload}/malicious.js'></script></html>",
        "status_code": 200,
        "elapsed_ms": 100,
        "headers": {
            "Content-Type": "text/html",
            "Cache-Control": "public, max-age=3600"
        }
    }
    
    attack_profile = {"name": "Test Attack"}

    finding = analyzer.analyze(response, attack_profile, endpoint="GET /", payload=payload)
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.5
    assert "reflected in body" in finding.evidence

def test_cache_poisoning_no_caching(analyzer):
    """Test that cache poisoning is NOT reported if response is not cacheable."""
    payload = "evil.com"
    response = {
        "body": "<html></html>",
        "status_code": 200,
        "elapsed_ms": 100,
        "headers": {
            "Content-Type": "text/html",
            "Cache-Control": "private, no-store",
            "Location": f"http://{payload}/login"
        }
    }
    
    attack_profile = {"name": "Test Attack"}

    finding = analyzer.analyze(response, attack_profile, endpoint="GET /", payload=payload)
    
    if finding:
        assert finding.vulnerability_type != "Cache Poisoning"

def test_cache_poisoning_safe_vary(analyzer):
    """Test safe case where Vary header handles the input."""
    payload = "evil.com"
    response = {
        "body": "Safe content",
        "status_code": 200,
        "elapsed_ms": 100,
        "headers": {
            "Content-Type": "text/html",
            "Cache-Control": "public, max-age=3600",
            "X-Forwarded-Host": "evil.com", # Reflected
            "Vary": "X-Forwarded-Host" # But protected by Vary
        }
    }
    
    attack_profile = {"name": "Test Attack"}

    finding = analyzer.analyze(response, attack_profile, endpoint="GET /", payload=payload)
    assert finding is None
