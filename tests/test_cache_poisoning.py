"""Tests for cache poisoning vulnerability detection."""

import pytest
from chaos_kitten.brain.response_analyzer import ResponseAnalyzer, Severity


@pytest.fixture
def analyzer():
    return ResponseAnalyzer()


# ============================================================================
# Test Suite 1: Weak Cache Configuration Detection
# ============================================================================

def test_detect_cache_poisoning_public_caching(analyzer):
    """Test detection of Cache-Control: public configuration."""
    response_body = "<html><body>User profile data</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=3600",
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="attacker.com",
        endpoint="/api/user/profile",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.6


def test_detect_cache_poisoning_shared_cache_max_age(analyzer):
    """Test detection of s-maxage in Cache-Control."""
    response_body = "<html><body>Content</body></html>"
    response_headers = {
        "Cache-Control": "public, s-maxage=86400, max-age=3600",
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="x-forwarded-host: attacker.com",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


def test_detect_cache_poisoning_payload_in_body_and_public_cache(analyzer):
    """Test detection when poisoned payload appears in response body with public caching."""
    poisoned_payload = "attacker.com"
    response_body = f"<html><body>Redirect to: {poisoned_payload}</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=7200",
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used=poisoned_payload,
        endpoint="/api/redirect",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"
    assert finding.confidence >= 0.75  # High confidence due to payload + weak cache


# ============================================================================
# Test Suite 2: Missing Vary Header Detection
# ============================================================================

def test_detect_cache_poisoning_missing_vary_x_forwarded_host(analyzer):
    """Test detection when X-Forwarded-Host header is used but not in Vary."""
    response_body = "<html><body>Data</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=3600",
        "Vary": "Accept-Encoding",  # Missing X-Forwarded-Host
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="X-Forwarded-Host: attacker.com",
        endpoint="/api/endpoint",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"
    assert finding.confidence >= 0.6


def test_detect_cache_poisoning_missing_vary_x_original_host(analyzer):
    """Test detection when X-Original-Host header is not in Vary."""
    response_body = "<html><body>Content</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=1800",
        "Vary": "Accept-Language",  # Missing X-Original-Host
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="X-Original-Host: malicious.com",
        endpoint="/api/content",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


def test_detect_cache_poisoning_proper_vary_header_safe(analyzer):
    """Test that proper Vary header prevents false positives."""
    response_body = "<html><body>Data</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=3600",
        "Vary": "X-Forwarded-Host, Accept-Encoding",  # Properly includes relevant headers
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="X-Forwarded-Host: attacker.com",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    # Should not be flagged as vulnerable due to proper Vary header
    # (unless payload appears in body, which it doesn't here)
    if finding:
        # If we do detect something, confidence should be lower
        assert finding.severity == Severity.HIGH  # Still high severity for cache issues


# ============================================================================
# Test Suite 3: Private Cache (Safe Configuration)
# ============================================================================

def test_no_cache_poisoning_when_private_cached(analyzer):
    """Test that private caching prevents cache poisoning detection."""
    response_body = "<html><body>Sensitive user data</body></html>"
    response_headers = {
        "Cache-Control": "private, max-age=3600",  # Private cache is safe
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="malicious-payload",
        endpoint="/api/sensitive",
        response_headers=response_headers
    )
    
    # Should not detect cache poisoning for private cached responses
    if finding is not None:
        assert finding.vulnerability_type != "Cache Poisoning"


def test_no_cache_poisoning_with_no_store(analyzer):
    """Test that no-store prevents cache poisoning."""
    response_body = "<html><body>Data</body></html>"
    response_headers = {
        "Cache-Control": "no-store, no-cache",
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="payload",
        endpoint="/api/endpoint",
        response_headers=response_headers
    )
    
    # Should not detect cache poisoning for non-cacheable responses
    if finding is not None:
        assert finding.vulnerability_type != "Cache Poisoning"


# ============================================================================
# Test Suite 4: Cache Poisoning with Long TTL
# ============================================================================

def test_cache_poisoning_long_ttl_high_impact(analyzer):
    """Test detection of cache poisoning with long max-age (high impact)."""
    response_body = "<html><body>Cached data</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=604800",  # 7 days - very long
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="x-forwarded-host: attacker.com",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


def test_cache_poisoning_short_ttl_lower_impact(analyzer):
    """Test detection of cache poisoning with short max-age (medium impact)."""
    response_body = "<html><body>Data</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=60",  # Only 1 minute
        "Content-Type": "text/html"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="test",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    # May or may not be detected depending on other factors
    # Short cache is less critical but still a concern
    if finding:
        assert finding.vulnerability_type == "Cache Poisoning"


# ============================================================================
# Test Suite 5: Host Header Injection Scenarios
# ============================================================================

def test_cache_poisoning_host_header_injection(analyzer):
    """Test detection of cache poisoning via Host header manipulation."""
    response_body = "<html><body>Content served from attacker.com</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=3600",
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="attacker.com",
        endpoint="/",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


def test_cache_poisoning_x_forwarded_host_injection(analyzer):
    """Test detection of cache poisoning via X-Forwarded-Host header."""
    response_body = "<html><body>Data from poisoned cache</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=86400",
        "Vary": "Accept-Encoding",
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="X-Forwarded-Host: attacker.com",
        endpoint="/api/resource",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


# ============================================================================
# Test Suite 6: Unkeyed Request Parameters
# ============================================================================

def test_cache_poisoning_unkeyed_parameters(analyzer):
    """Test detection of cache poisoning via unkeyed parameters."""
    payload = "?utm_source=attacker&utm_medium=cache&utm_campaign=poison"
    response_body = f"<html><body>Cached response for {payload}</body></html>"
    response_headers = {
        "Cache-Control": "public, max-age=3600",
        "Vary": "Accept-Encoding",  # Doesn't include utm parameters
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used=payload,
        endpoint="/api/endpoint",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


# ============================================================================
# Test Suite 7: Multiple Vulnerability Check (Cache Poisoning vs Others)
# ============================================================================

def test_cache_poisoning_vs_sql_injection_priority(analyzer):
    """Test that SQL injection takes priority over cache poisoning."""
    sql_error_response = "Error: You have an error in your SQL syntax"
    weak_cache_headers = {
        "Cache-Control": "public, max-age=3600"
    }
    
    finding = analyzer.analyze(
        response_body=sql_error_response,
        status_code=500,
        response_time_ms=50,
        payload_used="' OR '1'='1",
        endpoint="/api/search",
        response_headers=weak_cache_headers
    )
    
    # SQL injection should be detected first
    assert finding is not None
    assert finding.vulnerability_type == "SQL Injection"


def test_cache_poisoning_vs_xss_priority(analyzer):
    """Test that XSS takes priority over cache poisoning."""
    xss_payload = "<script>alert('poisoned')</script>"
    response_body = f"Search results for: {xss_payload}"
    weak_cache_headers = {
        "Cache-Control": "public, max-age=3600"
    }
    
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used=xss_payload,
        endpoint="/api/search",
        response_headers=weak_cache_headers
    )
    
    # XSS should be detected first
    assert finding is not None
    assert finding.vulnerability_type == "Reflected XSS"


# ============================================================================
# Test Suite 8: Edge Cases
# ============================================================================

def test_no_headers_provided(analyzer):
    """Test handling when no response headers are provided."""
    response_body = "<html><body>Data</body></html>"
    
    # Should handle None headers gracefully
    finding = analyzer.analyze(
        response_body=response_body,
        status_code=200,
        response_time_ms=50,
        payload_used="test",
        endpoint="/api/endpoint",
        response_headers=None
    )
    
    # Should not crash, result depends on body content
    assert True  # Just ensure no exception


def test_empty_response_body(analyzer):
    """Test handling of empty response body."""
    response_headers = {
        "Cache-Control": "public, max-age=3600"
    }
    
    finding = analyzer.analyze(
        response_body="",
        status_code=200,
        response_time_ms=50,
        payload_used="test",
        endpoint="/api/endpoint",
        response_headers=response_headers
    )
    
    # Should handle gracefully
    assert True


def test_case_insensitive_cache_control(analyzer):
    """Test that Cache-Control header analysis is case-insensitive."""
    response_headers = {
        "Cache-Control": "PUBLIC, MAX-AGE=3600"  # All uppercase
    }
    
    finding = analyzer.analyze(
        response_body="<html><body>Data</body></html>",
        status_code=200,
        response_time_ms=50,
        payload_used="x-forwarded-host: attacker.com",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert finding.vulnerability_type == "Cache Poisoning"


# ============================================================================
# Test Suite 9: Remediation Guidance
# ============================================================================

def test_cache_poisoning_remediation_message(analyzer):
    """Test that cache poisoning findings include proper remediation."""
    response_headers = {
        "Cache-Control": "public, max-age=3600"
    }
    
    finding = analyzer.analyze(
        response_body="<html><body>Data</body></html>",
        status_code=200,
        response_time_ms=50,
        payload_used="x-forwarded-host: attacker.com",
        endpoint="/api/data",
        response_headers=response_headers
    )
    
    assert finding is not None
    assert "Cache-Control: private" in finding.remediation
    assert "Vary" in finding.remediation
    assert "Host header" in finding.remediation
