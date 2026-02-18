import pytest
from chaos_kitten.brain.response_analyzer import ResponseAnalyzer, VulnerabilityFinding, Severity

def test_detect_aws_access_key():
    analyzer = ResponseAnalyzer()
    response = "User config: { 'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE' }"
    
    finding = analyzer.analyze(response, 200, 100, "")
    
    assert finding is not None
    assert finding.vulnerability_type == "Exposed Secret / API Key"
    assert finding.severity == Severity.CRITICAL
    assert "AWS Access Key" in finding.evidence

def test_detect_google_api_key():
    analyzer = ResponseAnalyzer()
    response = "var apiKey = 'AIzaSyD-G8S9-s8_s8d7-s8d7s8d7s8d7s8d7'"
    
    finding = analyzer.analyze(response, 200, 100, "")
    
    assert finding is not None
    assert "Google API Key" in finding.evidence

def test_detect_private_key():
    analyzer = ResponseAnalyzer()
    response = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    
    finding = analyzer.analyze(response, 200, 100, "")
    
    assert finding is not None
    assert "Private Key" in finding.evidence

def test_detect_generic_api_key():
    analyzer = ResponseAnalyzer()
    response = "\"api_key\": \"abcdef1234567890abcdef1234567890\""
    
    finding = analyzer.analyze(response, 200, 100, "")
    assert finding is not None
    assert "Potential Secret" in finding.evidence

def test_no_secret():
    analyzer = ResponseAnalyzer()
    response = "Welcome to our API. No secrets here!"
    
    finding = analyzer.analyze(response, 200, 100, "")
    assert finding is None
