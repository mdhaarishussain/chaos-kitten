
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Dict, Any
import re

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class VulnerabilityFinding:
    vulnerability_type: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    evidence: str
    endpoint: str
    payload_used: str
    remediation: str

class ResponseAnalyzer:
    def __init__(self) -> None:
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> dict[str, list[str]]:
        """Load regex patterns for vulnerability detection."""
        return {
            "sql_injection": [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Microsoft SQL Server",
                r"OLE DB.* SQL Server",
                r"Warning.*mssql_",
                r"Msg \d+, Level \d+, State \d+",
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_",
                r"Warning.*SQLite3::",
                r"SQL syntax.*MariaDB",
            ],
            "path_traversal": [
                r"root:x:0:0:root",
                r"\[boot loader\]",
                r"\[extensions\]",
                r"\/usr\/bin\/",
                r"\/bin\/bash",
                r"win\.ini",
                r"system\.ini",
            ],
            "cache_poisoning": [
                r"attacker\.com",
                r"<script>alert\(",
                r"../../../",
                r"\.\.%5c",
            ]
        }

    def analyze(
        self, 
        response_body: str, 
        status_code: int, 
        response_time_ms: float,
        payload_used: str,
        endpoint: str = "",
        attack_type: str = "unknown",
        response_headers: Optional[Dict[str, str]] = None
    ) -> Optional[VulnerabilityFinding]:
        """
        Analyze an HTTP response for vulnerability indicators.
        
        Returns a VulnerabilityFinding if a vulnerability is detected,
        None otherwise.
        """
        if response_headers is None:
            response_headers = {}
            
        # 1. Check for SQL Injection
        is_sqli, sqli_confidence = self.detect_sql_injection(response_body)
        if is_sqli:
            return VulnerabilityFinding(
                vulnerability_type="SQL Injection",
                severity=Severity.CRITICAL,
                confidence=sqli_confidence,
                evidence="Database error message detected in response",
                endpoint=endpoint,
                payload_used=payload_used,
                remediation="Use parameterized queries (prepared statements) to prevent SQL injection."
            )

        # 2. Check for XSS Reflection
        is_xss, xss_confidence = self.detect_xss_reflection(response_body, payload_used)
        if is_xss:
            return VulnerabilityFinding(
                vulnerability_type="Reflected XSS",
                severity=Severity.HIGH,
                confidence=xss_confidence,
                evidence=f"Payload reflected in response: {payload_used}",
                endpoint=endpoint,
                payload_used=payload_used,
                remediation="Implement context-aware output encoding and valid input validation."
            )
            
        # 3. Check for Path Traversal
        is_pt, pt_confidence = self.detect_path_traversal(response_body)
        if is_pt:
            return VulnerabilityFinding(
                vulnerability_type="Path Traversal",
                severity=Severity.HIGH,
                confidence=pt_confidence,
                evidence="System file content detected in response",
                endpoint=endpoint,
                payload_used=payload_used,
                remediation="Validate user input against a strict allowlist and do not use input directly in file paths."
            )
        
        # 4. Check for Cache Poisoning
        is_cache_poison, cache_confidence, cache_evidence = self.detect_cache_poisoning(response_body, response_headers, payload_used)
        if is_cache_poison:
            return VulnerabilityFinding(
                vulnerability_type="Cache Poisoning",
                severity=Severity.HIGH,
                confidence=cache_confidence,
                evidence=cache_evidence,
                endpoint=endpoint,
                payload_used=payload_used,
                remediation="Set Cache-Control: private for sensitive responses, use Vary header properly, and validate Host header against whitelist."
            )

        # 5. Check for Timing Attacks (Basic)
        # Assuming a baseline or checking if response time is significantly high > 5000ms for this example
        if response_time_ms > 5000:
             return VulnerabilityFinding(
                vulnerability_type="Potential Timing Attack / DoS",
                severity=Severity.MEDIUM,
                confidence=0.6,
                evidence=f"Response time unusually high: {response_time_ms}ms",
                endpoint=endpoint,
                payload_used=payload_used,
                remediation="Limit processing time and ensure efficient query execution."
            )

        return None
    
    def detect_sql_injection(self, response: str) -> Tuple[bool, float]:
        """Check for SQL error messages indicating injection."""
        for pattern in self.patterns["sql_injection"]:
            if re.search(pattern, response, re.IGNORECASE):
                return True, 1.0
        return False, 0.0
    
    def detect_xss_reflection(self, response: str, payload: str) -> Tuple[bool, float]:
        """Check if XSS payload is reflected in response."""
        # Simple check: is the payload strictly present in the response?
        # A more advanced check would verify if it's executable (e.g., inside <script> tags or attrs)
        if payload and payload in response:
            return True, 0.9
        return False, 0.0
    
    def detect_path_traversal(self, response: str) -> Tuple[bool, float]:
        """Check for file content indicators."""
        for pattern in self.patterns["path_traversal"]:
            if re.search(pattern, response, re.IGNORECASE):
                return True, 1.0
        return False, 0.0
    
    def detect_cache_poisoning(
        self, 
        response_body: str, 
        response_headers: Dict[str, str],
        payload_used: str
    ) -> Tuple[bool, float, str]:
        """
        Detect cache poisoning vulnerabilities by analyzing cache headers and payload presence.
        
        Returns:
            Tuple[bool, float, str]: (is_vulnerable, confidence, evidence)
        """
        # 1. Check if payload appears in response body (indicates weak cache key)
        payload_in_body = payload_used in response_body if payload_used else False
        
        # 2. Analyze cache headers for weak configuration
        weak_cache_config = self._check_weak_cache_headers(response_headers)
        
        # 3. Check for dynamic content being cached
        is_cacheable = self._is_response_cacheable(response_headers)
        
        # 4. Check for lack of cache key variance
        lacks_vary_header = self._lacks_proper_vary_header(response_headers, payload_used)
        
        # If payload is in body AND response is cacheable with weak config, high confidence
        if payload_in_body and is_cacheable and weak_cache_config:
            evidence = (
                f"Payload reflected in response and response is publicly cacheable. "
                f"Cache-Control: {response_headers.get('Cache-Control', 'Not Set')}"
            )
            return True, 0.9, evidence
        
        # If weak caching + lacks vary header
        if weak_cache_config and lacks_vary_header:
            evidence = (
                f"Weak cache configuration detected. "
                f"Cache-Control: {response_headers.get('Cache-Control', 'Not Set')}, "
                f"Vary header: {response_headers.get('Vary', 'Not Set')}"
            )
            return True, 0.75, evidence
        
        # If just weak cache configuration
        if weak_cache_config and is_cacheable:
            evidence = f"Response is publicly cacheable: {response_headers.get('Cache-Control', 'Not Set')}"
            return True, 0.6, evidence
        
        return False, 0.0, ""
    
    def _check_weak_cache_headers(self, response_headers: Dict[str, str]) -> bool:
        """Check if cache headers are weakly configured (e.g., Cache-Control: public)."""
        cache_control = response_headers.get("Cache-Control", "").lower()
        
        # Weak configuration: public caching without proper restrictions
        weak_indicators = [
            "public" in cache_control and "no-cache" not in cache_control,
            "max-age=" in cache_control and int(re.findall(r"max-age=(\d+)", cache_control)[0]) > 300 if re.findall(r"max-age=(\d+)", cache_control) else False,
            "s-maxage=" in cache_control,  # Shared cache with extended TTL
        ]
        
        return any(weak_indicators)
    
    def _is_response_cacheable(self, response_headers: Dict[str, str]) -> bool:
        """Check if the response is marked as cacheable."""
        cache_control = response_headers.get("Cache-Control", "").lower()
        
        # Response is cacheable if it has max-age duration and not explicitly private
        cacheable = (
            "max-age=" in cache_control or 
            "expires" in response_headers
        ) and "private" not in cache_control and "no-store" not in cache_control
        
        return cacheable
    
    def _lacks_proper_vary_header(self, response_headers: Dict[str, str], payload_used: str) -> bool:
        """
        Check if response lacks proper Vary header for user-controlled parameters.
        
        If payload includes headers like X-Forwarded-Host or Host, the Vary header
        should include these to differentiate cache entries.
        """
        vary_header = response_headers.get("Vary", "").lower()
        
        # Common cache poisoning vectors via headers
        poisoning_headers = [
            "x-forwarded-host",
            "x-original-host",
            "x-host",
            "x-forwarded-for",
        ]
        
        # Check if poisoning vector is in payload but not in Vary header
        if payload_used:
            for header in poisoning_headers:
                if header in payload_used.lower() and header not in vary_header:
                    return True
        
        return False

