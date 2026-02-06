
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple
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
            ]
        }

    def analyze(
        self, 
        response_body: str, 
        status_code: int, 
        response_time_ms: float,
        payload_used: str,
        endpoint: str = "",
        attack_type: str = "unknown"
    ) -> Optional[VulnerabilityFinding]:
        """
        Analyze an HTTP response for vulnerability indicators.
        
        Returns a VulnerabilityFinding if a vulnerability is detected,
        None otherwise.
        """
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

        # 4. Check for Timing Attacks (Basic)
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
