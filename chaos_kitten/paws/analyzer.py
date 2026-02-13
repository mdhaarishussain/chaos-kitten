"""Response Analyzer Module.

This module analyzes HTTP responses to detect successful vulnerability exploitation
based on error patterns, timing anomalies, data leakage, and status codes.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import re
import logging

logger = logging.getLogger(__name__)

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    vulnerability_type: str
    severity: Severity = Severity.MEDIUM
    evidence: str = ""
    endpoint: str = ""
    payload: str = ""
    recommendation: str = ""
    confidence: float = 1.0  # 0.0 to 1.0

class ResponseAnalyzer:
    """Analyzes responses for signs of vulnerability."""

    def __init__(self) -> None:
        # Pre-compile regex patterns for efficiency
        self.error_patterns = self._load_error_patterns()
        self.sensitive_patterns = self._load_sensitive_patterns()

    def _load_error_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load built-in error patterns."""
        patterns = {
            "SQL Injection": [
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
                r"unclosed quotation mark after the character string",
            ],
            "NoSQL Injection": [
                r"MongoError", 
                r"MongoDB", 
                r"mongo",
                r"E11000 duplicate key error",
                r"WriteError",
                r"CastError",
                r"failed to parse",
                r"Object representing the BSON type",
                r"unterminated string literal",
                r"\$where",
                r"\$regex",
                r"unexpected token",
                r"Illegal character",
                r"SyntaxError",
            ],
            "Application Error": [
                r"Traceback \(most recent call last\):",
                r"File \"[^\"]+\", line \d+, in",
                r"NameError:",
                r"TypeError:",
                r"ValueError:",
                r"SyntaxError:",
                r"at [\w\.]+\(", # Java/C# stack traces often look like "at Namespace.Class.Method("
            ]
        }
        
        compiled = {}
        for category, regex_list in patterns.items():
            compiled[category] = [re.compile(p, re.IGNORECASE) for p in regex_list]
        return compiled

    def _load_sensitive_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load patterns for data leakage."""
        patterns = {
            "Path Disclosure": [
                r"(?:[a-zA-Z]:)?\\[a-zA-Z0-9_\-\\]+\\\w+",  # Windows path
                r"(?<!\w)/var/www/\w+",  # Common Linux webroot
                r"(?<!\w)/home/\w+",
                r"(?<!\w)/etc/passwd",
            ],
            "Internal IP": [
                r"192\.168\.\d{1,3}\.\d{1,3}",
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
            ]
        }
        compiled = {}
        for category, regex_list in patterns.items():
            compiled[category] = [re.compile(p) for p in regex_list]
        return compiled

    def analyze(self, response: dict, attack_profile: dict, endpoint: str = "", payload: str = "") -> Optional[Finding]:
        """Main analysis method - checks all indicators.
        
        Args:
            response: Dictionary containing 'status_code', 'body' (text), 'elapsed_ms', 'headers'.
            attack_profile: Dictionary containing the attack definition, including 'success_indicators'.
            endpoint: The endpoint that was tested.
            payload: The payload that was used.
            
        Returns:
            A Finding object if a vulnerability is detected, else None.
        """
        body = response.get("body", "")
        status_code = response.get("status_code", 0)
        elapsed_ms = response.get("elapsed_ms", 0.0)
        
        success_indicators = attack_profile.get("success_indicators", {})
        
        # 1. Custom Indicators (High Confidence) via Attack Profile
        finding = self._check_custom_indicators(response, success_indicators)
        if finding:
            finding.endpoint = endpoint
            finding.payload = payload
            # If no type specified infinding, use profile info
            if not finding.vulnerability_type:
                 finding.vulnerability_type = attack_profile.get("name", "Unknown Vulnerability")
            if not finding.recommendation:
                finding.recommendation = attack_profile.get("remediation", "Check input sanitization.")
            
            # Map string severity to Enum if needed
            profile_severity = attack_profile.get("severity", "medium").lower()
            try:
                finding.severity = Severity(profile_severity)
            except ValueError:
                finding.severity = Severity.MEDIUM
                
            return finding
            
        # 2. Generic Error Patterns (Medium Confidence)
        errors = self.check_error_patterns(body)
        if errors:
            issue_type = errors[0].split(":")[0]  # rough category
            return Finding(
                vulnerability_type=f"Potential {issue_type} (Error Leak)",
                severity=Severity.MEDIUM,
                evidence=f"Error pattern matched: {errors[0]}",
                endpoint=endpoint,
                payload=payload,
                recommendation="Disable verbose error messages in production.",
                confidence=0.7
            )

        # 3. Data Leakage (Medium Confidence)
        leaks = self.check_data_leakage(body)
        if leaks:
            return Finding(
                vulnerability_type="Information Disclosure",
                severity=Severity.LOW,
                evidence=f"Sensitive info leaked: {leaks[0]}",
                endpoint=endpoint,
                payload=payload,
                recommendation="Ensure sensitive internal information is not exposed in responses.",
                confidence=0.6
            )
            
        # 4. Timing Anomalies (Profile based)
        # Note: Generic timing check without baseline is hard, so we rely on profile 'response_time_gt'
        # which is handled in _check_custom_indicators usually.
        
        return None

    def _check_custom_indicators(self, response: dict, indicators: dict) -> Optional[Finding]:
        """Check against success indicators defined in the attack profile."""
        if not indicators:
            return None
            
        body = response.get("body", "")
        status_code = response.get("status_code")
        elapsed_ms = response.get("elapsed_ms", 0) / 1000.0  # convert to seconds

        # Check response_contains
        if "response_contains" in indicators:
            for pattern in indicators["response_contains"]:
                if pattern in body:
                    return Finding(
                        vulnerability_type="", # Filled by caller
                        evidence=f"Response contained success indicator string: '{pattern}'",
                        confidence=0.9
                    )

        # Check status_codes
        if "status_codes" in indicators:
            expected_codes = indicators["status_codes"]
            if status_code in expected_codes:
                # Be careful: 200/500 might be common.
                # If specific list is provided, we assume it's a signal.
                return Finding(
                    vulnerability_type="",
                    evidence=f"Status code {status_code} matched success criteria {expected_codes}",
                    confidence=0.8
                )
        
        # Check response_time_gt
        if "response_time_gt" in indicators:
            limit = indicators["response_time_gt"]
            if elapsed_ms > limit:
                 return Finding(
                    vulnerability_type="",
                    evidence=f"Response time {elapsed_ms:.2f}s > {limit}s",
                    confidence=0.8
                )

        return None

    def check_error_patterns(self, body: str) -> List[str]:
        """Detect error messages that reveal vulnerabilities."""
        detected = []
        for category, patterns in self.error_patterns.items():
            for regex in patterns:
                match = regex.search(body)
                if match:
                    detected.append(f"{category}: {match.group(0)[:100]}...") # Truncate matches
                    break # One per category is enough usually
        return detected

    def check_status_anomalies(self, status_code: int, expected: int) -> bool:
        """Detect unexpected status codes.
        
        This is a simple heuristic. In a real scenario, we'd need more context.
        """
        return status_code != expected and status_code >= 500

    def check_timing_anomalies(self, elapsed_ms: float, baseline_ms: float) -> bool:
        """Detect time-based injection (response significantly slower)."""
        # E.g., > 2000ms and > 5x baseline
        return elapsed_ms > 2000 and elapsed_ms > (baseline_ms * 5)

    def check_data_leakage(self, body: str) -> List[str]:
        """Detect sensitive data in responses."""
        detected = []
        for category, patterns in self.sensitive_patterns.items():
            for regex in patterns:
                match = regex.search(body)
                if match:
                    detected.append(f"{category}: {match.group(0)}")
        return detected
