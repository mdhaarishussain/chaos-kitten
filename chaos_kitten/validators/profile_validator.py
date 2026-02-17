from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
import yaml
import re
import os
from pathlib import Path

@dataclass
class ValidationReport:
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

class AttackProfileValidator:
    REQUIRED_FIELDS = ['name', 'category', 'severity', 'payloads', 'success_indicators']
    VALID_SEVERITIES = ['critical', 'high', 'medium', 'low']
    VALID_CATEGORIES = [
        'sql_injection', 'xss', 'idor', 'bola', 'auth_bypass', 'xxe', 
        'deserialization', 'jwt', 'mass_assignment', 'business_logic',
        'ssrf', 'csrf', 'rce', 'command_injection', 'path_traversal',
        'access-control', 'authentication', 'request-forgery' # Added from existing profiles
    ]
    
    def validate_profile(self, profile_path: str) -> ValidationReport:
        report = ValidationReport(is_valid=True)
        path = Path(profile_path)
        
        if not path.exists():
            report.is_valid = False
            report.errors.append(f"File not found: {profile_path}")
            return report

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
        except yaml.YAMLError as e:
            report.is_valid = False
            report.errors.append(f"Invalid YAML syntax: {e}")
            return report
        except Exception as e:
            report.is_valid = False
            report.errors.append(f"Error reading file: {e}")
            return report
            
        if not isinstance(content, dict):
            report.is_valid = False
            report.errors.append("Profile root must be a dictionary/map")
            return report

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in content:
                report.is_valid = False
                report.errors.append(f"Missing required field: '{field}'")
        
        if not report.is_valid:
            return report
            
        # Validate name
        if not isinstance(content.get('name'), str) or not content.get('name').strip():
            report.is_valid = False
            report.errors.append("Field 'name' must be a non-empty string")

        # Validate severity
        severity = content.get('severity')
        if severity not in self.VALID_SEVERITIES:
            report.is_valid = False
            report.errors.append(f"Invalid severity '{severity}'. Must be one of: {', '.join(self.VALID_SEVERITIES)}")
            
        # Validate category
        category = content.get('category')
        if category not in self.VALID_CATEGORIES:
            # Check if it's a known category or valid string
            if not isinstance(category, str):
                 report.is_valid = False
                 report.errors.append(f"Category must be a string")
            else:
                 report.warnings.append(f"Unknown category '{category}'. Consider using standard categories: {', '.join(self.VALID_CATEGORIES[:5])}...")

        # Validate payloads
        payloads = content.get('payloads')
        if not isinstance(payloads, list):
            report.is_valid = False
            report.errors.append("Field 'payloads' must be a list")
        elif len(payloads) == 0:
            report.is_valid = False
            report.errors.append("Field 'payloads' cannot be empty")
        else:
            for i, p in enumerate(payloads):
                if isinstance(p, dict):
                    if 'value' not in p:
                        report.errors.append(f"Payload at index {i} missing 'value' field")
                        report.is_valid = False
                elif not isinstance(p, str):
                    report.errors.append(f"Payload at index {i} must be a string or object with 'value'")
                    report.is_valid = False

        # Validate success_indicators
        indicators = content.get('success_indicators')
        if not isinstance(indicators, dict):
             report.is_valid = False
             report.errors.append("Field 'success_indicators' must be a dictionary")
        else:
             if not any(k in indicators for k in ['response_contains', 'status_codes', 'response_differs_from', 'absence_of', 'response_time_gt', 'headers_present']):
                 report.warnings.append("No standard success indicators found (response_contains, status_codes, etc.)")

        # Validate references (CWE/OWASP)
        references = content.get('references')
        if references:
            if not isinstance(references, list):
                report.errors.append("Field 'references' must be a list")
                report.is_valid = False
            else:
                for ref in references:
                    if not isinstance(ref, str):
                        continue
                    if 'cwe.mitre.org' in ref:
                        # naive check for CWE format in URL
                        if not re.search(r'CWE-\d+', ref, re.IGNORECASE) and not re.search(r'definitions/\d+\.html', ref):
                             report.warnings.append(f"Reference '{ref}' might not follow standard CWE format")
                    if 'owasp.org' in ref:
                        # Check for valid structure if possible, usually just verify link format
                        pass

        return report

    def validate_all_profiles(self, toys_dir: str) -> Dict[str, ValidationReport]:
        results = {}
        path = Path(toys_dir)
        
        if not path.exists():
             return {"error": ValidationReport(is_valid=False, errors=[f"Path not found: {toys_dir}"])}
             
        if path.is_file():
            results[path.name] = self.validate_profile(str(path))
        elif path.is_dir():
            for file_path in path.glob('*.yaml'):
                results[file_path.name] = self.validate_profile(str(file_path))
        else:
             return {"error": ValidationReport(is_valid=False, errors=[f"Invalid path type: {toys_dir}"])}
            
        return results
