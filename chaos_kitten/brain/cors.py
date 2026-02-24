from typing import Dict, List

def analyze_cors(headers: Dict[str, str]) -> List[dict]:
    findings = []

    aco = headers.get("access-control-allow-origin", "")
    acc = headers.get("access-control-allow-credentials", "")
    acm = headers.get("access-control-allow-methods", "")

    # Wildcard origin
    if aco.strip() == "*":
        findings.append({
            "issue": "Wildcard ACAO",
            "severity": "high"
        })

    # Credential exposure (avoid duplicate when wildcard origin already present)
    if acc.lower() == "true" and aco and aco.strip() != "*":
        findings.append({
            "issue": "Credentialed CORS allowed",
            "severity": "critical"
    })

    # Methods exposed
    dangerous = ["PUT", "DELETE", "PATCH"]
    allowed_methods = [m.strip().upper() for m in acm.split(",")]
    if any(m in allowed_methods for m in dangerous):
        findings.append({
            "issue": "Dangerous methods exposed via CORS",
            "severity": "medium"
        })

    return findings