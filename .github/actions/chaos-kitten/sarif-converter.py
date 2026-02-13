#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

# Severity levels mapping
SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def load_results(report_dir):
    """Load scan results from JSON file."""
    results_path = Path(report_dir) / "results.json"
    if not results_path.exists():
        print(f"::error::Results file not found at {results_path}")
        sys.exit(1)

    with open(results_path) as f:
        return json.load(f)


def check_failure_condition(stats, threshold):
    """Check if vulnerabilities exceed severity threshold."""
    if threshold.lower() == "none" or threshold.lower() == "off":
        return False, []

    threshold_val = SEVERITY_LEVELS.get(threshold.lower(), 3)  # Default to high

    failed = False
    failure_reasons = []

    for severity, count in stats.items():
        if severity not in SEVERITY_LEVELS:
            continue

        if SEVERITY_LEVELS[severity] >= threshold_val and count > 0:
            failed = True
            failure_reasons.append(f"{count} {severity} vulnerabilities")

    return failed, failure_reasons


def generate_markdown_summary(stats, vulnerabilities, report_path):
    """Generate Markdown summary for PR comment."""
    summary = ["### 🐱 Chaos Kitten Security Scan Results"]

    # Summary table
    summary.append("\n| Severity | Count | status |")
    summary.append("|---|---|---|")

    icons = {
        "critical": "🔴",
        "high": "asd",  # wait "asd"?? Typo prevention: "🟠"
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
    }

    for severity in ["critical", "high", "medium", "low"]:
        count = stats.get(severity, 0)
        icon = icons.get(severity, "")
        status = "Pass" if count == 0 else "Fail"
        summary.append(f"| {icon} {severity.capitalize()} | {count} | {status} |")

    summary.append(f"\n**Total Vulnerabilities:** {stats.get('total', 0)}")

    # Top vulnerabilities
    if vulnerabilities:
        summary.append("\n#### Top Findings:")
        for v in vulnerabilities[:5]:
            summary.append(
                f"- **[{v.get('severity', 'unknown').upper()}]** {v.get('title', 'Unknown Issue')}"
            )

    summary.append(f"\n[View Full Report]({report_path})")

    return "\n".join(summary)


def main():
    if len(sys.argv) < 3:
        print("Usage: sarif-converter.py <report_dir> <severity_threshold>")
        sys.exit(1)

    report_dir = sys.argv[1]
    threshold = sys.argv[2]

    print(f"::group::Processing Scan Results (Threshold: {threshold})")

    results = load_results(report_dir)

    # Calculate stats if not present in root (depends on implementation)
    # The current Reporter implementation puts counts in root
    stats = {
        "critical": results.get("critical", 0),
        "high": results.get("high", 0),
        "medium": results.get("medium", 0),
        "low": results.get("low", 0),
        "total": results.get("total", 0),
    }

    vulns = results.get("vulnerabilities", [])

    # Check failure
    failed, reasons = check_failure_condition(stats, threshold)

    # Generate outputs
    markdown_summary = generate_markdown_summary(stats, vulns, "results.html")

    # Write summary to file for GITHUB_STEP_SUMMARY or similar
    with open("scan-summary.md", "w", encoding="utf-8") as f:
        f.write(markdown_summary)

    # Output for GitHub Actions
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"vulnerabilities-found={stats['total']}\n")
    else:
        print(f"::set-output name=vulnerabilities-found::{stats['total']}")

    if failed:
        print(
            f"::error::Pipeline failed due to severe vulnerabilities: {', '.join(reasons)}"
        )
        print("::endgroup::")
        sys.exit(1)
    else:
        print("::notice::Security scan passed validation.")
        print("::endgroup::")
        sys.exit(0)


if __name__ == "__main__":
    main()
