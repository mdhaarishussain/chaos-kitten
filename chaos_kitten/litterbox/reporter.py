"""Security Report Generator."""

from pathlib import Path
from typing import Any, Dict, List, Union
from datetime import datetime
import json
import logging
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, TemplateError

logger = logging.getLogger(__name__)


class Reporter:
    """Generate security scan reports.

    Supports multiple output formats:
    - HTML (with nice styling)
    - Markdown
    - JSON (for programmatic access)

    Reports include:
    - Executive summary
    - Detailed vulnerability descriptions
    - Proof of Concept scripts (curl commands)
    - Remediation suggestions
    """

    def __init__(
        self,
        output_path: Union[str, Path] = "./reports",
        output_format: str = "html",
        include_poc: bool = True,
        include_remediation: bool = True,
    ) -> None:
        """Initialize the reporter.

        Args:
            output_path: Directory to save reports
            output_format: Report format (html, markdown, json)
            include_poc: Include Proof of Concept scripts
            include_remediation: Include remediation suggestions
        """
        self.output_path = Path(output_path)
        self.output_format = output_format
        self.include_poc = include_poc
        self.include_remediation = include_remediation

        # Initialize template engine
        self._setup_template_engine()

    def generate(
        self,
        scan_results: Dict[str, Any],
        target_url: str,
    ) -> Path:
        """Generate a security report.

        Args:
            scan_results: Results from the security scan
            target_url: URL that was scanned

        Returns:
            Path to the generated report file
        """
        # Create output directory
        self.output_path.mkdir(parents=True, exist_ok=True)

        # Generate filename
        # CI/CD Compatibility: If sarif, use standard names
        if self.output_format == "sarif":
            filename = "results.sarif"
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"chaos-kitten-{timestamp}.{self._get_extension()}"

        output_file = self.output_path / filename

        # Generate report based on format
        if self.output_format == "html":
            content = self._generate_html(scan_results, target_url)
        elif self.output_format == "markdown":
            content = self._generate_markdown(scan_results, target_url)
        elif self.output_format == "sarif":
            # Recalculate summary to get flat counts
            vulns = self._validate_vulnerability_data(scan_results)
            
            # Pass validated vulns to sarif generator to avoid double validation
            content = self._generate_sarif_from_vulns(vulns, target_url)
            
            # Also generate minimal results.json for the CI script
            # The CI script expects report.critical, report.high etc.
            summary = self._calculate_executive_summary(vulns)
            counts = summary["severity_breakdown"]

            ci_json = {
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "total": summary["total_vulnerabilities"],
                "vulnerabilities": vulns,
            }
            (self.output_path / "results.json").write_text(
                json.dumps(ci_json, indent=2), encoding="utf-8"
            )
        else:
            content = self._generate_json(scan_results, target_url)

        output_file.write_text(content, encoding="utf-8")
        return output_file

    def _get_extension(self) -> str:
        """Get file extension for the output format."""
        extensions = {
            "html": "html",
            "markdown": "md",
            "json": "json",
            "sarif": "sarif",
        }
        return extensions.get(self.output_format, "txt")

    def _setup_template_engine(self) -> None:
        """Set up Jinja2 template engine with proper error handling."""
        try:
            # Get the template directory path relative to this file
            template_dir = Path(__file__).parent / "templates"

            if not template_dir.exists():
                raise FileNotFoundError(
                    f"Template directory not found: {template_dir}. "
                    f"Please ensure the templates directory exists in {template_dir.parent}"
                )

            # Initialize Jinja2 environment
            self.template_env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=True,  # Security: prevent XSS in HTML reports
                trim_blocks=True,
                lstrip_blocks=True,
            )

        except PermissionError as e:
            raise PermissionError(
                f"Permission denied accessing template directory: {template_dir}. "
                f"Please check file permissions. Original error: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize template engine: {e}. "
                f"Please check template directory setup."
            ) from e

    def _load_template(self, template_name: str) -> Any:
        """Load a Jinja2 template with error handling.

        Args:
            template_name: Name of the template file to load

        Returns:
            Loaded Jinja2 template object

        Raises:
            FileNotFoundError: If template file is missing
            TemplateError: If template has syntax errors
        """
        try:
            return self.template_env.get_template(template_name)
        except TemplateNotFound as e:
            template_dir = Path(__file__).parent / "templates"
            raise FileNotFoundError(
                f"Template file '{template_name}' not found in {template_dir}. "
                f"Available templates: {list(template_dir.glob('*.html')) + list(template_dir.glob('*.md'))}"
            ) from e
        except TemplateError as e:
            raise TemplateError(
                f"Template '{template_name}' has syntax errors: {e}. "
                f"Please check the template file for valid Jinja2 syntax."
            ) from e

    def _validate_vulnerability_data(
        self, results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Validate and process vulnerability findings data.

        Args:
            results: Raw scan results containing vulnerability findings

        Returns:
            List of validated vulnerability findings

        Raises:
            ValueError: If vulnerability data is invalid
            TypeError: If vulnerability data types are incorrect
        """
        if not isinstance(results, dict):
            raise TypeError(f"Expected dict for results, got {type(results)}")

        # Extract vulnerabilities from results
        vulnerabilities = results.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise TypeError(
                f"Expected list for vulnerabilities, got {type(vulnerabilities)}"
            )

        validated_vulns = []
        used_ids = set()

        for i, vuln in enumerate(vulnerabilities):
            if not isinstance(vuln, dict):
                raise TypeError(f"Vulnerability {i} must be a dict, got {type(vuln)}")

            # Validate required fields
            required_fields = ["title", "description"]
            for field in required_fields:
                if field not in vuln:
                    raise ValueError(
                        f"Vulnerability {i} missing required field: {field}"
                    )
                if not isinstance(vuln[field], str) or not vuln[field].strip():
                    raise ValueError(
                        f"Vulnerability {i} field '{field}' must be a non-empty string"
                    )

            # Add default values for optional fields
            validated_vuln = vuln.copy()
            validated_vuln.setdefault("severity", "medium")
            validated_vuln.setdefault("proof_of_concept", "")
            validated_vuln.setdefault(
                "remediation", "No remediation guidance available."
            )
            validated_vuln.setdefault("endpoint", "")
            validated_vuln.setdefault("method", "GET")

            # Handle ID assignment and uniqueness validation
            vuln_id = vuln.get("id", f"vuln_{i}")
            if vuln_id in used_ids:
                # Generate a unique ID if duplicate found
                counter = 1
                original_id = vuln_id
                while vuln_id in used_ids:
                    vuln_id = f"{original_id}_{counter}"
                    counter += 1
                logger.warning(
                    f"Warning: Duplicate vulnerability ID '{original_id}' found, using '{vuln_id}' instead"
                )

            validated_vuln["id"] = vuln_id
            used_ids.add(vuln_id)

            # Validate severity level
            valid_severities = ["critical", "high", "medium", "low"]
            if validated_vuln["severity"].lower() not in valid_severities:
                logger.warning(
                    f"Warning: Invalid severity '{validated_vuln['severity']}' for vulnerability {i}, defaulting to 'medium'"
                )
                validated_vuln["severity"] = "medium"
            else:
                validated_vuln["severity"] = validated_vuln["severity"].lower()

            validated_vulns.append(validated_vuln)

        return validated_vulns

    def _calculate_executive_summary(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate executive summary statistics from vulnerability findings.

        Args:
            vulnerabilities: List of validated vulnerability findings

        Returns:
            Dictionary containing executive summary statistics
        """
        total_vulns = len(vulnerabilities)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "endpoints_tested": len(
                set(
                    vuln.get("endpoint", "")
                    for vuln in vulnerabilities
                    if vuln.get("endpoint")
                )
            ),
        }

    def _process_vulnerability_for_display(
        self, vuln: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process a vulnerability for display in templates.

        Args:
            vuln: Raw vulnerability data

        Returns:
            Processed vulnerability data with display formatting
        """
        severity = vuln.get("severity", "medium").lower()

        # Map severity to CSS classes
        severity_mapping = {
            "critical": {"class": "severity-critical", "color": "red"},
            "high": {"class": "severity-high", "color": "orange"},
            "medium": {"class": "severity-medium", "color": "yellow"},
            "low": {"class": "severity-low", "color": "green"},
        }

        severity_info = severity_mapping.get(severity, severity_mapping["medium"])

        processed = vuln.copy()
        processed.update(
            {
                "severity_class": severity_info["class"],
                "severity_color": severity_info["color"],
                "cat_message": (
                    f"🐱 I found a shiny secret! {severity.title()} severity issue."
                    if "Secret" in vuln.get("title", "") or "Key" in vuln.get("title", "")
                    else
                    f"🐱 I knocked this vase over! Found {severity} severity issue."
                ),
                "poc": vuln.get(
                    "proof_of_concept", ""
                ),  # Map proof_of_concept to poc for template
            }
        )

        return processed

    def _generate_html(self, results: Dict[str, Any], target: str) -> str:
        """Generate HTML report using Jinja2 template.

        Args:
            results: Vulnerability scan results
            target: Target URL that was scanned

        Returns:
            Generated HTML report content

        Raises:
            TemplateError: If template rendering fails
            ValueError: If vulnerability data is invalid
        """
        try:
            # Validate and process vulnerability data
            vulnerabilities = self._validate_vulnerability_data(results)

            # Calculate executive summary
            summary = self._calculate_executive_summary(vulnerabilities)

            # Process vulnerabilities for display
            processed_vulns = [
                self._process_vulnerability_for_display(vuln)
                for vuln in vulnerabilities
            ]

            # Prepare template context
            context = {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target,
                "version": "0.1.0",  # TODO: Get from package metadata
                "endpoints_tested": summary["endpoints_tested"],
                "total_vulns": summary["total_vulnerabilities"],
                "critical_count": summary["severity_breakdown"]["critical"],
                "high_count": summary["severity_breakdown"]["high"],
                "medium_count": summary["severity_breakdown"]["medium"],
                "low_count": summary["severity_breakdown"]["low"],
                "vulnerabilities": processed_vulns,
            }

            # Load and render template
            template = self._load_template("report.html")
            return template.render(**context)

        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid vulnerability data: {e}") from e
        except TemplateError as e:
            raise TemplateError(f"HTML template rendering failed: {e}") from e

    def _generate_markdown(self, results: Dict[str, Any], target: str) -> str:
        """Generate Markdown report using Jinja2 template.

        Args:
            results: Vulnerability scan results
            target: Target URL that was scanned

        Returns:
            Generated Markdown report content

        Raises:
            TemplateError: If template rendering fails
            ValueError: If vulnerability data is invalid
        """
        try:
            # Validate and process vulnerability data
            vulnerabilities = self._validate_vulnerability_data(results)

            # Calculate executive summary
            summary = self._calculate_executive_summary(vulnerabilities)

            # Process vulnerabilities for display (Markdown doesn't need CSS classes)
            processed_vulns = []
            for vuln in vulnerabilities:
                processed = vuln.copy()
                processed["cat_message"] = (
                    f"🐱 I knocked this vase over! Found {vuln.get('severity', 'medium')} severity issue."
                )
                processed["poc"] = vuln.get(
                    "proof_of_concept", ""
                )  # Map proof_of_concept to poc for template
                processed_vulns.append(processed)

            # Prepare template context
            context = {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target,
                "version": "0.1.0",  # TODO: Get from package metadata
                "endpoints_tested": summary["endpoints_tested"],
                "total_vulns": summary["total_vulnerabilities"],
                "critical_count": summary["severity_breakdown"]["critical"],
                "high_count": summary["severity_breakdown"]["high"],
                "medium_count": summary["severity_breakdown"]["medium"],
                "low_count": summary["severity_breakdown"]["low"],
                "vulnerabilities": processed_vulns,
                "endpoints": [  # Mock endpoint data for template
                    {
                        "method": vuln.get("method", "GET"),
                        "path": vuln.get("endpoint") or "/unknown",
                        "status": "Tested",
                    }
                    for vuln in vulnerabilities
                ],
                "time_taken": "< 1 minute",  # Mock timing data
            }

            # Load and render template
            template = self._load_template("report.md")
            return template.render(**context)

        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid vulnerability data: {e}") from e
        except TemplateError as e:
            raise TemplateError(f"Markdown template rendering failed: {e}") from e

    def _generate_json(self, results: Dict[str, Any], target: str) -> str:
        """Generate JSON report.

        Args:
            results: Vulnerability scan results
            target: Target URL that was scanned

        Returns:
            Generated JSON report content
        """
        try:
            # Validate and process vulnerability data
            vulnerabilities = self._validate_vulnerability_data(results)

            # Calculate executive summary
            summary = self._calculate_executive_summary(vulnerabilities)

            # Prepare JSON structure
            report_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "target_url": target,
                    "tool_version": "0.1.0",
                    "report_format": "json",
                },
                "executive_summary": summary,
                "vulnerabilities": vulnerabilities,
            }

            return json.dumps(report_data, indent=2, ensure_ascii=False)

        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid vulnerability data for JSON export: {e}") from e

    def _generate_sarif(self, results: Dict[str, Any], target: str) -> str:
        """Generate SARIF report.

        Args:
            results: Vulnerability scan results
            target: Target URL that was scanned

        Returns:
            Generated SARIF report content
        """
        try:
            vulnerabilities = self._validate_vulnerability_data(results)
            return self._generate_sarif_from_vulns(vulnerabilities, target)
        except Exception as e:
            raise ValueError(f"Failed to generate SARIF report: {e}") from e

    def _generate_sarif_from_vulns(self, vulnerabilities: List[Dict[str, Any]], target: str) -> str:
        """Generate SARIF report from validated vulnerabilities.

        Args:
            vulnerabilities: List of validated vulnerability findings
            target: Target URL that was scanned

        Returns:
            Generated SARIF report content
        """
        try:
            rules = []
            sarif_results = []
            rule_indices = {}

            for index, vuln in enumerate(vulnerabilities):
                vuln_type = vuln.get("type", "unknown")

                # Add rule if not exists
                if vuln_type not in rule_indices:
                    rule_indices[vuln_type] = len(rules)
                    rules.append(
                        {
                            "id": vuln_type,
                            "name": vuln.get("title", vuln_type),
                            "shortDescription": {
                                "text": vuln.get("title", vuln_type)
                            },
                            "fullDescription": {"text": vuln.get("description", "")},
                            "help": {"text": vuln.get("remediation", "")},
                            "helpUri": "https://github.com/mdhaarishussain/chaos-kitten",
                            "defaultConfiguration": {
                                "level": self._map_severity_to_sarif(
                                    vuln.get("severity", "medium")
                                )
                            },
                        }
                    )

                # Add result
                sarif_results.append(
                    {
                        "ruleId": vuln_type,
                        "ruleIndex": rule_indices[vuln_type],
                        "level": self._map_severity_to_sarif(
                            vuln.get("severity", "medium")
                        ),
                        "message": {"text": vuln.get("description", "")},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        # Use endpoint as location, fallback to target if empty
                                        "uri": vuln.get("endpoint") or target
                                    }
                                }
                            }
                        ],
                        "properties": {
                            "payload": vuln.get("payload", ""),
                            "proof_of_concept": vuln.get("proof_of_concept", ""),
                            "remediation": vuln.get("remediation", ""),
                            "evidence": vuln.get("evidence", "")
                        }
                    }
                )

            sarif_report = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "chaos-kitten",
                                "version": "0.1.0",
                                "rules": rules,
                            }
                        },
                        "results": sarif_results,
                    }
                ],
            }

            return json.dumps(sarif_report, indent=2)

        except Exception as e:
            raise ValueError(f"Failed to generate SARIF report: {e}") from e

    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map severity to SARIF level."""
        severity = severity.lower()
        if severity in ["critical", "high"]:
            return "error"
        elif severity == "medium":
            return "warning"
        else:
            return "note"
