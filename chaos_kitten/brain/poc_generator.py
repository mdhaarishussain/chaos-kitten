"""Autonomous Exploit PoC Generator for Chaos Kitten.

When ResponseAnalyzer flags a high/critical finding, this module uses an LLM
to generate a standalone Python script (using ``httpx``) or a ``curl`` command
that reproduces the vulnerability, giving security teams a concrete proof of
concept they can hand directly to developers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

POC_GENERATION_PROMPT = textwrap.dedent("""\
    You are an expert penetration tester writing a proof-of-concept script.

    A vulnerability scanner has detected the following issue:

    Vulnerability Type : {vulnerability_type}
    Severity           : {severity}
    Endpoint           : {endpoint}
    HTTP Method        : {method}
    Payload Used       : {payload}
    Evidence           : {evidence}
    Base URL           : {base_url}

    Write a MINIMAL, standalone Python script that:
    1. Uses the ``httpx`` library (``import httpx``).
    2. Sends the exact request that triggered the finding.
    3. Prints whether the vulnerability was successfully reproduced,
       including the relevant part of the response.
    4. Includes clear comments explaining each step.
    5. Uses ``if __name__ == "__main__":`` as entry-point.

    Also provide the equivalent ``curl`` command as a comment at the top of
    the script.

    Respond with ONLY the Python code.  Do NOT wrap it in markdown code
    fences or add any explanation outside the script.
""")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PoCGenerator:
    """Generate standalone exploit-reproduction scripts for confirmed findings.

    Parameters
    ----------
    base_url : str
        Target application base URL (e.g. ``http://localhost:8080``).
    output_dir : str | Path
        Directory where generated PoC scripts are written.
        Created automatically if it does not exist.
    llm_provider : str
        LLM backend to use (``anthropic``, ``openai``, ``ollama``).
    temperature : float
        Sampling temperature for the LLM.
    """

    SEVERITY_THRESHOLD = ("high", "critical")

    def __init__(
        self,
        base_url: str = "",
        output_dir: str = "pocs",
        llm_provider: str = "anthropic",
        temperature: float = 0.3,
    ) -> None:
        self.base_url = base_url
        self.output_dir = Path(output_dir)
        self.llm_provider = llm_provider.lower()
        self.temperature = temperature
        self.llm = self._init_llm()

    # ------------------------------------------------------------------
    # LLM initialisation (mirrors AttackPlanner pattern)
    # ------------------------------------------------------------------

    def _init_llm(self) -> Any:
        """Initialise the backing language model.

        Returns ``None`` when the required provider package is missing so
        that the generator degrades gracefully to template-based PoCs.
        """
        try:
            if self.llm_provider == "anthropic":
                from langchain_anthropic import ChatAnthropic
                return ChatAnthropic(
                    model="claude-3-5-sonnet-20241022",
                    temperature=self.temperature,
                )
            if self.llm_provider == "openai":
                from langchain_openai import ChatOpenAI
                return ChatOpenAI(
                    model="gpt-4o",
                    temperature=self.temperature,
                )
            if self.llm_provider == "ollama":
                from langchain_ollama import ChatOllama
                return ChatOllama(
                    model="llama3",
                    temperature=self.temperature,
                )
            logger.warning(
                "Unknown LLM provider %s – falling back to anthropic.",
                self.llm_provider,
            )
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(
                model="claude-3-5-sonnet-20241022",
                temperature=self.temperature,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM init failed (%s); PoCs will use templates.", exc)
            return None

    # ------------------------------------------------------------------
    # Core generation
    # ------------------------------------------------------------------

    def generate(self, finding: Dict[str, Any]) -> Optional[str]:
        """Generate a PoC script for a single finding.

        Parameters
        ----------
        finding : dict
            A finding dictionary as produced by ``ResponseAnalyzer`` or the
            orchestrator.  Expected keys include ``vulnerability_type``,
            ``severity``, ``endpoint``, ``payload``, ``evidence``.

        Returns
        -------
        str | None
            Absolute path to the saved PoC script, or ``None`` if the
            finding did not meet the severity threshold.
        """
        severity = self._extract_severity(finding)
        if severity not in self.SEVERITY_THRESHOLD:
            logger.debug(
                "Skipping PoC for %s (severity=%s)",
                finding.get("vulnerability_type", "unknown"),
                severity,
            )
            return None

        poc_code = self._generate_with_llm(finding)
        if not poc_code:
            poc_code = self._generate_template(finding)

        filepath = self._save(finding, poc_code)
        logger.info("PoC saved to %s", filepath)
        return str(filepath)

    def generate_batch(
        self, findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate PoCs for all high/critical findings in a list.

        Returns a list of file-paths for the generated scripts.
        """
        paths: List[str] = []
        for finding in findings:
            result = self.generate(finding)
            if result:
                paths.append(result)
        return paths

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_severity(self, finding: Dict[str, Any]) -> str:
        """Normalise the severity value from various finding formats."""
        raw = finding.get("severity", "")
        if hasattr(raw, "value"):
            # Enum instances (e.g. ``Severity.HIGH``)
            raw = raw.value
        return str(raw).lower()

    def _extract_method(self, finding: Dict[str, Any]) -> str:
        """Best-effort extraction of the HTTP method."""
        endpoint = finding.get("endpoint", "")
        # Orchestrator stores endpoints as "GET /path"
        if " " in endpoint:
            return endpoint.split()[0].upper()
        return finding.get("method", "GET").upper()

    def _extract_path(self, finding: Dict[str, Any]) -> str:
        """Best-effort extraction of the URL path."""
        endpoint = finding.get("endpoint", "")
        if " " in endpoint:
            return endpoint.split(maxsplit=1)[1]
        return endpoint or "/"

    def _generate_with_llm(self, finding: Dict[str, Any]) -> Optional[str]:
        """Ask the LLM to write a PoC script."""
        if self.llm is None:
            return None

        try:
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_core.output_parsers import StrOutputParser

            prompt = ChatPromptTemplate.from_template(POC_GENERATION_PROMPT)
            chain = prompt | self.llm | StrOutputParser()

            result = chain.invoke({
                "vulnerability_type": finding.get("vulnerability_type", "Unknown"),
                "severity": self._extract_severity(finding),
                "endpoint": self._extract_path(finding),
                "method": self._extract_method(finding),
                "payload": str(finding.get("payload", "")),
                "evidence": finding.get("evidence", ""),
                "base_url": self.base_url,
            })

            # Strip markdown fences if the LLM included them anyway
            code = self._strip_markdown_fences(result)
            return code
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM PoC generation failed: %s", exc)
            return None

    @staticmethod
    def _strip_markdown_fences(text: str) -> str:
        """Remove ```python ... ``` wrappers that LLMs sometimes add."""
        text = text.strip()
        # Remove leading ```python or ```
        text = re.sub(r"^```(?:python)?\s*\n?", "", text)
        # Remove trailing ```
        text = re.sub(r"\n?```\s*$", "", text)
        return text.strip()

    def _generate_template(self, finding: Dict[str, Any]) -> str:
        """Produce a deterministic PoC when no LLM is available."""
        method = self._extract_method(finding)
        path = self._extract_path(finding)
        payload = finding.get("payload", "")
        vuln_type = finding.get("vulnerability_type", "Unknown")
        full_url = f"{self.base_url}{path}"

        # Escape values for safe embedding in a Python source string literal
        safe_url = self._escape_for_python_string(full_url)
        safe_vuln = self._escape_for_python_string(vuln_type)
        safe_method = self._escape_for_python_string(method)

        # Build a curl equivalent (also escaped for inclusion in a docstring)
        if method in ("POST", "PUT", "PATCH"):
            curl = f"curl -X {method} '{full_url}' -H 'Content-Type: application/json' -d '{payload}'"
        else:
            curl = f"curl '{full_url}'"
        safe_curl = self._escape_for_python_string(curl)

        return textwrap.dedent(f"""\
            #!/usr/bin/env python3
            \"\"\"Proof-of-Concept: {safe_vuln}

            Generated by Chaos Kitten on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

            Equivalent curl command:
                {safe_curl}
            \"\"\"

            import httpx

            TARGET_URL = "{safe_url}"
            PAYLOAD = {json.dumps(payload)}

            def main() -> None:
                print(f"[*] PoC for {safe_vuln}")
                print(f"[*] Target: {{TARGET_URL}}")

                with httpx.Client(timeout=30) as client:
                    response = client.request(
                        method="{safe_method}",
                        url=TARGET_URL,
                        json=PAYLOAD if PAYLOAD else None,
                    )

                print(f"[*] Status Code: {{response.status_code}}")
                print(f"[*] Response (first 500 chars):")
                print(response.text[:500])

                if response.status_code >= 500:
                    print("[!] Server error detected \u2014 vulnerability likely exploitable.")
                elif response.status_code == 200:
                    print("[+] Request succeeded \u2014 check response for evidence of exploitation.")
                else:
                    print(f"[-] Unexpected status {{response.status_code}}.")

            if __name__ == "__main__":
                main()
        """)

    def _save(self, finding: Dict[str, Any], code: str) -> Path:
        """Write the PoC to disk and return the file path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        vuln_type = finding.get("vulnerability_type", "unknown")
        # Sanitise for filename
        safe_name = re.sub(r"[^a-zA-Z0-9_]+", "_", vuln_type).strip("_").lower()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"poc_{safe_name}_{timestamp}.py"

        filepath = self.output_dir / filename
        filepath.write_text(code, encoding="utf-8")
        return filepath

    @staticmethod
    def _escape_for_python_string(value: str) -> str:
        """Escape a value so it can be safely embedded inside a Python string literal.

        Prevents code injection when user-controlled data (paths, vuln types)
        is interpolated into generated PoC scripts.
        """
        return (
            value
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
