"""Tests for the Autonomous Exploit PoC Generator."""

import json
import os
import textwrap

import pytest

from chaos_kitten.brain.poc_generator import PoCGenerator


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def poc_dir(tmp_path):
    """Temporary directory for generated PoC scripts."""
    return tmp_path / "pocs"


@pytest.fixture
def generator(poc_dir):
    """PoCGenerator with LLM disabled (template-only)."""
    gen = PoCGenerator(
        base_url="http://localhost:8080",
        output_dir=str(poc_dir),
    )
    gen.llm = None  # Force template fallback
    return gen


# ── Helpers ─────────────────────────────────────────────────────────────


def _make_finding(
    vuln_type="SQL Injection",
    severity="critical",
    endpoint="POST /api/users",
    payload="' OR 1=1 --",
    evidence="SQL syntax error in response",
):
    return {
        "vulnerability_type": vuln_type,
        "severity": severity,
        "endpoint": endpoint,
        "payload": payload,
        "evidence": evidence,
    }


# ── Tests: severity filtering ──────────────────────────────────────────


class TestSeverityFiltering:
    def test_generates_for_critical(self, generator):
        path = generator.generate(_make_finding(severity="critical"))
        assert path is not None
        assert os.path.isfile(path)

    def test_generates_for_high(self, generator):
        path = generator.generate(_make_finding(severity="high"))
        assert path is not None

    def test_skips_medium(self, generator):
        path = generator.generate(_make_finding(severity="medium"))
        assert path is None

    def test_skips_low(self, generator):
        path = generator.generate(_make_finding(severity="low"))
        assert path is None

    def test_skips_info(self, generator):
        path = generator.generate(_make_finding(severity="info"))
        assert path is None

    def test_handles_enum_severity(self, generator):
        """Severity supplied as an Enum-like object with a .value attribute."""
        from chaos_kitten.paws.analyzer import Severity

        finding = _make_finding()
        finding["severity"] = Severity.CRITICAL
        path = generator.generate(finding)
        assert path is not None


# ── Tests: template-based PoC content ──────────────────────────────────


class TestTemplatePoC:
    def test_contains_target_url(self, generator):
        path = generator.generate(_make_finding())
        content = open(path).read()
        assert "http://localhost:8080/api/users" in content

    def test_contains_payload(self, generator):
        path = generator.generate(_make_finding(payload="<script>alert(1)</script>"))
        content = open(path).read()
        assert "<script>alert(1)</script>" in content

    def test_contains_vulnerability_type(self, generator):
        path = generator.generate(_make_finding(vuln_type="XSS Reflected"))
        content = open(path).read()
        assert "XSS Reflected" in content

    def test_contains_curl_command(self, generator):
        path = generator.generate(_make_finding())
        content = open(path).read()
        assert "curl" in content

    def test_contains_httpx_import(self, generator):
        path = generator.generate(_make_finding())
        content = open(path).read()
        assert "import httpx" in content

    def test_contains_main_guard(self, generator):
        path = generator.generate(_make_finding())
        content = open(path).read()
        assert 'if __name__ == "__main__"' in content

    def test_method_extracted_from_endpoint(self, generator):
        path = generator.generate(_make_finding(endpoint="PUT /api/items/1"))
        content = open(path).read()
        assert "PUT" in content

    def test_get_method_curl(self, generator):
        path = generator.generate(_make_finding(endpoint="GET /api/health", severity="high"))
        content = open(path).read()
        assert "curl" in content
        assert "-X" not in content or "GET" in content


# ── Tests: batch generation ────────────────────────────────────────────


class TestBatchGeneration:
    def test_batch_generates_only_qualifying(self, generator):
        findings = [
            _make_finding(severity="critical", vuln_type="SQLi"),
            _make_finding(severity="low", vuln_type="Info Disclosure"),
            _make_finding(severity="high", vuln_type="XSS"),
        ]
        paths = generator.generate_batch(findings)
        assert len(paths) == 2  # critical + high only

    def test_batch_empty_list(self, generator):
        paths = generator.generate_batch([])
        assert paths == []


# ── Tests: file naming ─────────────────────────────────────────────────


class TestFileNaming:
    def test_filename_sanitisation(self, generator):
        path = generator.generate(
            _make_finding(vuln_type="SQL Injection (MySQL)")
        )
        assert "poc_sql_injection_mysql_" in os.path.basename(path)

    def test_output_dir_created(self, generator, poc_dir):
        assert not poc_dir.exists()
        generator.generate(_make_finding())
        assert poc_dir.exists()


# ── Tests: markdown fence stripping ────────────────────────────────────


class TestMarkdownStripping:
    def test_strips_python_fence(self):
        raw = "```python\nprint('hello')\n```"
        assert PoCGenerator._strip_markdown_fences(raw) == "print('hello')"

    def test_strips_plain_fence(self):
        raw = "```\nprint('hello')\n```"
        assert PoCGenerator._strip_markdown_fences(raw) == "print('hello')"

    def test_no_fence(self):
        raw = "print('hello')"
        assert PoCGenerator._strip_markdown_fences(raw) == "print('hello')"


# ── Tests: LLM integration (mocked) ───────────────────────────────────


class TestLLMGeneration:
    def test_llm_poc_saved(self, poc_dir):
        """With a mocked LLM chain, the generated code is saved correctly."""
        from unittest.mock import MagicMock, patch

        gen = PoCGenerator(
            base_url="http://localhost:8080",
            output_dir=str(poc_dir),
        )
        gen.llm = MagicMock()

        mock_code = textwrap.dedent("""\
            import httpx
            response = httpx.get("http://localhost:8080/api/users")
            print(response.text)
        """)

        with patch("langchain_core.prompts.ChatPromptTemplate.from_template") as mock_prompt:
            mock_chain = MagicMock()
            mock_chain.invoke.return_value = mock_code
            mock_p = MagicMock()
            mock_p.__or__ = MagicMock(return_value=MagicMock())
            mock_p.__or__.return_value.__or__ = MagicMock(return_value=mock_chain)
            mock_prompt.return_value = mock_p

            path = gen.generate(_make_finding())

        assert path is not None
        content = open(path).read()
        assert "import httpx" in content

    def test_llm_failure_falls_back_to_template(self, poc_dir):
        """If the LLM raises, we still get a template PoC."""
        from unittest.mock import MagicMock, patch

        gen = PoCGenerator(
            base_url="http://localhost:8080",
            output_dir=str(poc_dir),
        )
        gen.llm = MagicMock()

        with patch("langchain_core.prompts.ChatPromptTemplate.from_template") as mock_prompt:
            mock_prompt.side_effect = Exception("LLM unavailable")
            path = gen.generate(_make_finding())

        assert path is not None
        content = open(path).read()
        assert "import httpx" in content  # Template fallback
        assert "SQL Injection" in content
