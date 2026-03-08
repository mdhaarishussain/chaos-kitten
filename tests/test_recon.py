"""Tests for the Reconnaissance Engine."""

import sys
from unittest.mock import MagicMock

# Mock dependencies that might be missing in the environment or cause import errors
for mod in [
    "langchain_anthropic", 
    "langchain_core", 
    "langchain_core.output_parsers",
    "langchain_core.prompts",
    "langchain_ollama", 
    "langchain_openai", 
    "langgraph", 
    "langgraph.graph",
    "prance"
]:
    sys.modules[mod] = MagicMock()

import asyncio
import pytest
from unittest.mock import patch, mock_open, AsyncMock
import shutil
import socket
from chaos_kitten.brain.recon import ReconEngine


class TestReconEngine:
    def setup_method(self):
        self.config = {
            "target": {"base_url": "https://example.com"},
            "recon": {
                "enabled": True,
                "wordlist_path": "toys/data/subdomains.txt",
                "scan_depth": "fast",
                "ports": [80, 443]
            }
        }
        self.engine = ReconEngine(self.config)

    def test_init_defaults(self):
        engine = ReconEngine({"target": {"base_url": "https://example.com"}})
        assert engine.enabled is False
        assert engine.ports == [80, 443]

    @pytest.mark.asyncio
    async def test_run_disabled(self):
        self.engine.enabled = False
        results = await self.engine.run()
        assert results == {}

    @pytest.mark.asyncio
    async def test_enumerate_subdomains(self):
        mock_file_content = "www\napi"
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("socket.gethostbyname") as mock_dns:
                def dns_side_effect(domain):
                    if domain == "www.example.com":
                        return "1.2.3.4"
                    raise socket.gaierror
                mock_dns.side_effect = dns_side_effect

                subs = await self.engine.enumerate_subdomains("example.com")
                assert "www.example.com" in subs
                # api.example.com raises gaierror, so it shouldn't be in subs
                assert "api.example.com" not in subs

    @pytest.mark.asyncio
    async def test_scan_ports(self):
        """Test async scan_ports with mocked asyncio subprocess."""
        nmap_output = "Host: 127.0.0.1 ()\tPorts: 80/open/tcp//http///, 443/open/tcp//https///"

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            nmap_output.encode("utf-8"),
            b"",
        )
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            self.engine.scan_depth = "fast"
            ports = await self.engine.scan_ports("example.com")

        assert 80 in ports
        assert 443 in ports
        # Verify -F flag was included for fast scan
        call_args = mock_exec.call_args[0]
        assert "-F" in call_args

    @pytest.mark.asyncio
    async def test_scan_ports_timeout(self):
        """Test that scan_ports handles timeout gracefully."""
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            ports = await self.engine.scan_ports("example.com")

        assert ports == []
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_ports_deep(self):
        """Test deep scan passes -p- flag."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
            self.engine.scan_depth = "deep"
            await self.engine.scan_ports("example.com")

        call_args = mock_exec.call_args[0]
        assert "-p-" in call_args

    @pytest.mark.asyncio
    async def test_fingerprint_tech(self):
        """Test async fingerprint_tech with mocked httpx.AsyncClient."""
        mock_response = MagicMock()
        mock_response.headers = {"Server": "nginx", "X-Powered-By": "PHP/7.4"}
        mock_response.text = '<html><body>Content="WordPress"</body></html>'
        cookie = MagicMock()
        cookie.name = "PHPSESSID"
        mock_response.cookies = [cookie]

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            tech = await self.engine.fingerprint_tech("http://example.com")

        assert tech.get("server") == "nginx"
        assert tech.get("powered_by") == "PHP/7.4"
        assert "WordPress" in tech.get("cms", [])
        assert "PHP" in tech.get("frameworks", [])

    @pytest.mark.asyncio
    async def test_fingerprint_tech_connection_error(self):
        """Test that fingerprint_tech handles connection errors gracefully."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("Connection refused")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            tech = await self.engine.fingerprint_tech("http://example.com")

        assert tech == {}

    @pytest.mark.asyncio
    @patch("chaos_kitten.brain.recon.ReconEngine.enumerate_subdomains")
    @patch("chaos_kitten.brain.recon.ReconEngine.scan_ports")
    @patch("chaos_kitten.brain.recon.ReconEngine.fingerprint_tech")
    @patch("shutil.which")
    async def test_run_integration(self, mock_which, mock_fingerprint, mock_scan, mock_enum):
        mock_enum.return_value = ["www.example.com"]
        mock_which.return_value = True  # nmap exists
        mock_scan.return_value = [80]
        mock_fingerprint.return_value = {"server": "test"}

        results = await self.engine.run()

        assert results["domain"] == "example.com"
        assert "www.example.com" in results["subdomains"]
        assert results["services"]["www.example.com"] == [80]
        assert "http://www.example.com:80" in results["technologies"]


if __name__ == "__main__":
    pytest.main([__file__])
