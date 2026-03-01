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

import unittest
from unittest.mock import patch, mock_open
import shutil
import socket
from chaos_kitten.brain.recon import ReconEngine

class TestReconEngine(unittest.TestCase):
    def setUp(self):
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
        self.assertFalse(engine.enabled)
        self.assertEqual(engine.ports, [80, 443])

    def test_run_disabled(self):
        self.engine.enabled = False
        results = self.engine.run()
        self.assertEqual(results, {})

    def test_enumerate_subdomains(self):
        mock_file_content = "www\napi"
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            with patch("socket.gethostbyname") as mock_dns:
                def dns_side_effect(domain):
                    if domain == "www.example.com":
                        return "1.2.3.4"
                    raise socket.gaierror
                mock_dns.side_effect = dns_side_effect

                # Need to update wordlist path config or ensure open calls correct path
                # Since we mock open, the path doesn't matter much as long as it opens something.
                subs = self.engine.enumerate_subdomains("example.com")
                self.assertIn("www.example.com", subs)
                # api.example.com raises gaierror, so it shouldn't be in subs
                self.assertNotIn("api.example.com", subs)

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_scan_ports(self, mock_run, mock_which):
        # Mock nmap existence
        mock_which.return_value = "/usr/bin/nmap"
        
        # Mock nmap output
        mock_result = MagicMock()
        mock_result.stdout = "Host: 127.0.0.1 ()	Ports: 80/open/tcp//http///, 443/open/tcp//https///"
        mock_run.return_value = mock_result
        
        # We need to make sure self.engine.scan_depth is what we expect
        self.engine.scan_depth = "fast"
        ports = self.engine.scan_ports("example.com")
        
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        
        # Verify arguments based on scan_depth="fast"
        args = mock_run.call_args[0][0]
        self.assertIn("-F", args)

    @patch("httpx.Client")
    def test_fingerprint_tech(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.headers = {"Server": "nginx", "X-Powered-By": "PHP/7.4"}
        mock_response.text = '<html><body>Content="WordPress"</body></html>'
        cookie = MagicMock()
        cookie.name = "PHPSESSID"
        # Ensure name attribute is set on mock object
        mock_response.cookies = [cookie]
        
        mock_client.get.return_value = mock_response
        
        tech = self.engine.fingerprint_tech("http://example.com")
        
        self.assertEqual(tech.get("server"), "nginx")
        self.assertEqual(tech.get("powered_by"), "PHP/7.4")
        self.assertIn("WordPress", tech.get("cms", []))
        self.assertIn("PHP", tech.get("frameworks", []))

    @patch("chaos_kitten.brain.recon.ReconEngine.enumerate_subdomains")
    @patch("chaos_kitten.brain.recon.ReconEngine.scan_ports")
    @patch("chaos_kitten.brain.recon.ReconEngine.fingerprint_tech")
    @patch("shutil.which")
    def test_run_integration(self, mock_which, mock_fingerprint, mock_scan, mock_enum):
        mock_enum.return_value = ["www.example.com"]
        mock_which.return_value = True # nmap exists
        mock_scan.return_value = [80]
        mock_fingerprint.return_value = {"server": "test"}
        
        results = self.engine.run()
        
        self.assertEqual(results["domain"], "example.com")
        self.assertIn("www.example.com", results["subdomains"])
        self.assertEqual(results["services"]["www.example.com"], [80])
        # It should try http and https for port 80? Or just http since 80 is usually http
        # My code uses port logic: 443 -> https, others -> http
        self.assertIn("http://www.example.com:80", results["technologies"])

if __name__ == "__main__":
    unittest.main()
