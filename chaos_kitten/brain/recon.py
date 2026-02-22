"""Reconnaissance Engine for Chaos Kitten.

Performs subdomain enumeration, port scanning, and technology fingerprinting.
"""

import socket
import logging
import subprocess
import shutil
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)

class ReconEngine:
    """
    Reconnaissance engine to discover attack surface.
    
    Capabilities:
    - Subdomain enumeration (DNS brute-force)
    - Port scanning (via nmap)
    - Technology fingerprinting (via response headers/body)
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        Initialize the ReconEngine.

        Args:
            config: Configuration dictionary containing 'recon' and 'target' settings.
        """
        self.config = config.get("recon", {})
        self.target_config = config.get("target", {})
        self.enabled = self.config.get("enabled", False)
        self.wordlist_path = self.config.get("wordlist_path", "toys/data/subdomains.txt")
        self.scan_depth = self.config.get("scan_depth", "fast") # fast, medium, deep
        self.ports = self.config.get("ports", [80, 443])
        self.timeout = self.config.get("timeout", 5.0)

    def run(self) -> Dict[str, Any]:
        """
        Run the full reconnaissance process.

        Returns:
            Dict containing discovered assets and fingerprints.
        """
        if not self.enabled:
            logger.info("Reconnaissance phase disabled.")
            return {}

        base_url = self.target_config.get("base_url")
        if not base_url:
            logger.warning("No target base_url provided for recon.")
            return {}

        parsed_url = urlparse(base_url)
        domain = parsed_url.hostname
        if not domain:
            logger.warning(f"Could not parse domain from base_url: {base_url}")
            return {}

        logger.info(f"Starting reconnaissance for domain: {domain}")

        results = {
            "domain": domain,
            "subdomains": [],
            "services": {}, # host -> ports
            "technologies": {} # url -> fingerprints
        }

        # 1. Subdomain Enumeration
        subdomains = self.enumerate_subdomains(domain)
        results["subdomains"] = subdomains
        logger.info(f"Found {len(subdomains)} subdomains.")

        # Add the main domain to the list for scanning
        targets = [domain] + subdomains 

        # 2. Port Scanning
        if shutil.which("nmap"):
             for target in targets:
                ports = self.scan_ports(target)
                if ports:
                    results["services"][target] = ports
        else:
             logger.info("Nmap not found. Skipping port scanning.")

        # 3. Technology Fingerprinting
        for target in targets:
             # Construct URLs (try http and https)
             urls_to_check = []
             if target in results["services"]:
                 for port in results["services"][target]:
                     protocol = "https" if port == 443 else "http"
                     urls_to_check.append(f"{protocol}://{target}:{port}")
             else:
                 urls_to_check.append(f"http://{target}")
                 urls_to_check.append(f"https://{target}")

             for url in urls_to_check:
                 tech = self.fingerprint_tech(url)
                 if tech:
                     results["technologies"][url] = tech

        return results

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using DNS brute-force.
        """
        found_subdomains = []
        try:
             with open(self.wordlist_path, "r", encoding="utf-8") as f:
                 subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
             logger.warning(f"Subdomain wordlist not found at {self.wordlist_path}. Skipping enumeration.")
             return []

        logger.info(f"Brute-forcing {len(subdomains)} subdomains...")
        
        for sub in subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                logger.debug(f"Found subdomain: {full_domain}")
            except socket.gaierror:
                pass
        
        return found_subdomains

    def scan_ports(self, host: str) -> List[int]:
        """
        Scan ports using nmap.
        """
        open_ports = []
        cmd = ["nmap", "-T4", "--open", host]
        
        if self.scan_depth == "fast":
            cmd.extend(["-F"])
        elif self.scan_depth == "deep":
            cmd.extend(["-p-"])
        
        try:
            cmd.extend(["-oG", "-"])
            
            # Using subprocess with text=True for string output
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout
            
            # Parse nmap grepable output
            # Host: 127.0.0.1 ()	Ports: 80/open/tcp//http///, 443/open/tcp//https///
            for line in output.splitlines():
                if "Ports:" in line and "Status: Up" not in line and "Host:" in line: 
                     # Extract ports part
                     try:
                         parts = line.split("Ports: ")[1]
                         port_entries = parts.split(", ")
                         for entry in port_entries:
                             port_slash = entry.split("/")
                             if len(port_slash) > 0 and port_slash[0].strip().isdigit():
                                 open_ports.append(int(port_slash[0].strip()))
                     except IndexError:
                         continue

        except subprocess.TimeoutExpired:
             logger.error(f"Nmap scan timed out for {host}")
        except subprocess.SubprocessError as e:
            logger.error(f"Nmap scan failed for {host}: {e}")
        except Exception as e:
            logger.error(f"Error parsing nmap output: {e}")

        return open_ports

    def fingerprint_tech(self, url: str) -> Dict[str, Any]:
        """
        Identify technologies from response headers and body using httpx.
        """
        fingerprints = {}
        try:
            logger.warning("TLS verification disabled for technology fingerprinting - man-in-the-middle risk in untrusted networks")
            with httpx.Client(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                response = client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = response.text.lower()

                # 1. Server Header
                if "server" in headers:
                    fingerprints["server"] = headers["server"]

                # 2. X-Powered-By
                if "x-powered-by" in headers:
                    fingerprints["powered_by"] = headers["x-powered-by"]

                # 3. Cookies
                for cookie in response.cookies:
                     if "JSESSIONID" in cookie.name:
                         fingerprints.setdefault("frameworks", []).append("Java/Servlet")
                     if "PHPSESSID" in cookie.name:
                         fingerprints.setdefault("frameworks", []).append("PHP")
                     if "csrftoken" in cookie.name: 
                         fingerprints.setdefault("frameworks", []).append("Django")

                # 4. Body heurstics
                if 'content="wordpress"' in body:
                     fingerprints.setdefault("cms", []).append("WordPress")
                if 'react' in body or 'react-dom' in body:
                     fingerprints.setdefault("frontend", []).append("React")
                if 'vue.js' in body:
                     fingerprints.setdefault("frontend", []).append("Vue.js")

        except httpx.RequestError as e:
            logger.debug(f"Could not connect to {url} for fingerprinting: {e}")
            pass
            
        return fingerprints
