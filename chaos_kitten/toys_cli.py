"""Community Toy Marketplace CLI commands."""

import json
import logging
import os
import re
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table
from typer import Exit

from chaos_kitten.validators.profile_validator import AttackProfileValidator

logger = logging.getLogger(__name__)
console = Console()

toys_app = typer.Typer(
    name="toys",
    help="Manage community attack profiles (toys)",
    no_args_is_help=True,
)

# Default registry URL (can be overridden by env var)
DEFAULT_REGISTRY_URL = "https://raw.githubusercontent.com/mdhaarishussain/chaos-kitten/main/toys/registry.json"
REGISTRY_URL = os.environ.get("CHAOS_KITTEN_REGISTRY_URL", DEFAULT_REGISTRY_URL)


def _validate_url(url: str, context: str = "URL") -> None:
    """Ensure URL uses a safe scheme (http/https)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{context} uses disallowed scheme '{parsed.scheme}'. Only http/https are permitted.")


def _fetch_registry() -> Dict[str, Any]:
    """Fetch the toy registry from the remote URL.

    On error, prints a helpful message and exits with a non-zero code
    so CI/CD can detect the failure.
    """
    try:
        _validate_url(REGISTRY_URL, "CHAOS_KITTEN_REGISTRY_URL")
        req = urllib.request.Request(REGISTRY_URL, headers={"User-Agent": "Chaos-Kitten-CLI"})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                console.print(f"[red]Failed to fetch registry: HTTP {response.status}[/red]")
                raise Exit(code=1)

            data = response.read().decode("utf-8")
            try:
                return json.loads(data)
            except json.JSONDecodeError as e:
                console.print(f"[red]Invalid registry JSON: {e}[/red]")
                raise Exit(code=1)
    except URLError as e:
        console.print(f"[red]Network error fetching registry from {REGISTRY_URL}: {e}[/red]")
        raise Exit(code=1)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise Exit(code=1)

def _get_local_toys_dir() -> Path:
    """Get the local toys directory."""
    # Default to ./toys in current directory, or fallback to package toys dir
    local_dir = Path("toys")
    if not local_dir.exists():
        local_dir.mkdir(parents=True, exist_ok=True)
    return local_dir

@toys_app.command("search")
def search_toys(
    keyword: str = typer.Argument(None, help="Keyword to search for"),
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
):
    """Search the community registry for attack profiles."""
    console.print("[cyan]Fetching registry...[/cyan]")
    registry = _fetch_registry()
    
    if not registry or "profiles" not in registry:
        console.print("[red]Registry is empty or invalid.[/red]")
        raise Exit(code=1)
        
    profiles = registry["profiles"]
    
    # Filter profiles
    results = []
    for slug, profile in profiles.items():
        if keyword:
            kw = keyword.lower()
            if kw not in slug.lower() and kw not in profile.get("description", "").lower() and kw not in profile.get("name", "").lower():
                continue
        if category and category.lower() != profile.get("category", "").lower():
            continue
        results.append((slug, profile))
        
    if not results:
        console.print("[yellow]No profiles found matching your criteria.[/yellow]")
        return
        
    table = Table(title="Community Attack Profiles")
    table.add_column("Slug", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Category", style="magenta")
    table.add_column("Author", style="blue")
    table.add_column("Description")
    
    for slug, profile in results:
        table.add_row(
            slug,
            profile.get("name", "Unknown"),
            profile.get("category", "Unknown"),
            profile.get("author", "Unknown"),
            profile.get("description", "")[:50] + "..." if len(profile.get("description", "")) > 50 else profile.get("description", "")
        )
        
    console.print(table)

@toys_app.command("install")
def install_toy(
    slug: str = typer.Argument(..., help="The slug of the profile to install"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing profile"),
):
    """Download and install an attack profile from the registry."""
    console.print(f"[cyan]Fetching registry to find '{slug}'...[/cyan]")
    registry = _fetch_registry()
    
    if not registry or "profiles" not in registry:
        console.print("[red]Registry is empty or invalid.[/red]")
        raise Exit(code=1)
        
    if slug not in registry["profiles"]:
        console.print(f"[red]Profile '{slug}' not found in registry.[/red]")
        raise Exit(code=1)
        
    profile_info = registry["profiles"][slug]
    download_url = profile_info.get("url")
    
    if not download_url:
        console.print(f"[red]Profile '{slug}' has no download URL.[/red]")
        raise Exit(code=1)
        
    toys_dir = _get_local_toys_dir()
    # Determine extension from URL or default to yaml
    ext = ".json" if download_url.endswith(".json") else ".yaml"
    dest_path = toys_dir / f"{slug}{ext}"
    
    if dest_path.exists() and not force:
        console.print(f"[yellow]Profile '{slug}' is already installed at {dest_path}. Use --force to overwrite.[/yellow]")
        return
        
    console.print(f"[cyan]Downloading '{slug}' from {download_url}...[/cyan]")
    try:
        _validate_url(download_url, f"download_url for '{slug}'")
        req = urllib.request.Request(download_url, headers={"User-Agent": "Chaos-Kitten-CLI"})
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                console.print(f"[red]Failed to download profile: HTTP {response.status}[/red]")
                raise Exit(code=1)

            content = response.read().decode("utf-8")

            # Validate content before saving (schema-level)
            console.print("[cyan]Validating profile...[/cyan]")

            # Optional content audit for suspicious patterns
            suspicious_patterns = [r'\.system\(', r'__import__']
            for pattern in suspicious_patterns:
                if re.search(pattern, content):
                    console.print(f"[yellow]⚠️ Profile contains suspicious pattern: {pattern}[/yellow]")

            # Save temporarily to validate schema
            temp_path = toys_dir / f".temp_{slug}{ext}"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(content)

            try:
                validator = AttackProfileValidator()
                report = validator.validate_profile(str(temp_path))
            except Exception as e:
                console.print(f"[red]Validation error: {e}[/red]")
                if temp_path.exists():
                    temp_path.unlink()
                raise Exit(code=1) from e

            if not report.is_valid:
                console.print("[red]Schema validation failed:[/red]")
                for err in report.errors:
                    console.print(f"  - {err}")
                temp_path.unlink()
                raise Exit(code=1)

            # Atomically move temp file to final destination
            try:
                temp_path.replace(dest_path)
            except Exception as e:
                console.print(f"[red]Failed to save profile: {e}[/red]")
                if temp_path.exists():
                    temp_path.unlink()
                raise Exit(code=1)

            console.print(f"[green]Successfully installed '{slug}' to {dest_path}[/green]")
    except URLError as e:
        console.print(f"[red]Network error downloading profile from {download_url}: {e}[/red]")
        raise Exit(code=1)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise Exit(code=1)

@toys_app.command("list")
def list_toys():
    """List installed attack profiles."""
    toys_dir = _get_local_toys_dir()

    profiles = []
    for ext in ["*.yaml", "*.yml", "*.json"]:
        profiles.extend(list(toys_dir.glob(ext)))
        
    if not profiles:
        console.print("[yellow]No profiles installed.[/yellow]")
        return
        
    table = Table(title="Installed Attack Profiles")
    table.add_column("File", style="cyan")
    table.add_column("Path", style="green")
    
    for p in profiles:
        table.add_row(p.name, str(p))
        
    console.print(table)

@toys_app.command("publish")
def publish_toy(
    file_path: str = typer.Argument(..., help="Path to the profile file to publish"),
):
    """Publish a local toy to the registry (Instructions)."""
    path = Path(file_path)
    if not path.exists():
        console.print(f"[red]File not found: {file_path}[/red]")
        raise Exit(code=1)
        
    console.print("[bold magenta]Publishing to Chaos Kitten Registry[/bold magenta]")
    console.print("\nThe registry is hosted as a GitHub-backed JSON index.")
    console.print("To publish your profile, please follow these steps:")
    console.print("1. Fork the repository: https://github.com/mdhaarishussain/chaos-kitten")
    console.print("2. Add your profile to the `toys/` directory.")
    console.print("3. Update `toys/registry.json` with your profile's metadata.")
    console.print("4. Submit a Pull Request.")
    console.print("\n[cyan]Thank you for contributing to the community![/cyan]")
