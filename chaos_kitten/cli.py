"""Chaos Kitten CLI - Command Line Interface."""
import typer
import logging
from rich.console import Console
from rich.panel import Panel
from chaos_kitten.brain.cors import analyze_cors

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="chaos-kitten",
    help="🐱 Chaos Kitten - The adorable AI agent that knocks things off your API tables",
    add_completion=False,
)


console = Console()

ASCII_CAT = r"""
           /\___/\  
   _      ( o . o )   
  / \      >  ^  <     ~
  | |o====/==  || \   /
  | |    /     ||  \ /
  | |   (      ||   )
  |_|    \_____oo__/
"""


@app.command()
def version():
    """Show version information."""
    from chaos_kitten import __version__

    console.print(f"[bold magenta]Chaos Kitten[/bold magenta] v{__version__}")


@app.command()
def init():
    """Initialize a new chaos-kitten.yaml configuration file."""
    config_template = '''"""# Chaos Kitten Configuration
target:
  base_url: "http://localhost:3000"
  openapi_spec: "./openapi.json"
  auth:
    type: "bearer"  # bearer, basic, none
    token: "${API_TOKEN}"

agent:
  llm_provider: "anthropic"  # anthropic, openai, ollama
  model: "claude-3-5-sonnet-20241022"
  temperature: 0.7
  max_iterations: 10

executor:
  concurrent_requests: 5
  timeout: 30
  rate_limit: 10  # requests per second

safety:
  allowed_domains:
    - "localhost"
    - "*.test.com"
  destructive_mode: false

toys:
  enabled:
    - "sql_injection"
    - "xss"
    - "idor"
  disabled:
    - "dos"

reporting:
  format: "html"
  output_path: "./reports"
  include_poc: true
  include_remediation: true
"""'''

    with open("chaos-kitten.yaml", "w") as f:
        f.write(config_template.strip('"""'))

    console.print("[green]✓[/green] Created chaos-kitten.yaml")
    console.print("Edit the file with your target API details.")


@app.command()
def scan(
    config: str = typer.Option(
        "chaos-kitten.yaml",
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    target: str = typer.Option(
        None,
        "--target",
        "-t",
        help="Target URL (overrides config)",
    ),
    spec: str = typer.Option(
        None,
        "--spec",
        "-s",
        help="Path to OpenAPI spec (overrides config)",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Directory to save the security report",
    ),
    format: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Format of the report (html, markdown, json, sarif, junit)",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        help="Exit with code 1 if severity >= level (none, low, medium, high, critical)",
    ),
    silent: bool = typer.Option(
        False,
        "--silent",
        help="Suppress console output except errors (useful for CI)",
    ),
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider (openai, anthropic, ollama)",
    ),
    demo: bool = typer.Option(
        False,
        "--demo",
        help="Run scan against the demo vulnerable API",
    ),
    chaos: bool = typer.Option(
        False,
        "--chaos",
        help="Enable chaos mode for negative testing with random invalid inputs",
    ),
    chaos_level: int = typer.Option(
        3,
        "--chaos-level",
        help="Chaos intensity from 1 (gentle) to 5 (maximum carnage)",
        min=1,
        max=5,
    ),
):
    """Scan an API for security vulnerabilities."""
    if not silent:
        console.print(Panel(ASCII_CAT, title="🐱 Chaos Kitten", border_style="magenta"))
        console.print()

    if demo:
        if not silent:
            console.print("[bold cyan]🎮 Running in DEMO mode![/bold cyan]")
        target = target or "http://localhost:5000"
        spec = spec or "examples/sample_openapi.json"
        
        if not silent:
            console.print(f"🎯 Target: {target}")
            console.print(f"📋 Spec: {spec}")
            console.print()

    # Check for API keys if using LLM providers
    import os
    if not demo and not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        console.print("[yellow]⚠️  No LLM API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY).[/yellow]")
        console.print("[yellow]    Some features like attack planning might not work.[/yellow]")
    elif not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
         console.print("[yellow]⚠️  Proceeding without API keys since we are in demo mode...[/yellow]")
    
    # Build configuration
    app_config = {}
    
    try:
        from chaos_kitten.brain.orchestrator import Orchestrator
        from chaos_kitten.litterbox.reporter import Reporter
        import asyncio
        
    if output:
        if "reporting" not in app_config:
            app_config["reporting"] = {}
        app_config["reporting"]["output_path"] = output

    if format:
        if "reporting" not in app_config:
            app_config["reporting"] = {}
        app_config["reporting"]["format"] = format

    if provider:
        if "agent" not in app_config:
            app_config["agent"] = {}
        app_config["agent"]["llm_provider"] = provider

    if goal:
        if "agent" not in app_config: app_config["agent"] = {}
        app_config["agent"]["goal"] = goal

    # Run the orchestrator
    from chaos_kitten.brain.orchestrator import Orchestrator
    orchestrator = Orchestrator(app_config, resume=resume)
    try:
        if not silent:
            console.print("[bold green]🚀 Launching Chaos Kitten...[/bold green]")
        
        # Override with CLI args
        if target:
            cfg.setdefault("target", {})["base_url"] = target
        if spec:
            cfg.setdefault("target", {})["openapi_spec"] = spec
        if output:
            cfg.setdefault("reporting", {})["output_path"] = output
        if format:
            cfg.setdefault("reporting", {})["format"] = format
        if provider:
            cfg.setdefault("agent", {})["llm_provider"] = provider
            
        orchestrator = Orchestrator(cfg, chaos=chaos, chaos_level=chaos_level)
        results = asyncio.run(orchestrator.run())
        
        # Check for orchestrator runtime errors
        if isinstance(results, dict) and results.get("status") == "failed":
            console.print(f"[bold red]❌ Scan failed:[/bold red] {results.get('error')}")
            raise typer.Exit(code=1)

        # Display summary
        summary = results.get("summary", {})
        if summary:
            console.print("\n[bold green]📊 Scan Summary:[/bold green]")
            console.print(f"   Tested Endpoints: {summary.get('tested_endpoints', 0)} / {summary.get('total_endpoints', 0)}")
            console.print(f"   Vulnerabilities Found: [bold red]{summary.get('vulnerabilities_found', 0)}[/bold red]")

        # Handle --fail-on-critical
        if fail_on_critical:
            vulnerabilities = results.get("vulnerabilities", [])
            critical_vulns = [
                v for v in vulnerabilities
                if str(v.get("severity", "")).lower() == "critical"
            ]
            if critical_vulns:
                console.print(f"[bold red]❌ Found {len(critical_vulns)} critical vulnerabilities. Failing pipeline.[/bold red]")
                raise typer.Exit(code=1)
            elif not silent:
                console.print("[bold green]✅ No vulnerabilities found exceeding the failure threshold.[/bold green]")

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]❌ Scan failed:[/bold red] {e}")
        raise typer.Exit(code=1) from e


@app.command()
def diff(
    old: str = typer.Option(
        ...,
        "--old",
        help="Path to old OpenAPI spec (JSON or YAML)",
    ),
    new: str = typer.Option(
        ...,
        "--new",
        help="Path to new OpenAPI spec (JSON or YAML)",
    ),
    target: str = typer.Option(
        None,
        "--base-url",
        "-t",
        help="Base URL for the API (e.g., https://api.example.com)",
    ),
    output: str = typer.Option(
        "./reports",
        "--output",
        "-o",
        help="Directory to save the security report",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Format of the report (html, markdown, json, sarif)",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Run full scan on all endpoints (overrides delta-only mode)",
    ),
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Exit with code 1 if critical vulnerabilities found",
    ),
    provider: str = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider (openai, anthropic, ollama)",
    ),
):
    """API Spec Diff Scanning - Test only what changed between API versions."""
    console.print(Panel(ASCII_CAT, title="🐱 Chaos Kitten - Diff Mode", border_style="magenta"))
    console.print()

    # Load specs
    import json
    import yaml
    from pathlib import Path
    from chaos_kitten.brain.spec_differ import SpecDiffer

    def load_spec(path: str) -> dict:
        """Load OpenAPI spec from JSON or YAML."""
        spec_path = Path(path)
        if not spec_path.exists():
            console.print(f"[bold red]❌ File not found:[/bold red] {path}")
            raise typer.Exit(code=1)

        content = spec_path.read_text(encoding="utf-8")
        try:
            if spec_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except Exception as e:
            console.print(f"[bold red]❌ Failed to parse spec:[/bold red] {e}")
            raise typer.Exit(code=1)

    old_spec = load_spec(old)
    new_spec = load_spec(new)

    # Compute diff
    console.print("[bold cyan]📊 Computing API diff...[/bold cyan]")
    differ = SpecDiffer(old_spec, new_spec)
    diff_result = differ.compute_diff()

    summary = diff_result["summary"]
    critical_findings = diff_result["critical_findings"]

    # Display diff summary
    console.print()
    console.print(Panel(
        f"""[bold]Diff Summary:[/bold]
        
    except Exception as e:
        console.print(f"[bold red]💥 Error:[/bold red] {str(e)}")
        # If it's not a FileNotFoundError, we might want to see the traceback
        if not isinstance(e, FileNotFoundError):
            import traceback
            logger.debug(traceback.format_exc())
        raise typer.Exit(code=1)
    
    console.print()
    console.print("🐾 [italic]Chaos Kitten is done![/italic]")
    console.print()

    from chaos_kitten.brain.orchestrator import Orchestrator

    orchestrator = Orchestrator(app_config)
    try:
        import asyncio

        results = asyncio.run(orchestrator.run())

        # Check for orchestrator runtime errors
        if isinstance(results, dict) and results.get("status") == "failed":
            console.print(
                f"[bold red]❌ Scan failed:[/bold red] {results.get('error')}"
            )
            raise typer.Exit(code=1)

        # Handle --fail-on-critical (including pre-scan findings)
        if fail_on_critical:
            vulnerabilities = results.get("vulnerabilities", [])
            critical_vulns = [
                v
                for v in vulnerabilities
                if str(v.get("severity", "")).lower() == "critical"
            ]
            # Note: orchestrator already injected critical_findings into vulnerabilities, so no need to add again
            total_critical = len(critical_vulns)
            
            if total_critical > 0:
                console.print(f"[bold red]❌ Found {total_critical} critical issue(s). Failing pipeline.[/bold red]")
                raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]❌ Diff scan failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def interactive():
    """Start interactive mode."""
    from chaos_kitten.console.repl import ChaosREPL
    import asyncio
    
    repl = ChaosREPL(console)
    asyncio.run(repl.start())

@app.command()
def meow():
    """🐱 Meow!"""
    console.print(Panel(ASCII_CAT, title="🐱 Meow!", border_style="magenta"))
    console.print(
        "[italic]I'm going to knock some vulnerabilities off your API table![/italic]"
    )


@app.command()
def validate_profiles(
    path: str = typer.Option(
        "toys",
        "--path",
        "-p",
        help="Path to directory containing attack profiles",
    )
):
    """Validate attack profiles for syntax and best practices."""
    from chaos_kitten.validators import AttackProfileValidator
    import os
    
    console.print(Panel(f"🔍 Validating profiles in [bold]{path}[/bold]...", title="Profile Validator", border_style="blue"))
    
    validator = AttackProfileValidator()
    
    if not os.path.exists(path):
        console.print(f"[bold red]❌ Directory not found:[/bold red] {path}")
        raise typer.Exit(code=1)
        
    results = validator.validate_all_profiles(path)
    
    if not results:
        console.print("[yellow]⚠️  No profiles found.[/yellow]")
        return

    has_errors = False
    
    for filename, report in results.items():
        if report.is_valid:
            status = "[green]PASS[/green]"
        else:
            status = "[bold red]FAIL[/bold red]"
            has_errors = True
            
        console.print(f"{status} [bold]{filename}[/bold]")
        
        for error in report.errors:
            console.print(f"  ❌ {error}", style="red")
            
        for warning in report.warnings:
            console.print(f"  ⚠️  {warning}", style="yellow")
            
        for suggestion in report.suggestions:
            console.print(f"  💡 {suggestion}", style="blue")
            
        console.print()
        
    if has_errors:
        console.print("[bold red]❌ Validation failed. Please fix key errors.[/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]✅ All profiles valid![/bold green]")

if __name__ == "__main__":
    app()
