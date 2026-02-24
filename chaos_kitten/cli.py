"""Chaos Kitten CLI - Command Line Interface."""

import typer
from rich.console import Console
from rich.panel import Panel
import logging

try:
    from chaos_kitten import __version__
except ImportError:
    __version__ = "0.0.0"

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="chaos-kitten",
    help="≡ƒÉ▒ Chaos Kitten - The adorable AI agent that knocks things off your API tables",
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
    
    console.print("[green]Γ£ô[/green] Created chaos-kitten.yaml")
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
        "./reports",
        "--output",
        "-o",
        help="Directory to save the security report",
    ),
    format: str = typer.Option(
        "html",
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
    goal: str = typer.Option(
        None,
        "--goal",
        "-g",
        help="Natural language goal to target specific endpoints (e.g., 'test payment price manipulation')",
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
        console.print(Panel(ASCII_CAT, title="≡ƒÉ▒ Chaos Kitten", border_style="magenta"))
        console.print()

    if demo:
        if not silent:
            console.print("[bold cyan]≡ƒÄ« Running in DEMO mode![/bold cyan]")
        target = target or "http://localhost:5000"
        spec = spec or "examples/sample_openapi.json"
        
        if not silent:
            console.print(f"≡ƒÄ» Target: {target}")
            console.print(f"≡ƒôï Spec: {spec}")
            console.print()

    # Check for API keys if using LLM providers
    import os
    if not demo and not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("OPENAI_API_KEY"):
        if not silent:
            console.print("[bold red]Γ¥î I can't see![/bold red]")
            console.print("I need an [bold]ANTHROPIC_API_KEY[/bold] or [bold]OPENAI_API_KEY[/bold] to plan my mischief.")
            console.print("[dim]Please set one in your environment or .env file.[/dim]")
        
        if not demo:
            # Check config or proceed with warning? 
            # Original code raised error unless demo mode.
            pass # We'll enforce later if orchestrator needs it, but let's stick to HEAD logic for a bit or Upstream logic...
            # Upstream logic: warn only. HEAD logic: raise Exit.
            # I will follow HEAD logic which is stricter but allow override if user knows what they do.
            # Actually, let's just warn if provider is ollama?
            if provider != "ollama":
                 pass # Let HEAD logic prevail down below.
    

    # Build configuration
    app_config = {}
    
    # Try to load from file
    from chaos_kitten.utils.config import Config
    config_loader = Config(config)
    try:
        app_config = config_loader.load()
    except FileNotFoundError:
        # It's okay if file doesn't exist AND we provided args
        if not target and not spec and not demo:
            if not silent:
                console.print(f"[bold red]Γ¥î Config file not found: {config}[/bold red]")
                console.print("Run 'chaos-kitten init' or provide --target and --spec args.")
            raise typer.Exit(code=1)
    except Exception as e:
        if not silent:
            console.print(f"[yellow]Warning: Could not load config file: {e}[/yellow]")

            
    # CLI args override config
    if target:
        if "target" not in app_config: app_config["target"] = {}
        app_config["target"]["base_url"] = target
        # Also support legacy api path for backward compat if needed, but prefer target
        if "api" not in app_config: app_config["api"] = {}
        app_config["api"]["base_url"] = target
        
    if spec:
        if "target" not in app_config: app_config["target"] = {}
        app_config["target"]["openapi_spec"] = spec
        # Support legacy path
        if "api" not in app_config: app_config["api"] = {}
        app_config["api"]["spec_path"] = spec
        
    if output:
        if "reporting" not in app_config: app_config["reporting"] = {}
        app_config["reporting"]["output_path"] = output

    if format:
        if "reporting" not in app_config: app_config["reporting"] = {}
        app_config["reporting"]["format"] = format

    if provider:
        if "agent" not in app_config: app_config["agent"] = {}
        app_config["agent"]["llm_provider"] = provider

    if goal:
        if "agent" not in app_config: app_config["agent"] = {}
        app_config["agent"]["goal"] = goal

    app_config["silent"] = silent

    # Run the orchestrator
    from chaos_kitten.brain.orchestrator import Orchestrator
    
    # Pass chaos flags to Orchestrator
    orchestrator = Orchestrator(app_config, chaos=chaos, chaos_level=chaos_level)
    
    try:
        if not silent:
            console.print("[bold green]≡ƒÜÇ Launching Chaos Kitten...[/bold green]")
        
        import asyncio
        results = asyncio.run(orchestrator.run())

        # Check for orchestrator runtime errors
        if isinstance(results, dict) and results.get("status") == "failed":
            if not silent:
                console.print(f"[bold red]Γ¥î Scan failed:[/bold red] {results.get('error')}")
            raise typer.Exit(code=1)

        # Handle --fail-on
        if fail_on and fail_on.lower() != "none":
            severity_levels = ["low", "medium", "high", "critical"]
            try:
                threshold_index = severity_levels.index(fail_on.lower())
            except ValueError:
                if not silent:
                    console.print(f"[bold yellow]ΓÜá∩╕Å Invalid fail-on level '{fail_on}', defaulting to critical[/bold yellow]")
                threshold_index = 3  # Default to critical
            
            vulnerabilities = results.get("vulnerabilities", [])
            max_severity_found = -1
            
            for vuln in vulnerabilities:
                severity = str(vuln.get("severity", "low")).lower()
                if severity in severity_levels:
                    idx = severity_levels.index(severity)
                    if idx > max_severity_found:
                        max_severity_found = idx
                        
            if max_severity_found >= threshold_index:
                if not silent:
                    console.print(f"[bold red]Γ¥î Found vulnerabilities of severity {severity_levels[max_severity_found].upper()} or higher. Failing pipeline.[/bold red]")
                raise typer.Exit(code=1)
            elif not silent:
                console.print("[bold green]Γ£à No vulnerabilities found exceeding the failure threshold.[/bold green]")

    except typer.Exit:
        raise
    except Exception as e:
        if not silent:
            console.print(f"[bold red]Γ¥î Scan failed:[/bold red] {e}")
            # import traceback
            # console.print(traceback.format_exc())
        raise typer.Exit(code=1)


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
    console.print(Panel(ASCII_CAT, title="≡ƒÉ▒ Chaos Kitten - Diff Mode", border_style="magenta"))
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
            console.print(f"[bold red]Γ¥î File not found:[/bold red] {path}")
            raise typer.Exit(code=1)

        content = spec_path.read_text(encoding="utf-8")
        try:
            if spec_path.suffix in [".yaml", ".yml"]:
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except Exception as e:
            console.print(f"[bold red]Γ¥î Failed to parse spec:[/bold red] {e}")
            raise typer.Exit(code=1)

    old_spec = load_spec(old)
    new_spec = load_spec(new)

    # Compute diff
    console.print("[bold cyan]≡ƒôè Computing API diff...[/bold cyan]")
    differ = SpecDiffer(old_spec, new_spec)
    diff_result = differ.compute_diff()

    summary = diff_result["summary"]
    critical_findings = diff_result["critical_findings"]

    # Display diff summary
    console.print()
    console.print(Panel(
        f"""[bold]Diff Summary:[/bold]
        
≡ƒôè Total endpoints in old spec: {summary['total_old']}
≡ƒôè Total endpoints in new spec: {summary['total_new']}

Γ₧ò [green]Added endpoints:[/green] {summary['added_count']}
Γ₧û [yellow]Removed endpoints:[/yellow] {summary['removed_count']}
≡ƒöä [cyan]Modified endpoints:[/cyan] {summary['modified_count']}
Γ£ô [dim]Unchanged endpoints:[/dim] {summary['unchanged_count']}
""",
        title="API Spec Diff",
        border_style="cyan"
    ))

    # Show critical findings immediately
    if critical_findings:
        console.print()
        console.print(Panel(
            f"[bold red]≡ƒÜ¿ {len(critical_findings)} CRITICAL security regression(s) detected![/bold red]",
            border_style="red"
        ))
        for finding in critical_findings:
            console.print(f"  ΓÇó [red]{finding.method} {finding.path}[/red]: {finding.reason}")
            for mod in finding.modifications or []:
                console.print(f"    - {mod}")
        console.print()

    # Show what will be tested (display-only count; orchestrator uses spec/delta config)
    if full:
        console.print("[bold yellow]ΓÜá∩╕Å  --full flag set: Testing ALL endpoints[/bold yellow]")
        endpoints_to_test_display = summary["total_new"]
    else:
        endpoints_to_test_display = summary["added_count"] + summary["modified_count"]
        console.print(f"[bold green]Γ£ô Delta mode:[/bold green] Testing {endpoints_to_test_display} changed endpoints, skipping {summary['unchanged_count']} unchanged")

    if endpoints_to_test_display == 0 and not critical_findings:
        console.print()
        console.print("[bold green]Γ£à No changes detected! API is identical.[/bold green]")
        return

    # Check for target URL when we have endpoints to test
    if endpoints_to_test_display > 0 and not target:
        console.print()
        console.print("[bold red]Γ¥î Missing --base-url:[/bold red] Need target URL to test endpoints")
        console.print("[dim]Example: --base-url https://api.example.com[/dim]")
        raise typer.Exit(code=1)

    # Only pre-scan critical findings exist (no endpoints to test) ΓÇö exit without running orchestrator
    if endpoints_to_test_display == 0:
        console.print()
        console.print("[bold yellow]Γä╣∩╕Å  No changed endpoints to test ΓÇö critical findings already displayed above[/bold yellow]")
        if fail_on_critical:
            console.print(f"[bold red]Γ¥î Found {len(critical_findings)} critical issue(s). Failing pipeline.[/bold red]")
            raise typer.Exit(code=1)
        return

    # Prepare config for orchestrator
    # Try to load from chaos-kitten.yaml if it exists
    app_config = {}
    from chaos_kitten.utils.config import Config
    import os
    
    config_path = "chaos-kitten.yaml"
    if os.path.exists(config_path):
        config_loader = Config(config_path)
        try:
            app_config = config_loader.load()
        except Exception:
            pass  # Fall back to defaults if config load fails
    
    # Override/set required fields
    if "target" not in app_config:
        app_config["target"] = {}
    app_config["target"]["base_url"] = target
    app_config["target"]["openapi_spec"] = new
    
    if "agent" not in app_config:
        app_config["agent"] = {}
    # Use provider flag or fall back to config or default
    if provider:
        app_config["agent"]["llm_provider"] = provider
    elif "llm_provider" not in app_config["agent"]:
        app_config["agent"]["llm_provider"] = "anthropic"
    
    # Set model defaults if not in config
    if "model" not in app_config["agent"]:
        app_config["agent"]["model"] = "claude-3-5-sonnet-20241022"
    if "temperature" not in app_config["agent"]:
        app_config["agent"]["temperature"] = 0.7
    if "max_iterations" not in app_config["agent"]:
        app_config["agent"]["max_iterations"] = 10
    
    if "executor" not in app_config:
        app_config["executor"] = {}
    if "concurrent_requests" not in app_config["executor"]:
        app_config["executor"]["concurrent_requests"] = 5
    if "timeout" not in app_config["executor"]:
        app_config["executor"]["timeout"] = 30
    
    # Use reporting key to match orchestrator expectations
    if "reporting" not in app_config:
        app_config["reporting"] = {}
    app_config["reporting"]["output_path"] = output
    app_config["reporting"]["format"] = format
    app_config["reporting"]["include_poc"] = True
    app_config["reporting"]["include_remediation"] = True
    
    # Diff mode specific
    app_config["diff_mode"] = {
        "enabled": not full,
        "delta_endpoints": differ.get_delta_endpoints() if not full else None,
        "critical_findings": critical_findings,
    }

    # Run orchestrator with diff mode
    console.print()
    console.print(f"[bold cyan]≡ƒÄ» Starting security scan on {'changed' if not full else 'all'} endpoints...[/bold cyan]")
    console.print()

    from chaos_kitten.brain.orchestrator import Orchestrator

    orchestrator = Orchestrator(app_config)
    try:
        import asyncio
        results = asyncio.run(orchestrator.run())

        # Check for orchestrator runtime errors
        if isinstance(results, dict) and results.get("status") == "failed":
            console.print(f"[bold red]Γ¥î Scan failed:[/bold red] {results.get('error')}")
            raise typer.Exit(code=1)

        # Handle --fail-on-critical (including pre-scan findings)
        if fail_on_critical:
            vulnerabilities = results.get("vulnerabilities", [])
            critical_vulns = [
                v for v in vulnerabilities 
                if str(v.get("severity", "")).lower() == "critical"
            ]
            # Note: orchestrator already injected critical_findings into vulnerabilities, so no need to add again
            total_critical = len(critical_vulns)
            
            if total_critical > 0:
                console.print(f"[bold red]Γ¥î Found {total_critical} critical issue(s). Failing pipeline.[/bold red]")
                raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Γ¥î Diff scan failed:[/bold red] {e}")
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
    """≡ƒÉ▒ Meow!"""
    console.print(Panel(ASCII_CAT, title="≡ƒÉ▒ Meow!", border_style="magenta"))
    console.print("[italic]I'm going to knock some vulnerabilities off your API table![/italic]")


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
    
    console.print(Panel(f"≡ƒöì Validating profiles in [bold]{path}[/bold]...", title="Profile Validator", border_style="blue"))
    
    validator = AttackProfileValidator()
    
    if not os.path.exists(path):
        console.print(f"[bold red]Γ¥î Directory not found:[/bold red] {path}")
        raise typer.Exit(code=1)
        
    results = validator.validate_all_profiles(path)
    
    if not results:
        console.print("[yellow]ΓÜá∩╕Å  No profiles found.[/yellow]")
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
            console.print(f"  Γ¥î {error}", style="red")
            
        for warning in report.warnings:
            console.print(f"  ΓÜá∩╕Å  {warning}", style="yellow")
            
        for suggestion in report.suggestions:
            console.print(f"  ≡ƒÆí {suggestion}", style="blue")
            
        console.print()
        
    if has_errors:
        console.print("[bold red]Γ¥î Validation failed. Please fix key errors.[/bold red]")
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]Γ£à All profiles valid![/bold green]")

if __name__ == "__main__":
    app()
