
import asyncio
import json
import logging
from typing import Optional, List, Dict, Any, Tuple
import shlex

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel
from rich.markdown import Markdown

from chaos_kitten.paws.executor import Executor
from chaos_kitten.brain.attack_planner import AttackPlanner

logger = logging.getLogger(__name__)

class ChaosREPL:
    """Interactive REPL for Chaos Kitten."""
    
    def __init__(self, console: Console):
        self.console = console
        self.target_url: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.history: List[Dict[str, Any]] = []
        self.executor: Optional[Executor] = None
        
    async def start(self):
        """Start the interactive loop."""
        self.console.print(Panel("🐱 [bold magenta]Chaos Kitten Interactive Mode[/bold magenta]\nType 'help' for commands.", border_style="magenta"))
        
        while True:
            try:
                # Dynamic prompt based on target
                prompt_text = "[bold cyan]chaos-kitten[/bold cyan]"
                if self.target_url:
                    prompt_text += f" ([dim]{self.target_url}[/dim])"
                prompt_text += " > "
                
                command_str = Prompt.ask(prompt_text)
                
                if not command_str.strip():
                    continue
                    
                await self.handle_command(command_str)
                
            except EOFError:
                break
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Type 'exit' to quit.[/yellow]")
            except Exception as e:
                self.console.print(f"[bold red]Error:[/bold red] {e}")

    async def handle_command(self, command_str: str):
        """Parse and execute a command."""
        try:
            parts = shlex.split(command_str)
        except ValueError as e:
            self.console.print(f"[red]Parse error:[/red] {e} (check for unmatched quotes)")
            return
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd == "exit" or cmd == "quit":
            self.console.print("Bye! 🐾")
            raise SystemExit(0)
            
        elif cmd == "help":
            self.show_help()
            
        elif cmd == "target":
            if not args:
                self.console.print("[red]Usage: target <url>[/red]")
            else:
                self.target_url = args[0]
                self.console.print(f"[green]Target set to:[/green] {self.target_url}")
                
        elif cmd == "auth":
            if not args:
                 self.console.print("[red]Usage: auth <token>[/red]")
            else:
                self.auth_token = args[0]
                self.console.print("[green]Auth token set.[/green]")

        elif cmd == "history":
            self.show_history()

        elif cmd == "send":
            if not self.target_url:
                self.console.print("[red]Please set a target URL first using 'target <url>'.[/red]")
                return
            await self.send_request(args)
            
        else:
            self.console.print(f"[red]Unknown command:[/red] {cmd}")
            
    def show_help(self):
        """Display help menu."""
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        
        table.add_row("target <url>", "Set the target API URL")
        table.add_row("auth <token>", "Set Bearer token for authentication")
        table.add_row("send <method> <path> [body]", "Send a manual HTTP request")
        table.add_row("history", "Show request history")
        table.add_row("help", "Show this help message")
        table.add_row("exit", "Exit the interactive mode")
        
        self.console.print(table)

    def show_history(self):
        """Display request history."""
        if not self.history:
            self.console.print("[dim]No history yet.[/dim]")
            return

        table = Table(title="Request History")
        table.add_column("#", justify="right", style="cyan")
        table.add_column("Method", style="magenta")
        table.add_column("Path", style="green")
        table.add_column("Status", style="bold")
        table.add_column("Duration", justify="right")
        
        for i, req in enumerate(self.history):
            status_style = "green" if 200 <= req.get("status_code", 0) < 300 else "red"
            table.add_row(
                str(i + 1),
                req.get("method"),
                req.get("path"),
                f"[{status_style}]{req.get('status_code')}[/{status_style}]",
                f"{req.get('elapsed_ms', 0):.2f}ms"
            )
            
        self.console.print(table)

    async def send_request(self, args: List[str]):
        """Execute a manual request."""
        if len(args) < 2:
            self.console.print("[red]Usage: send <method> <path> [body][/red]")
            return
            
        method = args[0].upper()
        path = args[1]
        body = args[2] if len(args) > 2 else None
        
        payload = None
        if body:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self.console.print("[red]Invalid JSON body.[/red]")
                return

        self.console.print(f"[dim]Sending {method} {path}...[/dim]")
        
        async with Executor(
            base_url=self.target_url,
            auth_type="bearer" if self.auth_token else "none",
            auth_token=self.auth_token
        ) as executor:
            
            response = await executor.execute_attack(
                method=method,
                path=path,
                payload=payload
            )
            
            # Store in history
            history_item = {
                "method": method,
                "path": path,
                "status_code": response["status_code"],
                "elapsed_ms": response["elapsed_ms"],
                "response_body": response["body"]
            }
            self.history.append(history_item)
            
            # Display result
            self.display_response(response)

    def display_response(self, response: Dict[str, Any]):
        """Render response details."""
        status = response["status_code"]
        style = "green" if 200 <= status < 300 else "red"
        
        self.console.print(f"\n[bold {style}]Status: {status}[/bold {style}]  [dim]Time: {response['elapsed_ms']:.2f}ms[/dim]")
        
        body = response.get("body", "")
        if body:
            try:
                # Try to pretty print JSON
                parsed = json.loads(body)
                self.console.print(Syntax(json.dumps(parsed, indent=2), "json", theme="monokai", word_wrap=True))
            except Exception:
                self.console.print(body)
        else:
            self.console.print("[dim](Empty response)[/dim]")
        self.console.print()
