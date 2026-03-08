from __future__ import annotations

"""The Brain Orchestrator - Main agent logic using LangGraph."""

import asyncio
import json
import logging
import time
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, TypedDict

try:
    from langgraph.graph import END, START, StateGraph, Graph
    HAS_LANGGRAPH = True
except (ImportError, TypeError):
    HAS_LANGGRAPH = False
    StateGraph = None
    Graph = None
    END = None
    START = None

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from chaos_kitten.utils.checkpoint import (
    CheckpointData,
    calculate_config_hash,
    clean_checkpoint,
    load_checkpoint,
    save_checkpoint,
)
from chaos_kitten.brain.recon import ReconEngine
from chaos_kitten.brain.openapi_parser import OpenAPIParser
from chaos_kitten.brain.attack_planner import NaturalLanguagePlanner, AttackPlanner
from chaos_kitten.paws.analyzer import ResponseAnalyzer
from chaos_kitten.paws.executor import Executor
from chaos_kitten.litterbox.reporter import Reporter

logger = logging.getLogger(__name__)
console = Console()

class AgentState(TypedDict):
    """The state shared between nodes in the graph."""
    targets: List[str]
    openapi_spec: Optional[Dict[str, Any]]
    attack_profiles: List[Dict[str, Any]]
    planned_attacks: List[Dict[str, Any]]
    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    recon_results: Dict[str, Any]
    nl_plan: Optional[Dict[str, Any]]  # Natural language planning results


async def run_recon(state: AgentState, app_config: Dict[str, Any], silent: bool = False) -> Dict[str, Any]:
    """Run the reconnaissance engine."""
    
    console.print("[bold blue]🔍 Starting Reconnaissance Phase...[/bold blue]")
    if state.get("recon_results"):
        if not silent:
            console.print("[yellow]✨ Skipping recon (results loaded from checkpoint)[/yellow]")
        return {"recon_results": state["recon_results"]}

    try:
        engine = ReconEngine(app_config)
        results = await engine.run()

        if results and not silent:
            subs = len(results.get('subdomains', []))
            techs = len(results.get('technologies', {}))
            console.print(f"[green]Recon complete: Found {subs} subdomains and fingerprint info for {techs} targets[/green]")
        return {"recon_results": results}
    except Exception as e:
        logger.exception("Reconnaissance failed")
        if not silent:
            console.print(f"[red]Reconnaissance failed: {e}[/red]")
        return {"recon_results": {}}


async def parse_openapi(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Parse the OpenAPI specification."""
    
    console.print("[bold blue]📖 Parsing OpenAPI Specification...[/bold blue]")
    if state.get("openapi_spec"):
        return {"openapi_spec": state["openapi_spec"]}
        
    recon = state.get("recon_results", {})
    spec_path = recon.get("openapi_spec_path")
    
    # Fall back to config target.openapi_spec if recon didn't find one
    if not spec_path:
        target_cfg = app_config.get("target", {})
        spec_path = target_cfg.get("openapi_spec")
    
    if not spec_path:
        console.print("[yellow]⚠️ No OpenAPI spec found during recon or config.[/yellow]")
        return {"openapi_spec": None}
        
    try:
        parser = OpenAPIParser(spec_path)
        spec = parser.parse()
        console.print(f"[green]OpenAPI spec parsed: Found {len(spec.get('paths', {}))} endpoints[/green]")
        return {"openapi_spec": spec}
    except Exception as e:
        logger.error(f"Failed to parse OpenAPI spec: {e}")
        return {"openapi_spec": {}}


async def natural_language_plan(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a high-level natural language attack plan."""
    
    console.print("[bold blue]📝 Generating Natural Language Attack Plan...[/bold blue]")
    if state.get("nl_plan"):
        return {"nl_plan": state["nl_plan"]}
        
    try:
        # Extract endpoints from the parsed OpenAPI spec
        spec = state.get("openapi_spec") or {}
        endpoints = []
        for path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "parameters": details.get("parameters", []),
                        "requestBody": details.get("requestBody"),
                    })

        planner = NaturalLanguagePlanner(endpoints=endpoints, config=app_config)
        goal = app_config.get("agent", {}).get("goal", "Find security vulnerabilities")
        nl_plan = planner.plan(goal)
        return {"nl_plan": nl_plan}
    except Exception as e:
        logger.error(f"Failed to generate NL plan: {e}")
        return {"nl_plan": None}


async def plan_attacks(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Plan specific attack vectors based on the API spec."""
    
    console.print("[bold blue]🎯 Planning Attack Vectors...[/bold blue]")
    if state.get("planned_attacks"):
        return {"planned_attacks": state["planned_attacks"]}
        
    try:
        # Extract endpoints from the parsed OpenAPI spec
        spec = state.get("openapi_spec") or {}
        endpoints = []
        for path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "parameters": details.get("parameters", []),
                        "requestBody": details.get("requestBody"),
                    })

        # ── Dynamic API Discovery (Spidering) ──────────────────
        spider_cfg = app_config.get("spider", {})
        if spider_cfg.get("enabled", False):
            try:
                from chaos_kitten.brain.spider import Spider

                target_url = app_config.get("target", {}).get("base_url", "")
                spider = Spider(
                    base_url=target_url,
                    max_depth=spider_cfg.get("max_depth", 3),
                    max_pages=spider_cfg.get("max_pages", 100),
                    concurrency=spider_cfg.get("concurrency", 5),
                    timeout=spider_cfg.get("timeout", 10.0),
                )
                console.print("[bold cyan]🕷️  Spidering target for hidden endpoints...[/bold cyan]")
                spider_results = await spider.crawl()
                spidered = spider.to_endpoint_dicts()

                # Merge: only add paths not already covered by the spec
                existing_paths = {ep["path"] for ep in endpoints}
                new_endpoints = [ep for ep in spidered if ep["path"] not in existing_paths]
                endpoints.extend(new_endpoints)

                if new_endpoints:
                    console.print(
                        f"[green]🕷️  Spider discovered {len(new_endpoints)} new endpoint(s) "
                        f"(visited {spider_results['pages_visited']} pages)[/green]"
                    )
            except Exception as spider_err:
                logger.warning("Spider phase failed: %s", spider_err)

        if not endpoints:
            console.print("[yellow]⚠️ No endpoints found to plan attacks against.[/yellow]")
            return {"planned_attacks": []}

        planner = AttackPlanner(endpoints=endpoints)
        planned = planner.plan_attacks()
        console.print(f"[green]Planned {len(planned)} attack vectors.[/green]")
        return {"planned_attacks": planned}
    except Exception as e:
        logger.error(f"Failed to plan attacks: {e}")
        return {"planned_attacks": []}


def _interactive_prompt(attack: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Prompt user for confirmation/modification of an attack."""
    payload = attack.get("body") if attack.get("body") is not None else attack.get("payload")
    payload_str = json.dumps(payload, indent=2) if payload is not None else "None"
    
    console.print(Panel(
        f"[bold]Name:[/bold] {attack.get('name', 'Unnamed Attack')}\n"
        f"[bold]Type:[/bold] {attack.get('type')}\n"
        f"[bold]Method:[/bold] {attack.get('method')}\n"
        f"[bold]Path:[/bold] {attack.get('path')}\n"
        f"[bold]Payload:[/bold]\n{payload_str}",
        title="[yellow]🛑 Execution Paused (Interactive Mode)[/yellow]",
        border_style="yellow"
    ))
    
    action = Prompt.ask(
        "Action ([green]y[/green]es/[red]n[/red]o/[blue]m[/blue]odify)",
        choices=["y", "n", "m"],
        default="y"
    )
    
    if action == "n":
        console.print("[dim]Skipping attack...[/dim]")
        return None
        
    if action == "m":
        # Modify logic
        console.print("[cyan]Enter new payload (JSON format):[/cyan]")
        new_payload_str = Prompt.ask("", default=json.dumps(payload) if payload is not None else "{}")
        try:
            new_payload = json.loads(new_payload_str)
            attack_copy = attack.copy()
            if attack_copy.get("body") is not None:
                attack_copy["body"] = new_payload
            else:
                attack_copy["payload"] = new_payload
            console.print("[green]Payload updated![/green]")
            return attack_copy
        except json.JSONDecodeError:
            console.print("[red]Invalid JSON! Proceeding with original payload.[/red]")
            return attack
            
    return attack


async def execute_and_analyze(state: AgentState, executor: Any, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute planned attacks and analyze responses."""
    from chaos_kitten.paws.analyzer import ResponseAnalyzer
    # Feature 88: Import new ErrorAnalyzer
    from chaos_kitten.brain.response_analyzer import ResponseAnalyzer as ErrorAnalyzer
    
    console.print("[bold blue]⚔️  Executing Attacks...[/bold blue]")

    planned_attacks = state.get("planned_attacks", [])
    if not planned_attacks:
        console.print("[yellow]No attacks planned — skipping execution.[/yellow]")
        return {"results": [], "findings": []}

    target_cfg = app_config.get("target", {})
    base_url = target_cfg.get("base_url", "")
    analyzer = ResponseAnalyzer()
    error_analyzer = ErrorAnalyzer()
    
    all_results = []
    all_findings = []

    for attack in planned_attacks:
        try:
            # Interactive Mode
            if app_config.get("execution", {}).get("interactive", False):
                attack = _interactive_prompt(attack)
                if attack is None:
                    continue

            # Check for concurrency attack
            if attack.get("concurrency"):
                concurrency_opts = attack.get("concurrency", {})
                try:
                    count = int(concurrency_opts.get("count", 5))
                except (ValueError, TypeError):
                    count = 5
                console.print(f"[bold cyan]⚡ Launching concurrent attack ({count} requests) on {attack.get('path')}...[/bold cyan]")
                
                # Execute requests concurrently
                tasks = [
                    executor.execute_attack(
                        method=attack.get("method", "GET"),
                        path=attack.get("path", "/"),
                        payload=attack.get("body") if attack.get("body") is not None else attack.get("payload"),
                        headers=attack.get("headers", {})
                    )
                    for _ in range(count)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Custom analysis for race conditions
                valid_responses = [r for r in responses if not isinstance(r, Exception)]
                if valid_responses:
                    # Check if all/multiple succeeded where only one should have
                    success_count = sum(1 for r in valid_responses if 200 <= r.get("status_code", 500) < 300)
                    if success_count > 1:
                        severity = attack.get("severity", "high")
                        finding = {
                            "type": attack.get("type", "race_condition"),
                            "name": attack.get("name", "Race Condition Detected"),
                            "description": f"Potential race condition: {success_count}/{count} concurrent requests succeeded.",
                            "severity": severity,
                            "evidence": f"Responses: {[r.get('status_code') for r in valid_responses]}",
                            "recommendation": attack.get("remediation", "Implement proper locking or atomic transactions."),
                            "endpoint": attack.get("path")
                        }
                        all_findings.append(finding)
                        console.print(f"[red]🚨 Race condition detected! ({success_count} successes)[/red]")
                    all_results.extend(valid_responses)
                continue

            # Check for workflow bypass attack
            if attack.get("workflow"):
                workflow_steps = attack.get("workflow", [])
                console.print(f"[bold cyan]🔄 Executing workflow attack ({len(workflow_steps)} steps): {attack.get('name')}...[/bold cyan]")
                
                step_results = []
                for step in workflow_steps:
                    # Interactive Mode for Steps
                    if app_config.get("execution", {}).get("interactive", False):
                        step = _interactive_prompt(step)
                        if step is None:
                            console.print("[yellow]Workflow step skipped by user.[/yellow]")
                            continue

                    response = await executor.execute_attack(
                        method=step.get("method", "GET"),
                        path=step.get("path", "/"),
                        payload=step.get("body") if step.get("body") is not None else step.get("payload"),
                        headers=step.get("headers", {}) or attack.get("headers", {}),
                    )
                    step_results.append(response)
                    
                    if not (200 <= response.get("status_code", 500) < 300):
                         # If a step fails, usually the workflow is broken, but for negative testing
                         # we might expect failure or success depending on the goal.
                         # Assuming we want to complete the flow to test bypass.
                         # If "success_indicators" match the FINAL response, we are good.
                         pass
                
                # Analyze final result (or specific step results if needed)
                final_response = step_results[-1] if step_results else {}
                
                # Use standard analyzer for the final result
                analysis = analyzer.analyze(final_response, attack)
                if analysis:
                    all_findings.append(analysis)
                    console.print(f"[red]🚨 Vulnerability found: {analysis.vulnerability_type}[/red]")
                
                all_results.extend(step_results)
                continue

            payload = {
                "method": attack.get("method", "GET"),
                "url": f"{base_url}{attack.get('path', '/')}",
                "headers": attack.get("headers", {}),
                "body": attack.get("body") or attack.get("payload"),
            }
            # Executor handles the request and retries
            # Updated to use execute_attack with unpacked arguments as expected by Executor class
            response = await executor.execute_attack(
                method=payload["method"],
                path=attack.get("path", "/"),
                payload=payload["body"],
                headers=payload["headers"]
            )
            all_results.append(response)

            # Standard Analysis
            finding = analyzer.analyze(response, attack, endpoint=f"{attack.get('method')} {attack.get('path')}", payload=str(payload.get('body')))
            if finding:
                all_findings.extend(finding if isinstance(finding, list) else [finding])
            
            # Feature 88: Error Analysis
            # Normalize response data for ErrorAnalyzer
            response_data = {
                "body": response.get("body", response.get("response_body", "")),
                "status_code": response.get("status_code", 0),
                "elapsed_ms": response.get("elapsed_ms", response.get("response_time", 0)),
            }
            
            error_res = error_analyzer.analyze_error_messages(response_data)
            if error_res.get("error_category"):
                cat = error_res["error_category"]
                conf = error_res.get("confidence", 0.0)
                inds = error_res.get("indicators", [])
                
                # Create a Finding-like dict or object compatible with existing findings list
                # Assuming simple dict for now, or using Finding class if imported
                from chaos_kitten.paws.analyzer import Finding, Severity as PawsSeverity
                
                # Map error category to PawsSeverity? Or keep as high/critical.
                severity_map = {
                    "sql_injection": PawsSeverity.CRITICAL,
                    "command_injection": PawsSeverity.CRITICAL,
                    "xxe": PawsSeverity.HIGH,
                    "nosql_injection": PawsSeverity.HIGH,
                    "path_traversal": PawsSeverity.HIGH,
                }
                
                error_finding = Finding(
                    vulnerability_type=f"Potential {cat} (Error Leak)",
                    severity=severity_map.get(cat, PawsSeverity.MEDIUM),
                    evidence=f"Error patterns matched: {inds}",
                    endpoint=f"{attack.get('method')} {attack.get('path')}",
                    payload=str(payload.get('body')),
                    recommendation="Review error handling and sanitize inputs.",
                    confidence=conf
                )
                all_findings.append(error_finding)

        except Exception as e:
            logger.warning(f"Attack execution failed for {attack.get('path')}: {e}")

    console.print(
        f"[green]Executed {len(all_results)} attacks, found {len(all_findings)} potential vulnerabilities.[/green]"
    )

    # ── PoC Generation Phase ─────────────────────────────────
    if all_findings:
        try:
            from chaos_kitten.brain.poc_generator import PoCGenerator

            poc_gen = PoCGenerator(
                base_url=base_url,
                output_dir=app_config.get("reporting", {}).get("poc_dir", "pocs"),
                llm_provider=app_config.get("agent", {}).get("llm_provider", "anthropic"),
            )

            # Normalise findings to dicts for the generator
            normalised = []
            for f in all_findings:
                if isinstance(f, dict):
                    normalised.append(f)
                elif hasattr(f, "to_dict"):
                    # Prefer explicit serialisation (e.g. StateFinding, Finding)
                    normalised.append(f.to_dict())
                elif hasattr(f, "__dict__"):
                    d = {}
                    for k, v in f.__dict__.items():
                        if k.startswith("_"):
                            continue
                        # Handle Enum values (e.g. Severity.HIGH → "high")
                        d[k] = v.value if hasattr(v, "value") else v
                    normalised.append(d)

            poc_paths = poc_gen.generate_batch(normalised)
            if poc_paths:
                console.print(
                    f"[bold magenta]📝 Generated {len(poc_paths)} PoC script(s) in '{poc_gen.output_dir}'[/bold magenta]"
                )
        except Exception as e:
            logger.warning("PoC generation phase failed: %s", e)

    return {"results": all_results, "findings": all_findings}


def should_continue(state: AgentState) -> Literal["plan", "end"]:
    """Determine if more attack planning is needed."""
    return "end"


class Orchestrator:
    """Orchestrates the main agent workflow using LangGraph."""

    def __init__(self, config: Dict[str, Any], chaos: bool = False, chaos_level: int = 3, resume: bool = False):
        self.config = config
        self.chaos = chaos
        self.chaos_level = chaos_level
        self.resume = resume
        self.checkpoint_file = Path("chaos-kitten.checkpoint.json")

    async def run(self) -> Dict[str, Any]:
        """Run the full agentic workflow."""
        if not HAS_LANGGRAPH:
            console.print("[bold red]Error: langgraph is not installed.[/bold red]")
            return {"status": "failed", "error": "langgraph is not installed"}

        from chaos_kitten.paws.executor import Executor
        
        target_cfg = self.config.get("target", {})
        auth_cfg = self.config.get("auth", {})
        
        # Extract retry settings from executor config or nested 'retry' block
        executor_config = self.config.get("executor", {})
        retry_config = executor_config.get("retry", {})

        # Initialize Executor with Context Manager to handle connections
        async with Executor(
            base_url=target_cfg.get("base_url", ""),
            auth_type=auth_cfg.get("type", "none"),
            auth_token=auth_cfg.get("token"),
            rate_limit=executor_config.get("rate_limit", 10),
            timeout=executor_config.get("timeout", 30),
            retry_config=retry_config
        ) as executor:
            
            graph = self._build_graph(executor)
            
            initial_state: AgentState = {
                "targets": [],
                "openapi_spec": None,
                "attack_profiles": [],
                "planned_attacks": [],
                "results": [],
                "findings": [],
                "recon_results": {},
                "nl_plan": None   
            }

            # Handle resume
            if self.resume:
                checkpoint = load_checkpoint(self.checkpoint_file)
                if checkpoint:
                    # Restore available state from checkpoint fields
                    if checkpoint.recon_results:
                        initial_state["recon_results"] = checkpoint.recon_results
                    if checkpoint.vulnerabilities:
                        initial_state["findings"] = checkpoint.vulnerabilities
                    console.print("[bold green]🔄 Resuming from checkpoint...[/bold green]")

            try:
                final_state = await graph.ainvoke(initial_state)

                # ── Chaos Testing Phase ──────────────────────────
                if self.chaos:
                    from chaos_kitten.brain.chaos_engine import ChaosEngine

                    # Build endpoint list from the parsed OpenAPI spec
                    chaos_endpoints = []
                    spec = final_state.get("openapi_spec") or {}
                    for path, methods in spec.get("paths", {}).items():
                        for method, details in methods.items():
                            if method.upper() not in (
                                "GET", "POST", "PUT", "PATCH", "DELETE",
                            ):
                                continue
                            # Extract field names and types from requestBody
                            fields: Dict[str, str] = {}
                            required_fields: List[str] = []
                            req_body = details.get("requestBody", {})
                            content = req_body.get("content", {}) if req_body else {}
                            json_schema = (
                                content
                                .get("application/json", {})
                                .get("schema", {})
                            )
                            if json_schema:
                                props = json_schema.get("properties", {})
                                for fname, fmeta in props.items():
                                    fields[fname] = fmeta.get("type", "string")
                                required_fields = json_schema.get("required", [])

                            chaos_endpoints.append({
                                "path": path,
                                "method": method.upper(),
                                "fields": fields,
                                "required_fields": required_fields,
                            })

                    engine = ChaosEngine(
                        chaos_level=self.chaos_level, executor=executor,
                    )
                    target_url_chaos = target_cfg.get("base_url", "")
                    chaos_findings = await engine.run_chaos_tests(
                        target_url_chaos,
                        endpoints=chaos_endpoints if chaos_endpoints else None,
                    )

                    # Merge chaos findings into the main findings list
                    existing_findings = list(final_state.get("findings", []))
                    existing_findings.extend(chaos_findings)
                    final_state["findings"] = existing_findings

                # ── State Machine Testing Phase ──────────────────
                state_cfg = self.config.get("state_machine", {})
                if state_cfg.get("enabled", False):
                    try:
                        from chaos_kitten.brain.state_machine import StateMachineAgent

                        console.print("[bold blue]🔗 Running State Machine Tests...[/bold blue]")

                        # Build endpoint list from spec
                        sm_endpoints = []
                        spec = final_state.get("openapi_spec") or {}
                        for path, methods in spec.get("paths", {}).items():
                            for method, details in methods.items():
                                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                                    sm_endpoints.append({
                                        "method": method.upper(),
                                        "path": path,
                                        "parameters": details.get("parameters", []),
                                        "requestBody": details.get("requestBody"),
                                    })

                        agent = StateMachineAgent(
                            base_url=target_cfg.get("base_url", ""),
                            executor=executor,
                            auth_token_b=state_cfg.get("auth_token_b"),
                        )
                        sm_findings = await agent.analyse(sm_endpoints)

                        if sm_findings:
                            existing = list(final_state.get("findings", []))
                            existing.extend(sm_findings)
                            final_state["findings"] = existing
                            console.print(
                                f"[red]🔗 State Machine found {len(sm_findings)} "
                                f"business-logic issue(s).[/red]"
                            )
                    except Exception as sm_err:
                        logger.warning("State machine tests failed: %s", sm_err)

                # Save checkpoint (implied success if we got here)
                save_checkpoint(CheckpointData(
                    target_url=self.config.get("target", {}).get("base_url", ""),
                    config_hash=calculate_config_hash(self.config),
                    completed_profiles=[],
                    vulnerabilities=final_state.get("findings", []),
                    timestamp=time.time(),
                    recon_results=final_state.get("recon_results", {}),
                ), self.checkpoint_file)

                # Generate report
                reporter_cfg = self.config.get("reporting", {})
                reporter = Reporter(
                    output_path=reporter_cfg.get("output_path", "./reports"),
                    output_format=reporter_cfg.get("format", "html"),
                )
                
                target_url = target_cfg.get("base_url", "")
                
                report_file = reporter.generate(
                    {"vulnerabilities": final_state.get("findings", [])}, target_url
                )
                
                console.print(
                    f"[bold cyan] Report generated:[/bold cyan] [underline]{report_file}[/underline]"
                )

                return {
                    "status": "success",
                    "summary": {
                        "tested_endpoints": len(final_state.get("results", [])),
                        "vulnerabilities_found": len(final_state.get("findings", []))
                    },
                    "findings": final_state.get("findings", [])
                }
            except Exception as e:
                logger.exception("Orchestrator execution failed")
                return {"status": "failed", "error": str(e)}

    def _build_graph(self, executor: Any) -> StateGraph:
        """Build the LangGraph workflow."""
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("recon", partial(run_recon, app_config=self.config))
        workflow.add_node("parse", partial(parse_openapi, app_config=self.config))
        workflow.add_node("nl_plan", partial(natural_language_plan, app_config=self.config))
        workflow.add_node("plan", partial(plan_attacks, app_config=self.config))
        workflow.add_node("execute", partial(execute_and_analyze, executor=executor, app_config=self.config))

        # Edges
        workflow.add_edge(START, "recon")
        workflow.add_edge("recon", "parse")
        workflow.add_edge("parse", "nl_plan")
        workflow.add_edge("nl_plan", "plan")
        workflow.add_edge("plan", "execute")

        workflow.add_conditional_edges(
            "execute",
            should_continue,
            {
                "plan": "plan",
                "end": END
            }
        )

        return workflow.compile()
