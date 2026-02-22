"""The Brain Orchestrator - Main agent logic using LangGraph."""

import asyncio
import json
import logging
from collections import defaultdict
from functools import partial
from typing import Any, Dict, List, Literal, Optional, TypedDict

try:
    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except (ImportError, TypeError):
    HAS_LANGGRAPH = False
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from chaos_kitten.brain.attack_planner import AttackPlanner, NaturalLanguagePlanner
try:
    from chaos_kitten.brain.adaptive_planner import AdaptivePayloadGenerator
    HAS_ADAPTIVE = True
except ImportError:
    HAS_ADAPTIVE = False
    AdaptivePayloadGenerator = None
# Internal Chaos Kitten imports
from chaos_kitten.brain.openapi_parser import OpenAPIParser
# from chaos_kitten.brain.response_analyzer import ResponseAnalyzer # Deprecated/Replaced
from chaos_kitten.paws.analyzer import ResponseAnalyzer
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten.paws.executor import Executor
from chaos_kitten.brain.recon import ReconEngine

logger = logging.getLogger(__name__)
console = Console()


class AgentState(TypedDict):
    spec_path: str
    base_url: str
    endpoints: List[Dict[str, Any]]
    current_endpoint: int
    planned_attacks: List[Dict[str, Any]]
    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    recon_results: Dict[str, Any]
    nl_plan: Optional[Dict[str, Any]]  # Natural language planning results


async def run_recon(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    # Renamed to app_config to avoid LangGraph collision
    console.print("[bold blue]🔍 Starting Reconnaissance Phase...[/bold blue]")
    try:
        engine = ReconEngine(app_config)
        
        # Run recon engine in an executor to avoid blocking the async loop
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(None, engine.run)

        if results:
            subs = len(results.get('subdomains', []))
            techs = len(results.get('technologies', {}))
            console.print(f"[green]Recon complete: Found {subs} subdomains and fingerprint info for {techs} targets[/green]")
        return {"recon_results": results}
    except Exception as e:
        logger.exception("Reconnaissance failed")
        console.print(f"[red]Reconnaissance failed: {e}[/red]")
        return {"recon_results": {}}



def parse_openapi(state: AgentState, app_config: Dict[str, Any] = None) -> Dict[str, Any]:
    """Parse OpenAPI spec or use pre-filtered diff endpoints."""
    try:
        # Check if we're in diff mode with pre-computed delta endpoints
        diff_mode = app_config.get("diff_mode", {}) if app_config else {}

        if diff_mode.get("enabled"):
            delta_endpoints = diff_mode.get("delta_endpoints") or []
            if delta_endpoints:
                # Use delta endpoints from diff analysis
                endpoints = delta_endpoints
                console.print(f"[bold cyan]🔄 Diff mode: Testing {len(endpoints)} changed endpoints[/bold cyan]")
            else:
                # Diff mode enabled but no delta endpoints provided/found
                logger.warning(
                    "Diff mode is enabled but no delta_endpoints were provided; "
                    "no endpoints will be tested."
                )
                console.print(
                    "[bold yellow]⚠ Diff mode enabled but no changed endpoints found/provided; skipping tests.[/bold yellow]"
                )
                endpoints = []
        else:
            # Normal mode: parse full spec
            parser = OpenAPIParser(state["spec_path"])
            parser.parse()
            endpoints = parser.get_endpoints()
    except Exception:
        logger.exception("Failed to parse OpenAPI spec")
        raise
    return {"endpoints": endpoints, "current_endpoint": 0}


def natural_language_plan(state: AgentState, app_config: Dict[str, Any]) -> Dict[str, Any]:
    """Filter endpoints based on natural language goal."""
    goal = app_config.get("agent", {}).get("goal")
    
    if not goal:
        # No goal specified, return all endpoints unchanged
        return {"nl_plan": {}}
    
    console.print(f"[bold cyan]🎯 Planning attacks for goal:[/bold cyan] {goal}")
    
    try:
        planner = NaturalLanguagePlanner(state["endpoints"], app_config)
        nl_plan = planner.plan(goal)
        
        # Filter endpoints based on NL plan
        # Build (method, path) set for precise matching
        relevant_pairs = {
            (ep.get("method", "").upper(), ep.get("path"))
            for ep in nl_plan.get("endpoints", [])
        }
        if relevant_pairs:
            filtered_endpoints = [
                ep for ep in state["endpoints"]
                if (ep.get("method", "GET").upper(), ep.get("path")) in relevant_pairs
            ]
        else:
            # Fallback: path-only
            relevant_paths = {ep.get("path") for ep in nl_plan.get("endpoints", [])}
            filtered_endpoints = [
                ep for ep in state["endpoints"]
                if ep.get("path") in relevant_paths
            ]
        
        console.print(
            f"[green]✓ LLM selected {len(filtered_endpoints)}/{len(state['endpoints'])} "
            f"relevant endpoints[/green]"
        )
        
        if nl_plan.get("focus"):
            console.print(f"[yellow]Focus:[/yellow] {nl_plan['focus']}")
        
        return {
            "endpoints": filtered_endpoints or state["endpoints"],  # Fallback to all if none match
            "nl_plan": nl_plan
        }
    except Exception as exc:
        logger.exception("Natural language planning failed: %s", exc)
        console.print("[yellow]⚠️  NL planning failed, using all endpoints[/yellow]")
        return {"nl_plan": {}}


def plan_attacks(state: AgentState) -> Dict[str, Any]:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"planned_attacks": []}

    endpoint = state["endpoints"][idx]
    
    # In future, we can inject recon data into the planner context here.
    # For now, we trust the LLM to deduce context from the endpoint itself.
    
    planner = AttackPlanner([endpoint])
    
    # Extract NL-selected profiles if available
    nl_profiles = (state.get("nl_plan") or {}).get("profiles")
    
    return {"planned_attacks": planner.plan_attacks(endpoint, allowed_profiles=nl_profiles)}


async def execute_and_analyze(
    state: AgentState, executor: Executor, app_config: Dict[str, Any]
) -> Dict[str, Any]:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"findings": state["findings"], "current_endpoint": idx}

    endpoint = state["endpoints"][idx]
    analyzer = ResponseAnalyzer()
    
    adaptive_config = app_config.get("adaptive", {}) or app_config.get("agent", {}).get("adaptive", {})
    adaptive_mode = adaptive_config.get("enabled", False)
    max_rounds = adaptive_config.get("max_rounds", 3)
    
    agent_config = app_config.get("agent", {})
    max_concurrent_agents = agent_config.get("max_concurrent_agents", 3)

    # Initialize Adaptive Generator if needed
    adaptive_gen = None
    if adaptive_mode:
        if not HAS_ADAPTIVE:
            logger.warning("AdaptivePayloadGenerator unavailable (missing dependencies). Adaptive mode disabled.")
            adaptive_mode = False
        else:
            provider = agent_config.get("llm_provider", "anthropic").lower()
            model = agent_config.get("model", "claude-3-5-sonnet-20241022")
            temperature = agent_config.get("temperature", 0.7)

            try:
                if provider == "openai":
                    from langchain_openai import ChatOpenAI
                    llm = ChatOpenAI(model=model, temperature=temperature)
                elif provider == "anthropic":
                    from langchain_anthropic import ChatAnthropic
                    llm = ChatAnthropic(model=model, temperature=temperature)
                else:
                    raise ValueError(f"Unsupported LLM provider for adaptive mode: {provider}")

                    
                adaptive_gen = AdaptivePayloadGenerator(llm, max_rounds=max_rounds)
            except (ImportError, ValueError) as e:
                logger.exception("Failed to set up adaptive LLM: %s", e)
                logger.warning("Adaptive mode disabled due to missing dependencies or invalid provider.")
                adaptive_mode = False

    new_findings = []
    
    # Helper to run a payload and analyze it
    async def run_single_payload(payload_val, attack_conf, is_adaptive=False):
        endpoint_path = endpoint.get("path")
        if not endpoint_path:
            return None, None

        try:
            result = await executor.execute_attack(
                method=endpoint.get("method", "GET"),
                path=endpoint_path,
                payload=payload_val,
            )
        except Exception:
            logger.exception(
                "Attack execution failed for %s %s",
                endpoint.get("method"),
                endpoint.get("path"),
            )
            return None, None

        payload_used = ""
        if payload_val is None:
            payload_used = ""
        elif isinstance(payload_val, dict):
            if len(payload_val) == 1:
                only_value = next(iter(payload_val.values()))
                payload_used = (
                    only_value if isinstance(only_value, str) else str(only_value)
                )
            else:
                payload_used = json.dumps(payload_val, sort_keys=True, default=str)
        else:
            payload_used = str(payload_val)
        
        response_data = {
            "headers": result.get("headers", {}),
            "body": result.get("body", result.get("response_body", "")),
            "status_code": result.get("status_code", 0),
            "elapsed_ms": result.get("elapsed_ms", result.get("response_time", 0)),
        }
        
        # Analyze
        if is_adaptive:
            analysis_attack_profile = attack_conf.copy()
            analysis_attack_profile["name"] = f"[ADAPTIVE] {analysis_attack_profile.get('name', 'Attack')}"
        else:
            analysis_attack_profile = attack_conf

        finding = analyzer.analyze(
            response=response_data,
            attack_profile=analysis_attack_profile,
            endpoint=f"{endpoint.get('method')} {endpoint.get('path')}",
            payload=payload_used
        )

        found_item = None
        if finding:
            severity_value = getattr(finding.severity, "value", finding.severity)
            severity_text = str(severity_value).lower()
            title = finding.vulnerability_type or "Potential vulnerability detected"
            if is_adaptive:
                title = f"[ADAPTIVE] {title}"
                
            description = finding.evidence or "Potential vulnerability detected"
            found_item = {
                "type": finding.vulnerability_type,
                "title": title,
                "description": description,
                "severity": severity_text,
                "endpoint": finding.endpoint,
                "method": endpoint.get("method", "GET"),
                "evidence": finding.evidence,
                "payload": payload_used,
                "proof_of_concept": "",
                "remediation": (
                    finding.recommendation
                    if getattr(finding, "recommendation", "")
                    else "Review input handling and validation."
                ),
            }
        
        return response_data, found_item

    # Process attack group concurrently
    async def process_attack_group(attacks_in_group):
        group_findings = []
        for attack in attacks_in_group:
            # 1. Run initial payload
            resp, finding = await run_single_payload(attack.get("payload"), attack, is_adaptive=False)
            
            # Guard against execution failure
            if resp is None:
                continue

            if finding:
                group_findings.append(finding)
            
            # 2. Adaptive logic (sequential per attack to maintain context)
            if adaptive_mode and adaptive_gen and resp:
                # We limit adaptive rounds here. 
                # Note: The original code had a per-endpoint limiter `llm_calls_count` but here we are in a sub-task.
                # To really limit per endpoint globally, we'd need a shared atomic counter or context managed counter.
                # For simplicity in MVP parallel mode, we limit per attack group or just rely on max_rounds inside generator call loop.
                try:
                    generated_payloads = await adaptive_gen.generate_payloads(
                        endpoint=endpoint,
                        previous_payload=attack.get("payload"),
                        response=resp
                    )
                    # Limit to max_rounds * 5 items or similar heuristic
                    for gen_payload in generated_payloads[:max_rounds*5]:
                        _, adapt_finding = await run_single_payload(gen_payload, attack, is_adaptive=True)
                        if adapt_finding:
                            group_findings.append(adapt_finding)
                except Exception as e:
                    logger.warning("Adaptive generation failed: %s", e)
        return group_findings

    # Group attacks by category/type
    attacks_by_category = defaultdict(list)
    for attack in state["planned_attacks"]:
        cat = attack.get("type", "generic")
        attacks_by_category[cat].append(attack)

    semaphore = asyncio.Semaphore(max_concurrent_agents)

    async def limited_process_category(category_name, attacks):
        async with semaphore:
            # Maybe update progress description?
            # console.log(f"Starting category agent: {category_name}")
            return await process_attack_group(attacks)

    tasks = []
    for cat, attacks in attacks_by_category.items():
        tasks.append(limited_process_category(cat, attacks))
    
    if tasks:
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                new_findings.extend(res)

    return {"findings": state["findings"] + new_findings, "current_endpoint": idx + 1}


def should_continue(state: AgentState) -> Literal["plan", "end"]:
    if state["current_endpoint"] < len(state["endpoints"]):
        return "plan"
    return "end"


class Orchestrator:
    """
    This class uses LangGraph to create an agentic workflow that:
    1. Parses the OpenAPI spec
    2. Plans attack strategies
    3. Executes attacks
    4. Analyzes results
    5. Generates reports
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    def _build_graph(self, executor: Executor):
        if not HAS_LANGGRAPH:
            raise ImportError(
                "langgraph is not available (requires Python 3.9+). "
                "Please upgrade Python or use a compatible langgraph version."
            )
        from langgraph.graph import END, START, StateGraph

        workflow = StateGraph(AgentState)
        workflow.add_node("recon", partial(run_recon, app_config=self.config))
        workflow.add_node("parse", parse_openapi)
        workflow.add_node("nl_plan", partial(natural_language_plan, app_config=self.config))
        workflow.add_node("plan", plan_attacks)

        async def execute_analyze_wrapper(state: AgentState):
            return await execute_and_analyze(state, executor, self.config)

        workflow.add_node("execute_analyze", execute_analyze_wrapper)

        workflow.add_edge(START, "recon")
        workflow.add_edge("recon", "parse")
        workflow.add_edge("parse", "nl_plan")
        workflow.add_edge("nl_plan", "plan")
        workflow.add_edge("plan", "execute_analyze")

        workflow.add_conditional_edges(
            "execute_analyze", should_continue, {"plan": "plan", "end": END}
        )
        return workflow.compile()

    async def run(self) -> Dict[str, Any]:
        console.print("[bold green]🧠 Chaos Kitten Brain Initializing...[/bold green]")

        api_config = self.config.get("api")
        target_config = self.config.get("target")

        spec_path = (
            (api_config.get("spec_path") if isinstance(api_config, dict) else None)
            or self.config.get("spec")
            or (
                target_config.get("openapi_spec")
                if isinstance(target_config, dict)
                else None
            )
        )
        target_url = (
            target_config.get("base_url")
            if isinstance(target_config, dict)
            else target_config
        ) or None

        missing_keys = []
        if not spec_path:
            missing_keys.append("api.spec_path/spec")
        if not target_url:
            missing_keys.append("target.base_url/target")

        if missing_keys:
            raise ValueError(
                f"Missing required configuration: {', '.join(missing_keys)}. "
                f"Please ensure spec_path and target_url are provided in the config."
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:

            scan_task = progress.add_task("[cyan]Scanning endpoints...", total=None)

            async with Executor(base_url=target_url) as executor:
                initial_state: AgentState = {
                    "spec_path": spec_path,
                    "base_url": target_url,
                    "endpoints": [],
                    "current_endpoint": 0,
                    "planned_attacks": [],
                    "results": [],
                    "findings": [],
                    "nl_plan": {},
                }

                app = self._build_graph(executor)

                final_state = initial_state
                async for output in app.astream(initial_state):
                    for node_name, state_update in output.items():
                        final_state.update(state_update)

                        if "endpoints" in state_update:
                            progress.update(
                                scan_task, total=len(state_update["endpoints"])
                            )
                        if node_name == "execute_analyze":
                            progress.advance(scan_task)

        reporter_cfg = self.config.get("reporting", {})
        reporter = Reporter(
            output_path=reporter_cfg.get("output_path", "./reports"),
            output_format=reporter_cfg.get("format", "html"),
        )

        # Add critical findings from diff mode if present
        all_findings = final_state["findings"].copy()
        diff_mode = self.config.get("diff_mode", {})
        
        if diff_mode.get("critical_findings"):
            for critical in diff_mode["critical_findings"]:
                all_findings.append({
                    "type": "Security Regression",
                    "title": f"Authentication Removed: {critical.method} {critical.path}",
                    "description": critical.reason,
                    "severity": "critical",
                    "endpoint": critical.path,
                    "method": critical.method,
                    "evidence": "\n".join(f"• {mod}" for mod in (critical.modifications or [])),
                    "payload": "N/A (Pre-scan finding)",
                    "proof_of_concept": "Compare security requirements in old vs new OpenAPI spec",
                    "remediation": "Restore authentication requirements before deploying to production.",
                })

        report_file = reporter.generate(
            {"vulnerabilities": all_findings}, target_url
        )

        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(
            f"[bold cyan]📄 Report generated:[/bold cyan] [underline]{report_file}[/underline]"
        )

        return {
            "vulnerabilities": all_findings,
            "summary": {
                "total_endpoints": len(final_state["endpoints"]),
                "tested_endpoints": final_state["current_endpoint"],
                "vulnerabilities_found": len(all_findings),
                "diff_mode": diff_mode.get("enabled", False),
            },
        }
