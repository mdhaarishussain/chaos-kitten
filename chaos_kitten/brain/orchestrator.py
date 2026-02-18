"""The Brain Orchestrator - Main agent logic using LangGraph."""

import json
import logging
from functools import partial
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
)

from chaos_kitten.brain.attack_planner import AttackPlanner

# Internal Chaos Kitten imports
from chaos_kitten.brain.openapi_parser import OpenAPIParser
# from chaos_kitten.brain.response_analyzer import ResponseAnalyzer # Deprecated/Replaced
from chaos_kitten.paws.analyzer import ResponseAnalyzer
from chaos_kitten.litterbox.reporter import Reporter
from chaos_kitten.paws.executor import Executor

logger = logging.getLogger(__name__)
console = Console()


class AgentState(TypedDict):
    spec_path: str
    base_url: str
    endpoints: list[dict]
    current_endpoint: int
    planned_attacks: list[dict]
    results: list[dict]
    findings: list[dict]


def parse_openapi(state: AgentState) -> dict:
    try:
        parser = OpenAPIParser(state["spec_path"])
        parser.parse()
        endpoints = parser.get_endpoints()
    except Exception:
        logger.exception("Failed to parse OpenAPI spec")
        raise
    return {"endpoints": endpoints, "current_endpoint": 0}


def plan_attacks(state: AgentState) -> dict:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"planned_attacks": []}

    endpoint = state["endpoints"][idx]
    planner = AttackPlanner([endpoint])
    return {"planned_attacks": planner.plan_attacks(endpoint)}


async def execute_and_analyze(state: AgentState, executor: Executor) -> dict:
    idx = state["current_endpoint"]
    if idx >= len(state["endpoints"]):
        return {"findings": state["findings"], "current_endpoint": idx}

    endpoint = state["endpoints"][idx]
    analyzer = ResponseAnalyzer()

    new_findings = []

    for attack in state["planned_attacks"]:
        endpoint_path = endpoint.get("path")
        if not endpoint_path:
            logger.warning("Skipping attack - endpoint missing path: %s", endpoint)
            continue
        try:
            result = await executor.execute_attack(
                method=endpoint.get("method", "GET"),
                path=endpoint_path,
                payload=attack.get("payload"),
            )
        except Exception:
            logger.exception(
                "Attack execution failed for %s %s",
                endpoint.get("method"),
                endpoint.get("path"),
            )
            continue

        payload_obj = attack.get("payload")
        if payload_obj is None:
            payload_used = ""
        elif isinstance(payload_obj, dict):
            if len(payload_obj) == 1:
                only_value = next(iter(payload_obj.values()))
                payload_used = (
                    only_value if isinstance(only_value, str) else str(only_value)
                )
            else:
                payload_used = json.dumps(payload_obj, sort_keys=True, default=str)
        else:
            payload_used = str(payload_obj)
        
        # Prepare params for new analyzer signature
        response_data = {
            "body": result.get("body", result.get("response_body", "")),
            "status_code": result.get("status_code", 0),
            "elapsed_ms": result.get("elapsed_ms", result.get("response_time", 0)),
        }
        
        # Attack profile is in 'attack' variable
        finding = analyzer.analyze(
            response=response_data,
            attack_profile=attack,
            endpoint=f"{endpoint.get('method')} {endpoint.get('path')}",
            payload=payload_used
        )

        if finding:
            severity_value = getattr(finding.severity, "value", finding.severity)
            severity_text = str(severity_value).lower()
            title = finding.vulnerability_type or "Potential vulnerability detected"
            description = finding.evidence or "Potential vulnerability detected"
            new_findings.append(
                {
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
            )

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

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def _build_graph(self, executor: Executor):
        workflow = StateGraph(AgentState)

        workflow.add_node("parse", parse_openapi)
        workflow.add_node("plan", plan_attacks)
        workflow.add_node(
            "execute_analyze", partial(execute_and_analyze, executor=executor)
        )

        workflow.add_edge(START, "parse")
        workflow.add_edge("parse", "plan")
        workflow.add_edge("plan", "execute_analyze")

        workflow.add_conditional_edges(
            "execute_analyze", should_continue, {"plan": "plan", "end": END}
        )
        return workflow.compile()

    async def run(self) -> dict[str, Any]:
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

        report_file = reporter.generate(
            {"vulnerabilities": final_state["findings"]}, target_url
        )

        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print(
            f"[bold cyan] Report generated:[/bold cyan] [underline]{report_file}[/underline]"
        )

        return {
            "vulnerabilities": final_state["findings"],
            "summary": {
                "total_endpoints": len(final_state["endpoints"]),
                "tested_endpoints": final_state["current_endpoint"],
                "vulnerabilities_found": len(final_state["findings"]),
            },
        }
