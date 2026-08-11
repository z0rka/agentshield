"""LangGraph assembly of the scan workflow.

The graph exists for what a graph runtime gives you that a `for` loop does not: checkpointed
state so a scan survives a worker restart, streamed node transitions for the SSE feed, and a
trace span per node that lines up with the OpenTelemetry trace running through the whole
platform.

State is carried as a single `scan` key holding the `ScanState` object instead of being
spread across graph channels. Splitting a scan's state into a dozen reducer-managed channels
would buy nothing here - no two nodes write the same field concurrently - and would make the
node signatures depend on the graph library, which is exactly what `nodes.py` avoids.

Import is lazy: LangGraph is an optional extra, and `runner.py` drives the identical nodes
when it is absent.
"""

from __future__ import annotations

from typing import Any, TypedDict

from agentshield.graph import nodes
from agentshield.graph.state import ScanState
from agentshield.telemetry import span


class GraphState(TypedDict):
    """LangGraph channel schema."""

    scan: ScanState


def _wrap(node: Any) -> Any:
    """Adapt an `async (ScanState) -> ScanState` node to LangGraph's update protocol.

    The span is opened here for the same reason `runner.py` opens one: the nodes are pure
    functions with no telemetry imports, so whichever executor is driving them owns the
    tracing. Both must emit `node.<name>`, because the observability contract is about the
    pipeline and not about which runtime happened to run it - and when this wrapper did not,
    switching the default to LangGraph silently dropped every node span. `test_tracing.py`
    caught it, which is the only reason it is not still missing.
    """

    async def invoke(state: GraphState) -> GraphState:
        scan = state["scan"]
        with span(f"node.{node.__name__}", **{"scan.id": scan.scan_id}):
            return {"scan": await node(scan)}

    invoke.__name__ = node.__name__
    return invoke


def route_after_execution(state: GraphState) -> str:
    """Conditional edge out of `execute_attack`."""
    outcome = state["scan"].outcome
    if outcome == nodes.OUTCOME_TARGET_ERROR:
        return "retry_or_stop"
    if outcome == nodes.OUTCOME_BUDGET_EXCEEDED:
        return "finalize_report"
    return "collect_trajectory"


def build_graph(checkpointer: Any | None = None) -> Any:
    """Compile the scan graph.

    Raises ImportError when the `graph` extra is not installed; callers that do not need
    checkpointing should use `agentshield.graph.runner.run_scan` instead.
    """
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(GraphState)

    for node in (
        nodes.load_target,
        nodes.discover_capabilities,
        nodes.build_target_threat_model,
        nodes.select_attack_suite,
        nodes.generate_attack,
        nodes.execute_attack,
        nodes.collect_trajectory,
        nodes.evaluate_deterministically,
        nodes.evaluate_semantically,
        nodes.classify_finding,
        nodes.generate_remediation,
        nodes.minimize_reproduction,
        nodes.finalize_report,
        nodes.retry_or_stop,
    ):
        builder.add_node(node.__name__, _wrap(node))

    builder.add_edge(START, "load_target")
    builder.add_edge("load_target", "discover_capabilities")
    builder.add_edge("discover_capabilities", "build_target_threat_model")
    builder.add_edge("build_target_threat_model", "select_attack_suite")
    builder.add_edge("select_attack_suite", "generate_attack")
    builder.add_edge("generate_attack", "execute_attack")

    builder.add_conditional_edges(
        "execute_attack",
        route_after_execution,
        {
            "collect_trajectory": "collect_trajectory",
            "retry_or_stop": "retry_or_stop",
            "finalize_report": "finalize_report",
        },
    )

    builder.add_edge("collect_trajectory", "evaluate_deterministically")
    builder.add_edge("evaluate_deterministically", "evaluate_semantically")
    builder.add_edge("evaluate_semantically", "classify_finding")
    builder.add_edge("classify_finding", "generate_remediation")
    builder.add_edge("generate_remediation", "minimize_reproduction")
    builder.add_edge("minimize_reproduction", "finalize_report")
    builder.add_edge("retry_or_stop", "finalize_report")
    builder.add_edge("finalize_report", END)

    return builder.compile(checkpointer=checkpointer)


async def run_with_langgraph(state: ScanState, checkpointer: Any | None = None) -> ScanState:
    """Execute a scan through LangGraph, returning the final state.

    `recursion_limit` is raised above the default 25 because this graph has fourteen nodes and
    the default is a guard against cycles, not a statement about depth. A pipeline that halts
    two nodes from the end with `GraphRecursionError` would look exactly like a target problem.
    """
    graph = build_graph(checkpointer)
    result = await graph.ainvoke({"scan": state}, {"recursion_limit": 64})
    return result["scan"]
