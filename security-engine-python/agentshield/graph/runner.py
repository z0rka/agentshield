"""The scan pipeline's entry point, and its sequential reference executor.

`run_scan` is what every caller uses - the CLI, the engine API, the Kafka worker. It picks the
orchestrator and then owns the scan-level span, so the choice is made in one place and the
telemetry does not depend on which one won.

**LangGraph is the default**, and this file used to make that a lie. The docstring said the
graph drove the pipeline in production while `run_scan` ran the `for` loop below and nothing
imported `run_with_langgraph` at all. The extra was not even installed in CI. A claim about
architecture that no code path honours is worse than the simpler architecture stated plainly,
so the dispatch is now explicit and `AGENTSHIELD_ORCHESTRATOR` records which one ran.

The sequential executor stays, and not as a fallback of convenience: it is the readable
statement of the workflow and its conditional edges, it runs where the extra is absent, and
having two executors over one set of nodes is what proves the nodes depend on neither.

Tracing lives on the executor, never inside the nodes. The nodes stay pure functions of
`ScanState` with no telemetry imports, which is what lets them be unit-tested and driven by
either runtime.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable

from agentshield.graph import nodes
from agentshield.graph.state import ScanState
from agentshield.telemetry import set_attributes, span

log = logging.getLogger(__name__)

Node = Callable[[ScanState], Awaitable[ScanState]]

#: How the orchestrator is chosen. `auto` prefers LangGraph and falls back when the extra is
#: absent; `graph` and `sequential` pin it, which is what a reproduction needs.
ORCHESTRATOR_ENV = "AGENTSHIELD_ORCHESTRATOR"

#: The linear prefix: everything before execution is unconditional.
SETUP_NODES: tuple[Node, ...] = (
    nodes.load_target,
    nodes.discover_capabilities,
    nodes.build_target_threat_model,
    nodes.select_attack_suite,
    nodes.generate_attack,
)

#: The evaluation tail, run whenever there is anything worth judging.
EVALUATION_NODES: tuple[Node, ...] = (
    nodes.collect_trajectory,
    nodes.evaluate_deterministically,
    nodes.evaluate_semantically,
    nodes.classify_finding,
    nodes.generate_remediation,
    nodes.minimize_reproduction,
)


def select_orchestrator() -> str:
    """Which runtime drives this scan: `"graph"` or `"sequential"`.

    Resolved once per scan and recorded on the span, because "which orchestrator ran" is the
    first question about any behavioural difference between two runs and guessing it from the
    environment afterwards is not an answer.
    """
    requested = os.getenv(ORCHESTRATOR_ENV, "auto").strip().lower()
    if requested == "sequential":
        return "sequential"

    try:
        import langgraph  # noqa: F401
    except ImportError:
        if requested == "graph":
            raise RuntimeError(
                f"{ORCHESTRATOR_ENV}=graph but LangGraph is not installed; "
                "install agentshield-engine[graph]"
            ) from None
        return "sequential"
    return "graph"


async def run_scan(state: ScanState) -> ScanState:
    """Execute the full pipeline, honouring the conditional edges after `execute_attack`.

    ```
    execute_attack
      |-- success          -> collect_trajectory -> ... -> finalize_report
      |-- timeout          -> classify_finding   -> ... -> finalize_report
      |-- target_error     -> retry_or_stop      -> finalize_report
      |-- budget_exceeded  -> finalize_report
      \\-- cancelled        -> finalize_report
    ```

    The same edges exist twice, once here and once as LangGraph edges in `graph.py`, and
    `tests/test_orchestrators.py` asserts both runtimes reach the same state. Two encodings of
    one workflow is a cost; two that have silently diverged is a bug, so it is asserted.
    """
    orchestrator = select_orchestrator()
    with span(
        "scan",
        **{
            "scan.id": state.scan_id,
            "target.name": state.policy.target.name,
            "policy.version": state.policy.content_hash,
            "orchestrator": orchestrator,
        },
    ) as scan_span:
        if orchestrator == "graph":
            from agentshield.graph.graph import run_with_langgraph

            state = await run_with_langgraph(state)
        else:
            state = await _drive(state)
        summary = state.summary
        if summary is not None:
            set_attributes(
                scan_span,
                **{
                    "scan.outcome": state.outcome,
                    "scan.scenarios": summary.scenarios_executed,
                    "scan.findings": len(summary.findings),
                    "scan.critical": summary.critical,
                    "token.input": summary.total_input_tokens,
                    "token.output": summary.total_output_tokens,
                    "estimated.cost": summary.estimated_cost_usd,
                },
            )
        return state


async def _drive(state: ScanState) -> ScanState:
    for node in SETUP_NODES:
        state = await _node(node, state)
        if state.cancellation.cancelled:
            state.outcome = nodes.OUTCOME_CANCELLED
            return await _node(nodes.finalize_report, state)

    state = await _node(nodes.execute_attack, state)

    if state.outcome == nodes.OUTCOME_TARGET_ERROR:
        state = await _node(nodes.retry_or_stop, state)
        return await _node(nodes.finalize_report, state)

    if state.outcome == nodes.OUTCOME_CANCELLED:
        # Scenarios that did run are still evaluated: partial coverage beats none, and a
        # cancelled scan that already found something critical must still report it.
        state = await _evaluate(state)
        return await _node(nodes.finalize_report, state)

    state = await _evaluate(state)
    return await _node(nodes.finalize_report, state)


async def _evaluate(state: ScanState) -> ScanState:
    for node in EVALUATION_NODES:
        state = await _node(node, state)
    return state


async def _node(node: Node, state: ScanState) -> ScanState:
    with span(f"node.{node.__name__}", **{"scan.id": state.scan_id}):
        return await node(state)
