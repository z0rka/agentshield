"""Two runtimes, one workflow, and the assertion that keeps them one workflow.

The conditional edges after `execute_attack` are written twice: as ordinary Python in
`runner.py` and as LangGraph edges in `graph.py`. That is a real cost, and it is worth paying
only because the nodes stay pure - two executors over one set of nodes is what proves the nodes
depend on neither.

The cost comes due when the two encodings drift. Nothing would catch it: both would run, both
would produce a summary, and the difference would show up as a scan that behaves one way on a
laptop and another in the worker. So the equivalence is asserted, never assumed.

There is a second reason this file exists. `run_scan` claimed for a long time that LangGraph
drove the pipeline in production while every caller ran the `for` loop and the extra was not
installed in CI. The claim is now true, and these tests are what make it checkable.
"""

from __future__ import annotations

import httpx
import pytest

from agentshield.adapters.rest import AgentShieldProtocolAdapter
from agentshield.graph import runner
from agentshield.graph.state import ScanState
from agentshield.models.common import AttackCategory

langgraph = pytest.importorskip("langgraph", reason="the graph extra is not installed")


def _state(policy) -> ScanState:
    from demo_targets.vulnerable_support_agent.app import create_app

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(secure=False)),
        base_url="http://demo-target",
    )
    state = ScanState(
        scan_id="scan-orchestrator",
        policy=policy,
        target_config={"base_url": "http://demo-target", "tenant_id": "tenant-a"},
        requested_categories={AttackCategory.INDIRECT_PROMPT_INJECTION},
        # Small and fixed: this compares two executors, never the corpus.
        max_scenarios=6,
        variants_per_template=1,
        base_seed=0,
        minimize_reproductions=False,
    )
    state.adapter = AgentShieldProtocolAdapter(base_url="http://demo-target", client=client)
    return state


async def _run(policy, orchestrator: str) -> ScanState:
    state = _state(policy)
    try:
        if orchestrator == "graph":
            from agentshield.graph.graph import run_with_langgraph

            return await run_with_langgraph(state)
        return await runner._drive(state)
    finally:
        if state.adapter is not None:
            await state.adapter.aclose()


# ---------------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------------


def test_langgraph_is_the_default(monkeypatch):
    """The headline claim, as a test.

    It was false for three stages: the docstring said graph, the code said `for` loop, and
    CI installed every extra except this one.
    """
    monkeypatch.delenv(runner.ORCHESTRATOR_ENV, raising=False)

    assert runner.select_orchestrator() == "graph"


def test_the_orchestrator_can_be_pinned(monkeypatch):
    """A reproduction that cannot pin its runtime is not a reproduction."""
    monkeypatch.setenv(runner.ORCHESTRATOR_ENV, "sequential")

    assert runner.select_orchestrator() == "sequential"


def test_asking_for_a_runtime_that_is_absent_is_an_error(monkeypatch):
    """Silently falling back would make `AGENTSHIELD_ORCHESTRATOR=graph` a suggestion.

    The whole reason to pin one is that something behaved differently under the other.
    """
    monkeypatch.setenv(runner.ORCHESTRATOR_ENV, "graph")
    monkeypatch.setitem(__import__("sys").modules, "langgraph", None)

    with pytest.raises(RuntimeError, match="not installed"):
        runner.select_orchestrator()


def test_a_missing_extra_falls_back_without_complaint(monkeypatch):
    """`auto` is the default, and the CLI on a laptop has no reason to carry a graph runtime."""
    monkeypatch.delenv(runner.ORCHESTRATOR_ENV, raising=False)
    monkeypatch.setitem(__import__("sys").modules, "langgraph", None)

    assert runner.select_orchestrator() == "sequential"


# ---------------------------------------------------------------------------------
# equivalence
# ---------------------------------------------------------------------------------


async def test_both_runtimes_reach_the_same_verdict(policy):
    """The same scan, twice, judged the same.

    Findings are compared by fingerprint because that is what the regression baseline and the
    CI gate compare. Two executors that agree on counts but disagree on which defect they
    found would still break every downstream comparison.
    """
    sequential = await _run(policy, "sequential")
    graph = await _run(policy, "graph")

    assert sequential.summary is not None
    assert graph.summary is not None

    assert graph.outcome == sequential.outcome
    assert graph.summary.scenarios_executed == sequential.summary.scenarios_executed
    assert {f.fingerprint for f in graph.summary.findings} == {
        f.fingerprint for f in sequential.summary.findings
    }


async def test_both_runtimes_run_every_node(policy):
    """A node the graph forgot to wire would show up as a missing part of the result.

    Remediation and reproduction come from the tail of the pipeline, so their presence is the
    cheapest proof that the tail ran under both.
    """
    sequential = await _run(policy, "sequential")
    graph = await _run(policy, "graph")

    for state in (sequential, graph):
        assert state.summary is not None
        assert state.summary.findings, "no findings, so this proves nothing about the tail"
        assert all(f.remediation for f in state.summary.findings)
        assert all(f.reproduction for f in state.summary.findings)


async def test_the_graph_carries_the_cancellation_short_circuit(policy):
    """Cancellation is a property of the workflow, so both encodings owe it.

    A graph that ran the whole corpus after the token was set would be a different workflow
    wearing the same node names.
    """
    state = _state(policy)
    state.cancellation.cancel()
    try:
        from agentshield.graph.graph import run_with_langgraph

        result = await run_with_langgraph(state)
    finally:
        if state.adapter is not None:
            await state.adapter.aclose()

    assert result.summary is not None
    assert result.summary.scenarios_executed == 0
