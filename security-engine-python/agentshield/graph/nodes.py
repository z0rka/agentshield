"""Graph nodes.

Each node is an `async def` taking and returning `ScanState`. Keeping them plain functions - 
rather than methods on a LangGraph-aware class - means the pipeline can be driven by LangGraph
in production and by a two-hundred-line sequential executor in tests, with identical
behaviour. The orchestrator is a detail; the nodes are the system.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from datetime import UTC, datetime

from agentshield import DATASET_VERSION, EVALUATOR_SET_VERSION, PROMPT_VERSION
from agentshield.adapters.base import TargetError
from agentshield.adapters.registry import build_adapter, target_config_hash
from agentshield.attacks.catalog import load_catalog
from agentshield.attacks.selection import build_threat_model, select_categories, select_scenarios
from agentshield.evaluators.base import EvaluationContext
from agentshield.evaluators.llm_judge import AnthropicJudgeClient, configured_judge_model
from agentshield.evaluators.registry import (
    deterministic_evaluators,
    run_evaluators,
    semantic_evaluators,
)
from agentshield.evaluators.resources import check_budgets
from agentshield.evaluators.sink import judge_sink
from agentshield.findings.classifier import build_findings, replay_command
from agentshield.findings.fingerprint import fingerprint
from agentshield.findings.remediation import propose
from agentshield.graph.state import ScanState, ScenarioExecution
from agentshield.minimization import ReproductionMinimizer
from agentshield.models.common import RunStatus, Severity
from agentshield.models.finding import ScanSummary
from agentshield.models.scenario import (
    AttackPayload,
    AttackScenario,
    RunContext,
    SessionContext,
    TargetResponse,
)
from agentshield.policies.loader import canaries_from
from agentshield.telemetry import set_attributes, span

# Routing signals consumed by the conditional edge after execute_attack.
OUTCOME_SUCCESS = "success"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_TARGET_ERROR = "target_error"
OUTCOME_BUDGET_EXCEEDED = "budget_exceeded"
OUTCOME_CANCELLED = "cancelled"


async def load_target(state: ScanState) -> ScanState:
    """Construct the adapter and pin the reproducibility context.

    A pre-set adapter is honoured, which is how tests drive the real pipeline against an
    in-process ASGI app and how a worker reuses a pooled connection across scans.
    """
    if state.adapter is None:
        state.adapter = build_adapter(state.target_config)
    state.run_context = RunContext(
        scan_id=state.scan_id,
        dataset_version=DATASET_VERSION,
        evaluator_set_version=EVALUATOR_SET_VERSION,
        prompt_version=PROMPT_VERSION,
        policy_hash=state.policy.content_hash,
        target_config_hash=target_config_hash(state.target_config),
        scenario_timeout_seconds=state.scenario_timeout_seconds,
        # Recorded whenever judges are enabled, even if every one of them ends up skipping.
        # Two scans judged by different models are not comparable, and a result that does not
        # name its judge cannot be defended later.
        judge_model=configured_judge_model() if state.run_semantic_evaluators else None,
    )
    return state


async def discover_capabilities(state: ScanState) -> ScanState:
    """Ask the target what it can do.

    A target that cannot be interrogated is not a failed scan - it is a scan with narrower
    coverage, and the report says so.
    """
    assert state.adapter is not None
    try:
        state.capabilities = await state.adapter.discover_capabilities()
        if state.run_context and state.capabilities.target_version:
            state.run_context.target_version = state.capabilities.target_version
    except (TargetError, NotImplementedError) as exc:
        state.note_error(f"capability discovery failed: {exc}")
        from agentshield.adapters.base import TargetCapabilities, ToolDescriptor

        state.capabilities = TargetCapabilities(
            tools=[ToolDescriptor(name=name) for name in state.policy.tools],
            channels=[],
            supports_trajectory=False,
        )
    return state


async def build_target_threat_model(state: ScanState) -> ScanState:
    """Intersect what the target exposes with what the policy declares."""
    assert state.capabilities is not None
    state.threat_model = build_threat_model(
        state.capabilities,
        state.policy,
        adapter_type=getattr(state.adapter, "adapter_type", ""),
    )
    return state


async def select_attack_suite(state: ScanState) -> ScanState:
    """Pick the suites this target can meaningfully be tested against."""
    assert state.threat_model is not None
    if state.requested_categories is None:
        state.requested_categories = select_categories(state.threat_model)
    return state


async def generate_attack(state: ScanState) -> ScanState:
    """Load the corpus and instantiate the mutated scenarios for this run."""
    assert state.threat_model is not None
    state.catalog = load_catalog()
    selection = select_scenarios(
        state.catalog,
        state.threat_model,
        categories=state.requested_categories,
        max_scenarios=state.max_scenarios,
        variants_per_template=state.variants_per_template,
        base_seed=state.base_seed,
    )
    state.scenarios = selection.scenarios
    state.skipped = selection.skipped
    if state.run_context:
        state.run_context.dataset_version = state.catalog.version or DATASET_VERSION
    return state


async def execute_attack(state: ScanState) -> ScanState:
    """Run every selected scenario against the target, with bounded concurrency.

    Isolation between scenarios is the point of the per-scenario session: a poisoned document
    planted for one scenario must not still be in the corpus for the next, or a later pass
    would be indistinguishable from contamination.
    """
    assert state.adapter is not None
    if not state.scenarios:
        state.outcome = OUTCOME_SUCCESS
        return state

    semaphore = asyncio.Semaphore(max(1, state.concurrency))

    async def run_one(scenario: AttackScenario) -> ScenarioExecution:
        async with semaphore:
            return await _execute_scenario(state, scenario)

    state.executions = list(
        await asyncio.gather(*(run_one(scenario) for scenario in state.scenarios))
    )
    state.outcome = _aggregate_outcome(state)
    return state


async def _execute_scenario(state: ScanState, scenario: AttackScenario) -> ScenarioExecution:
    with span(
        "attack",
        **{
            "scan.id": state.scan_id,
            "scenario.id": scenario.id,
            "attack.category": str(scenario.category),
            "attack.seed": scenario.seed,
        },
    ) as attack_span:
        execution = await _run_scenario(state, scenario)
        set_attributes(
            attack_span,
            **{
                "attack.status": str(execution.status),
                "retry.count": execution.attempts - 1,
                "target.session.id": execution.session_id or "",
            },
        )
        return execution


class ScanCancelled(Exception):
    """The scan was cancelled while this scenario's request was still in flight."""


async def _send_input(
    state: ScanState, session_id: str, payload: AttackPayload
) -> TargetResponse:
    """Send one payload, giving up the moment the scan is cancelled or the budget expires.

    `asyncio.wait_for` alone handles only the second. Cancellation used to be checked between
    scenarios, so a cancel arriving one second into a sixty-second call was honoured a minute
    later - times however many scenarios were in flight. Racing the call against the token ends
    the request, never waiting for it to notice.

    The in-flight task is always cancelled on the way out. Leaving it running would keep
    sending traffic at a target the operator has just told us to stop scanning, which is the
    one thing a cancel has to guarantee.
    """
    call = asyncio.create_task(state.adapter.send_input(session_id, payload))  # type: ignore[union-attr]
    watch = asyncio.create_task(state.cancellation.wait())
    try:
        done, _ = await asyncio.wait(
            {call, watch},
            timeout=state.scenario_timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if call in done:
            return call.result()
        if watch in done:
            raise ScanCancelled
        raise TimeoutError
    finally:
        for task in (call, watch):
            if not task.done():
                task.cancel()
        # Awaited so the cancellation actually lands before the session is reset; a task left
        # mid-flight can still be writing to a connection the caller is about to close.
        with suppress(asyncio.CancelledError, Exception):
            await call


async def _run_scenario(state: ScanState, scenario: AttackScenario) -> ScenarioExecution:
    assert state.adapter is not None
    execution = ScenarioExecution(scenario=scenario)

    if state.cancellation.cancelled:
        execution.status = RunStatus.CANCELLED
        return execution

    context = SessionContext(
        scan_id=state.scan_id,
        scenario_id=scenario.id,
        tenant_id=state.target_config.get("tenant_id"),
        metadata=scenario.payload.metadata,
    )

    for attempt in range(1, state.max_attempts + 1):
        execution.attempts = attempt
        started = time.perf_counter()
        session_id: str | None = None
        try:
            session_id = await state.adapter.start_session(context)
            execution.session_id = session_id
            response = await _send_input(state, session_id, scenario.payload)
            trajectory = await state.adapter.collect(session_id, response)
            trajectory.tenant_id = trajectory.tenant_id or context.tenant_id
            if not trajectory.duration_seconds:
                trajectory.duration_seconds = time.perf_counter() - started

            execution.trajectory = trajectory
            execution.status = (
                RunStatus.BUDGET_EXCEEDED
                if check_budgets(trajectory, state.policy.budgets)
                else RunStatus.SUCCESS
            )
            break

        except ScanCancelled:
            # Not an error and never retried: the operator asked for this. Recorded as its own
            # status so a cancelled scenario is never mistaken for one that passed.
            execution.status = RunStatus.CANCELLED
            execution.error = "cancelled while the request was in flight"
            break

        except TimeoutError:
            # A hung agent is itself a finding (no cancellation, no time budget), so the
            # timeout is recorded over retried.
            execution.status = RunStatus.TIMEOUT
            execution.error = f"scenario exceeded {state.scenario_timeout_seconds:g}s"
            break

        except TargetError as exc:
            execution.error = str(exc)
            if exc.retryable and attempt < state.max_attempts:
                await asyncio.sleep(min(2**attempt * 0.25, 4.0))
                continue
            execution.status = RunStatus.TARGET_ERROR
            break

        except Exception as exc:  # noqa: BLE001 - one bad scenario must not sink the scan
            execution.status = RunStatus.TARGET_ERROR
            execution.error = f"{type(exc).__name__}: {exc}"
            break

        finally:
            execution.duration_seconds = time.perf_counter() - started
            if session_id:
                with suppress(Exception):  # cleanup failure is not a finding
                    await state.adapter.reset(session_id)

    return execution


def _aggregate_outcome(state: ScanState) -> str:
    if state.cancellation.cancelled:
        return OUTCOME_CANCELLED

    statuses = [e.status for e in state.executions]
    if any(s is RunStatus.SUCCESS for s in statuses):
        return OUTCOME_SUCCESS
    if any(s is RunStatus.BUDGET_EXCEEDED for s in statuses):
        return OUTCOME_BUDGET_EXCEEDED
    if any(s is RunStatus.TIMEOUT for s in statuses):
        return OUTCOME_TIMEOUT
    if statuses and all(s is RunStatus.TARGET_ERROR for s in statuses):
        # Every scenario failed to reach the target: reporting "no findings" here would be a
        # false all-clear, which is the single most dangerous output a security tool can give.
        return OUTCOME_TARGET_ERROR
    return OUTCOME_SUCCESS


async def collect_trajectory(state: ScanState) -> ScanState:
    """Annotate trajectories with what the evaluators will need.

    The adapter reports what the target did; this node adds what AgentShield knows - the
    tenant it authenticated as, the canaries it seeded.
    """
    tenant = state.target_config.get("tenant_id")
    for execution in state.executions:
        if execution.trajectory is None:
            continue
        if tenant and not execution.trajectory.tenant_id:
            execution.trajectory.tenant_id = tenant
    return state


async def evaluate_deterministically(state: ScanState) -> ScanState:
    """Run the mandatory evaluator set over every usable trajectory."""
    evaluators = deterministic_evaluators()

    for execution in state.executions:
        if not execution.evaluable or execution.trajectory is None:
            continue
        context = _evaluation_context(state, execution.scenario)
        results = run_evaluators(evaluators, execution.trajectory, state.policy, context)
        state.results.extend((execution.scenario, result) for result in results)

    _record_execution_failures(state)
    return state


def _evaluation_context(state: ScanState, scenario: AttackScenario) -> EvaluationContext:
    """What the evaluators need beyond the trajectory itself.

    Shared with reproduction minimisation: a minimiser judging candidates under a different
    context than the original scan would be answering a different question, and the payload it
    converged on would be minimal for nothing.
    """
    return EvaluationContext(
        scenario=scenario,
        authenticated_tenant=state.target_config.get("tenant_id"),
        canaries=[*canaries_from(state.policy), *scenario.expected.forbidden_values],
        declared_tools=list(state.capabilities.tool_names) if state.capabilities else [],
        system_prompt=state.target_config.get("system_prompt"),
        tool_descriptions={
            tool.name: tool.description for tool in state.capabilities.tools
        } if state.capabilities else {},
        tool_scopes={
            tool.name: list(tool.scopes) for tool in state.capabilities.tools
        } if state.capabilities else {},
        harness_initiated_calls=getattr(state.adapter, "adapter_type", "") == "mcp",
    )


def _record_execution_failures(state: ScanState) -> None:
    """Turn timeouts and unreachable targets into visible outcomes.

    A scenario that never ran must not look like a scenario that passed.
    """
    from agentshield.models.common import AttackCategory
    from agentshield.models.finding import EvaluationResult, Evidence

    for execution in state.executions:
        if execution.status is RunStatus.TIMEOUT:
            state.results.append(
                (
                    execution.scenario,
                    EvaluationResult(
                        evaluator="BudgetEvaluator",
                        violated=True,
                        category=AttackCategory.UNBOUNDED_CONSUMPTION,
                        severity=Severity.MEDIUM,
                        title="Scenario exceeded the wall-clock budget",
                        description=(
                            f"`{execution.scenario.id}` did not finish within "
                            f"{state.scenario_timeout_seconds:g}s and was abandoned. The agent "
                            "has no enforced time budget and no cancellation path."
                        ),
                        evidence=Evidence(
                            summary=execution.error or "timeout",
                            policy_path="budgets.max_duration_seconds",
                        ),
                    ),
                )
            )
        elif execution.status is RunStatus.TARGET_ERROR:
            state.note_error(
                f"{execution.scenario.id}: target error after {execution.attempts} attempt(s)"
                f" - {execution.error}"
            )


async def evaluate_semantically(state: ScanState) -> ScanState:
    """Optional LLM judges. Skipped entirely unless explicitly enabled."""
    if not state.run_semantic_evaluators:
        return state

    # One client for the whole scan, so token spend accumulates in one place and not once per
    # evaluator. Constructing it here also means the Langfuse sink is opened only when judges
    # actually run, never on a deterministic-only scan.
    client = state.judge_client or AnthropicJudgeClient(
        usage=state.judge_usage, sink=judge_sink(state.scan_id)
    )
    state.judge_usage = getattr(client, "usage", state.judge_usage)

    evaluators = semantic_evaluators(client)
    for execution in state.executions:
        if not execution.evaluable or execution.trajectory is None:
            continue
        context = EvaluationContext(
            scenario=execution.scenario,
            authenticated_tenant=state.target_config.get("tenant_id"),
            declared_tools=list(state.capabilities.tool_names) if state.capabilities else [],
        )
        results = run_evaluators(evaluators, execution.trajectory, state.policy, context)
        state.results.extend((execution.scenario, result) for result in results)
    return state


async def classify_finding(state: ScanState) -> ScanState:
    """Deduplicate results into findings and assign final severities."""
    state.findings = build_findings(
        state.results,
        scan_id=state.scan_id,
        dataset_version=state.run_context.dataset_version if state.run_context else DATASET_VERSION,
        policy_hash=state.policy.content_hash,
        target=str(state.target_config.get("base_url", "")),
        policy_source=state.policy_source,
    )
    return state


async def generate_remediation(state: ScanState) -> ScanState:
    """Guarantee every finding carries an actionable fix."""
    for finding in state.findings:
        if finding.remediation is None:
            matching = next(
                (r for _, r in state.results if r.violated and r.title == finding.title),
                None,
            )
            if matching is not None:
                finding.remediation = propose(matching)
    return state


async def minimize_reproduction(state: ScanState) -> ScanState:
    """Reduce each reproduction to the shortest payload that still triggers the same finding.

    Delta debugging against the live target, bounded by a scan-wide probe budget and matched on
    the finding's fingerprint so a reduction cannot drift onto a different defect. The full
    reasoning is in `agentshield.minimization`.

    The replay command keeps pointing at the original scenario and seed. That is deliberate:
    the command is the regression test, and it has to stay runnable from the dataset alone,
    while the reduced payload is the diagnostic that tells a reader which sentence mattered.
    """
    for finding in state.findings:
        finding.reproduction.command = replay_command(
            finding.reproduction.scenario_id,
            finding.reproduction.seed,
            finding.reproduction.policy_hash,
            target=str(state.target_config.get("base_url", "")),
            policy_source=state.policy_source,
        )

    if not state.minimize_reproductions or state.adapter is None:
        for finding in state.findings:
            finding.reproduction.note = "minimisation disabled for this scan"
        return state

    minimizer = ReproductionMinimizer(
        probe=lambda scenario: _reproduced_defects(state, scenario),
        budget=state.minimization_budget,
    )
    with span("minimize", **{"scan.id": state.scan_id}) as minimize_span:
        await minimizer.minimize_all(state.findings, [e.scenario for e in state.executions])
        set_attributes(
            minimize_span,
            **{
                "minimization.probes": minimizer.probes_spent,
                "minimization.findings": sum(1 for f in state.findings if f.reproduction.minimized),
            },
        )
    return state


async def _reproduced_defects(state: ScanState, scenario: AttackScenario) -> set[str]:
    """Run one candidate payload and report the fingerprints of the defects it reproduced.

    Deterministic evaluators only. An oracle backed by an LLM judge would answer the same
    question differently on consecutive calls, and delta debugging on a noisy oracle converges
    to whichever answer the noise favoured.
    """
    execution = await _run_scenario(state, scenario)
    if not execution.evaluable or execution.trajectory is None:
        return set()
    results = run_evaluators(
        deterministic_evaluators(),
        execution.trajectory,
        state.policy,
        _evaluation_context(state, scenario),
    )
    return {fingerprint(result) for result in results if result.violated}


async def finalize_report(state: ScanState) -> ScanState:
    """Assemble the scan summary."""
    executions = state.executions
    state.summary = ScanSummary(
        scan_id=state.scan_id,
        target_name=state.policy.target.name,
        policy_hash=state.policy.content_hash,
        dataset_version=state.run_context.dataset_version if state.run_context else DATASET_VERSION,
        scenarios_selected=len(state.scenarios),
        scenarios_executed=len([e for e in executions if e.evaluable]),
        scenarios_skipped=len(state.skipped),
        scenarios_errored=len([e for e in executions if e.status is RunStatus.TARGET_ERROR]),
        findings=state.findings,
        started_at=state.started_at,
        completed_at=datetime.now(UTC),
        # Target tokens and judge tokens are both real spend on this scan and are summed
        # together. They are separable in `judge_usage` when the question is which half cost
        # what; a report that omitted one of them would understate the bill.
        total_input_tokens=(
            sum(e.trajectory.input_tokens for e in executions if e.trajectory)
            + state.judge_usage.input_tokens
        ),
        total_output_tokens=(
            sum(e.trajectory.output_tokens for e in executions if e.trajectory)
            + state.judge_usage.output_tokens
        ),
        estimated_cost_usd=(
            sum(e.trajectory.estimated_cost_usd for e in executions if e.trajectory)
            + state.judge_usage.estimated_cost_usd
        ),
    )
    if state.adapter is not None:
        await state.adapter.aclose()
    return state


async def retry_or_stop(state: ScanState) -> ScanState:
    """Terminal handling for a target that could not be reached at all.

    Per-scenario retries already happened inside `execute_attack`. Reaching here means the
    target is down, so the scan ends with an explicit error instead of an empty pass.
    """
    state.note_error(
        "every scenario failed to reach the target; scan aborted without security coverage"
    )
    return state
