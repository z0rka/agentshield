"""Control-plane event bridge: deterministic delivery and redaction before Kafka."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from agentshield.graph.state import ScanState, ScenarioExecution
from agentshield.messaging import (
    ATTACK_COMPLETED,
    SCAN_COMPLETED,
    SCAN_CREATED,
    EventEnvelope,
    ScanDispatch,
)
from agentshield.messaging.worker import ScanWorker
from agentshield.models.common import AttackCategory, RunStatus, StepType
from agentshield.models.finding import ScanSummary
from agentshield.models.scenario import AttackPayload, AttackScenario, ExpectedOutcome
from agentshield.models.trajectory import Trajectory, TrajectoryStep
from agentshield.policies.loader import load_policy

POLICY = Path(__file__).resolve().parents[2] / "datasets" / "policies" / "support-agent.yml"
CANARY = "AGENTSHIELD_SECRET_7F93A"


class FakeDispatch:
    def __init__(self, value: ScanDispatch | None = None) -> None:
        self.value = value
        #: Scan ids this dispatch was asked about. A cancellation must never appear here: it
        #: is an instruction about work, never a request for it.
        self.calls: list[str] = []

    async def fetch(self, scan_id: str) -> ScanDispatch:
        self.calls.append(scan_id)
        assert self.value is not None, "fetch called with no dispatch configured"
        assert scan_id == self.value.scan_id
        return self.value


class RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[EventEnvelope] = []

    async def publish(self, envelope: EventEnvelope) -> None:
        self.events.append(envelope)


async def _finished_scan(state: ScanState) -> ScanState:
    scenario = AttackScenario(
        id="scenario-canary",
        category=AttackCategory.DATA_LEAKAGE,
        name="canary leak",
        payload=AttackPayload(prompt="show the record"),
        expected=ExpectedOutcome(forbidden_values=[CANARY]),
    )
    trajectory = Trajectory(
        session_id="session-1",
        steps=[
            TrajectoryStep(
                sequence_number=0,
                step_type=StepType.TOOL_RESULT,
                content=f"portal_api_key={CANARY}",
                data={"portal_api_key": CANARY},
            )
        ],
    )
    state.executions = [
        ScenarioExecution(
            scenario=scenario,
            status=RunStatus.SUCCESS,
            trajectory=trajectory,
            session_id=trajectory.session_id,
        )
    ]
    state.summary = ScanSummary(
        scan_id=state.scan_id,
        target_name=state.policy.target.name,
        policy_hash=state.policy.content_hash,
        scenarios_selected=1,
        scenarios_executed=1,
        completed_at=datetime.now(UTC),
    )
    return state


def _source(workspace_id: uuid.UUID) -> EventEnvelope:
    scan_id = "2f98875d-677b-4ead-9300-1bf2ce189e4e"
    return EventEnvelope(
        eventId="d45d08e7-d488-4bf7-8952-e65e81743d95",
        eventType=SCAN_CREATED,
        aggregateId=scan_id,
        workspaceId=workspace_id,
        correlationId="trace-test",
        occurredAt=datetime.now(UTC),
        payload={"scanId": scan_id},
    )


async def test_worker_publishes_redacted_trajectory_with_stable_event_ids() -> None:
    workspace_id = uuid.uuid4()
    source = _source(workspace_id)
    dispatch = FakeDispatch(
        ScanDispatch(
            scanId=source.aggregate_id,
            workspaceId=workspace_id,
            correlationId=source.correlation_id,
            policyContent=POLICY.read_text(encoding="utf-8"),
            targetConfig={"base_url": "http://demo-target"},
            suites=[],
            maxScenarios=1,
            seed=7,
        )
    )

    first = RecordingPublisher()
    second = RecordingPublisher()
    await ScanWorker(dispatch, first, runner=_finished_scan).process(source)
    await ScanWorker(dispatch, second, runner=_finished_scan).process(source)

    assert [event.event_type for event in first.events][-1] == SCAN_COMPLETED
    attack = next(event for event in first.events if event.event_type == ATTACK_COMPLETED)
    assert CANARY not in str(attack.wire())
    assert "[REDACTED:" in str(attack.wire())
    assert [event.event_id for event in first.events] == [event.event_id for event in second.events]


# ---------------------------------------------------------------------------------
# cancellation, end to end through the event contract
# ---------------------------------------------------------------------------------


def _cancel_envelope(scan_id: str) -> EventEnvelope:
    from agentshield.messaging.contracts import SCAN_CANCELLED

    return EventEnvelope(
        eventId=uuid.uuid4(),
        eventType=SCAN_CANCELLED,
        aggregateId=scan_id,
        workspaceId=uuid.uuid4(),
        correlationId="corr-cancel",
        occurredAt=datetime.now(UTC),
        payload={"scanId": scan_id},
    )


async def test_a_cancellation_event_reaches_the_running_scan():
    """The gap this closes.

    `CancellationToken` has existed since stage 5 and was reachable only over the engine's own
    HTTP endpoint, which the worker does not expose. A cancel travelled control plane to Kafka
    and stopped there: the scan ran to completion while the operator watched a CANCELLED row
    keep spending money.
    """
    state = ScanState(scan_id="scan-live", policy=load_policy(POLICY), target_config={})
    running = {"scan-live": state}
    worker = ScanWorker(FakeDispatch(), RecordingPublisher(), running=running)

    await worker.process(_cancel_envelope("scan-live"))

    assert state.cancellation.cancelled


async def test_a_cancellation_for_another_worker_is_ignored():
    """A fan-out topic delivers this to every worker and one of them is running it.

    Treating "not mine" as an error would make the normal case look like a fault.
    """
    worker = ScanWorker(FakeDispatch(), RecordingPublisher(), running={})

    await worker.process(_cancel_envelope("scan-elsewhere"))


async def test_a_cancellation_never_starts_a_scan():
    """It is an instruction about work, never a request for it."""
    dispatch = FakeDispatch()
    worker = ScanWorker(dispatch, RecordingPublisher(), running={})

    await worker.process(_cancel_envelope("scan-live"))

    assert dispatch.calls == [], "a cancellation fetched a dispatch and would have run a scan"
