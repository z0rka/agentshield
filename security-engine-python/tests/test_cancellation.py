"""Cancelling a scan that is already talking to the target.

The property under test is timing, so the assertions are about elapsed time. A scenario that
would take ten seconds must end within a fraction of that once cancelled, and a test that only
checked the final status would pass just as happily on the old polling behaviour - which
honoured a cancel after the request finished, up to a full scenario timeout later.

Every wait here is short and driven by a controllable target, so nothing depends on machine
speed beyond an order of magnitude.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from agentshield.adapters.base import BaseTargetAdapter, TargetCapabilities, ToolDescriptor
from agentshield.graph.nodes import ScanCancelled, _send_input
from agentshield.graph.state import CancellationToken, ScanState
from agentshield.models.common import RunStatus
from agentshield.models.policy import SecurityPolicy
from agentshield.models.scenario import AttackPayload, SessionContext, TargetResponse
from agentshield.models.trajectory import Trajectory, TrajectoryStep

#: Long enough that honouring the cancel only after the call returns would be unmistakable.
HANG_SECONDS = 10.0


class HangingAdapter(BaseTargetAdapter):
    """A target that accepts a request and then never answers."""

    adapter_type = "hanging"

    def __init__(self, hang: float = HANG_SECONDS) -> None:
        self.hang = hang
        self.started = asyncio.Event()
        self.completed = 0
        self.cancelled_mid_flight = 0

    async def discover_capabilities(self) -> TargetCapabilities:
        return TargetCapabilities(tools=[ToolDescriptor(name="noop")], supports_trajectory=True)

    async def start_session(self, context: SessionContext) -> str:
        return "session-1"

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        self.started.set()
        try:
            await asyncio.sleep(self.hang)
        except asyncio.CancelledError:
            self.cancelled_mid_flight += 1
            raise
        self.completed += 1
        return TargetResponse(session_id=session_id, output="never reached")

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        return []

    async def collect(self, session_id: str, response: TargetResponse) -> Trajectory:
        return Trajectory(session_id=session_id)


def _state(adapter: BaseTargetAdapter, policy: SecurityPolicy, **overrides) -> ScanState:
    state = ScanState(
        scan_id="cancel-test",
        policy=policy,
        target_config={"base_url": "http://demo-target"},
        scenario_timeout_seconds=overrides.pop("timeout", 30.0),
        **overrides,
    )
    state.adapter = adapter
    return state


# ---------------------------------------------------------------------------------
# the token
# ---------------------------------------------------------------------------------


async def test_a_waiter_wakes_when_cancellation_arrives():
    token = CancellationToken()
    waiter = asyncio.create_task(token.wait())
    await asyncio.sleep(0)

    token.cancel()

    await asyncio.wait_for(waiter, timeout=2)
    assert token.cancelled


async def test_cancelling_before_anyone_waits_still_wakes_the_next_waiter():
    """The ordering that a naive asyncio.Event gets wrong: the set happens first."""
    token = CancellationToken()
    token.cancel()

    await asyncio.wait_for(token.wait(), timeout=2)


async def test_cancellation_from_another_thread_reaches_the_loop():
    """The API process and the scan loop are not guaranteed to be the same thread.

    Setting an asyncio.Event from outside its loop loses the wakeup silently, so this is the
    case that decides whether cancellation works in the deployment that matters.
    """
    import threading

    token = CancellationToken()
    waiter = asyncio.create_task(token.wait())
    await asyncio.sleep(0)

    threading.Thread(target=token.cancel).start()

    await asyncio.wait_for(waiter, timeout=2)


# ---------------------------------------------------------------------------------
# the in-flight request
# ---------------------------------------------------------------------------------


async def test_an_in_flight_request_is_abandoned_immediately(policy: SecurityPolicy):
    """The whole point. Polling honoured this a scenario-timeout later."""
    adapter = HangingAdapter()
    state = _state(adapter, policy)

    async def cancel_once_started() -> None:
        await adapter.started.wait()
        state.cancellation.cancel()

    started = time.perf_counter()
    asyncio.create_task(cancel_once_started())
    with pytest.raises(ScanCancelled):
        await _send_input(state, "session-1", AttackPayload(prompt="hi"))
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0, f"took {elapsed:.2f}s; the request was not actually interrupted"
    assert adapter.completed == 0


async def test_the_target_call_is_really_cancelled_not_just_left_running(policy: SecurityPolicy):
    """Abandoning the await while the request continues would keep sending traffic at a
    target the operator has just told us to stop scanning."""
    adapter = HangingAdapter()
    state = _state(adapter, policy)

    asyncio.create_task(_cancel_when_started(adapter, state))
    with pytest.raises(ScanCancelled):
        await _send_input(state, "session-1", AttackPayload(prompt="hi"))

    assert adapter.cancelled_mid_flight == 1


async def test_the_timeout_path_still_works(policy: SecurityPolicy):
    """Cancellation is a second exit, not a replacement for the budget."""
    adapter = HangingAdapter(hang=5.0)
    state = _state(adapter, policy, timeout=0.2)

    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        await _send_input(state, "session-1", AttackPayload(prompt="hi"))

    assert time.perf_counter() - started < 2.0
    assert adapter.cancelled_mid_flight == 1, "a timed-out request must also be stopped"


async def test_an_uncancelled_call_returns_normally(policy: SecurityPolicy):
    adapter = HangingAdapter(hang=0.0)
    state = _state(adapter, policy)

    response = await _send_input(state, "session-1", AttackPayload(prompt="hi"))

    assert response.output == "never reached"
    assert adapter.completed == 1


# ---------------------------------------------------------------------------------
# what the scan records
# ---------------------------------------------------------------------------------


async def test_a_cancelled_scenario_is_recorded_as_cancelled_not_passed(policy: SecurityPolicy):
    """A cancelled scenario tested nothing. Reporting it as anything else is a false all-clear."""
    from agentshield.graph.nodes import _run_scenario
    from agentshield.models.common import AttackCategory
    from agentshield.models.scenario import AttackScenario

    adapter = HangingAdapter()
    state = _state(adapter, policy)
    scenario = AttackScenario(
        id="sc-1",
        category=AttackCategory.DIRECT_PROMPT_INJECTION,
        name="hangs",
        payload=AttackPayload(prompt="hi"),
    )

    asyncio.create_task(_cancel_when_started(adapter, state))
    execution = await _run_scenario(state, scenario)

    assert execution.status is RunStatus.CANCELLED
    assert not execution.evaluable, "a cancelled scenario must not be judged"
    assert execution.attempts == 1, "cancellation is the operator's decision, never retried"


async def _cancel_when_started(adapter: HangingAdapter, state: ScanState) -> None:
    await adapter.started.wait()
    state.cancellation.cancel()
