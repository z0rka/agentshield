"""Shared fixtures.

The end-to-end tests drive the real pipeline against the real demo target over an in-process
ASGI transport. No sockets, no ports, no sleeps - but every layer under test is the one that
runs in production, including the HTTP adapter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from agentshield.adapters.rest import AgentShieldProtocolAdapter
from agentshield.models.common import StepType
from agentshield.models.policy import SecurityPolicy
from agentshield.models.trajectory import Trajectory, TrajectoryStep
from agentshield.policies.loader import load_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "datasets" / "policies" / "support-agent.yml"

#: Credentials that would let a test reach a paid API. Stripped from every test, always.
BILLABLE_CREDENTIALS = (
    "ANTHROPIC_API_KEY",
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "OPENAI_API_KEY",
)


@pytest.fixture(autouse=True)
def _no_billable_credentials(monkeypatch):
    """No test may reach a paid API, whatever it happens to call.

    This exists because the suite once did. The CLI tests invoke `main()`, `main()` calls
    `load_dotenv()`, and `load_dotenv` writes `.env` into `os.environ` for the whole process -
    correct for a command that runs once and exits, and quietly catastrophic inside pytest.
    Every later test that built `semantic_evaluators()` then found live credentials and made
    real API calls. The suite went from twelve seconds to fourteen minutes and spent actual
    money, and the only reason anyone noticed is that one test asserts the judges are
    unavailable here.

    Autouse and unconditional. An opt-in guard protects the tests that remember to ask,
    which are never the ones that need it.
    """
    for name in BILLABLE_CREDENTIALS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def policy() -> SecurityPolicy:
    return load_policy(POLICY_PATH)


@pytest.fixture
def dataset_root() -> Path:
    return REPO_ROOT / "datasets"


def _adapter_for(secure: bool) -> AgentShieldProtocolAdapter:
    from demo_targets.vulnerable_support_agent.app import create_app

    app = create_app(secure=secure)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://demo-target"
    )
    return AgentShieldProtocolAdapter(base_url="http://demo-target", client=client)


@pytest.fixture
async def vulnerable_adapter() -> AsyncIterator[AgentShieldProtocolAdapter]:
    adapter = _adapter_for(secure=False)
    try:
        yield adapter
    finally:
        await adapter.aclose()


@pytest.fixture
async def secure_adapter() -> AsyncIterator[AgentShieldProtocolAdapter]:
    adapter = _adapter_for(secure=True)
    try:
        yield adapter
    finally:
        await adapter.aclose()


class TrajectoryBuilder:
    """Fluent builder for the hand-written trajectories the evaluator tests use.

    Evaluator tests must not depend on the demo target: a test that only fails when the demo
    agent changes is testing the demo agent.
    """

    def __init__(self, session_id: str = "sess-test") -> None:
        self.trajectory = Trajectory(session_id=session_id)

    def _add(self, step_type: StepType, **kwargs: object) -> TrajectoryBuilder:
        self.trajectory.add(
            TrajectoryStep(
                sequence_number=len(self.trajectory.steps),
                step_type=step_type,
                **kwargs,  # type: ignore[arg-type]
            )
        )
        return self

    def user(self, content: str) -> TrajectoryBuilder:
        return self._add(StepType.USER_INPUT, content=content, source="user")

    def retrieval(self, content: str, *, document_id: str = "DOC-1") -> TrajectoryBuilder:
        return self._add(
            StepType.RETRIEVAL,
            content=content,
            data={"document_id": document_id},
            source="knowledge_base",
        )

    def tool_call(self, name: str, **arguments: object) -> TrajectoryBuilder:
        return self._add(StepType.TOOL_CALL, tool_name=name, data={"arguments": arguments})

    def tool_result(self, name: str, content: str = "", **data: object) -> TrajectoryBuilder:
        return self._add(StepType.TOOL_RESULT, tool_name=name, content=content, data=data)

    def approval_request(self, name: str, **arguments: object) -> TrajectoryBuilder:
        return self._add(
            StepType.APPROVAL_REQUEST,
            tool_name=name,
            data={"tool_name": name, "arguments": arguments},
        )

    def approval_result(
        self, name: str, *, approved: bool = True, approval_id: str = "apr-1", **arguments: object
    ) -> TrajectoryBuilder:
        return self._add(
            StepType.APPROVAL_RESULT,
            tool_name=name,
            data={
                "tool_name": name,
                "approved": approved,
                "approval_id": approval_id,
                "arguments": arguments,
            },
        )

    def final(self, content: str) -> TrajectoryBuilder:
        return self._add(StepType.FINAL_OUTPUT, content=content, source="model")

    def build(self, **overrides: object) -> Trajectory:
        for key, value in overrides.items():
            setattr(self.trajectory, key, value)
        return self.trajectory


@pytest.fixture
def build_trajectory() -> type[TrajectoryBuilder]:
    return TrajectoryBuilder
