"""The target adapter contract.

An adapter is the only part of AgentShield that knows how a specific system under test is
shaped. Everything downstream - attack selection, evaluation, findings - works on the
normalised `Trajectory`, so adding a new target type never touches the evaluators.

Fidelity is explicit, not assumed. A target that exposes nothing but a chat endpoint yields
an output-only trajectory, and `TargetCapabilities` says so; the scenario selector then skips
scenarios that cannot be judged rather than reporting a false pass. Silently degrading
coverage is worse than reporting less coverage.
"""

from __future__ import annotations

import abc
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from agentshield.models.scenario import AttackPayload, SessionContext, TargetResponse
from agentshield.models.trajectory import Trajectory, TrajectoryStep


class ToolDescriptor(BaseModel):
    """A tool the target advertises, as discovered by `discover_capabilities`."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str = ""
    parameters: dict[str, object] = Field(default_factory=dict)
    #: Scopes the target claims the tool requires. Claimed, not verified - proving the
    #: backend actually enforces them is what the CROSS_TENANT suite is for.
    scopes: list[str] = Field(default_factory=list)


class TargetCapabilities(BaseModel):
    """What this target lets AgentShield observe and control.

    Drives scenario applicability. `channels` are the surfaces into which content can be
    planted for indirect-injection testing (knowledge_base, email, web_page, memory, ...).
    """

    model_config = ConfigDict(extra="forbid")

    tools: list[ToolDescriptor] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)
    supports_trajectory: bool = False
    supports_reset: bool = False
    supports_approval: bool = False
    supports_tenant_override: bool = False
    target_version: str | None = None

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.tools}

    @property
    def channel_names(self) -> set[str]:
        return set(self.channels)


@runtime_checkable
class TargetAdapter(Protocol):
    """Structural contract every target integration satisfies.

    Kept as a Protocol so a user's adapter needs no import from AgentShield to type-check
    against it; `BaseTargetAdapter` below is the convenience base class for ours.
    """

    async def start_session(self, context: SessionContext) -> str:
        """Open a session and return its id."""
        ...

    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse:
        """Deliver one attack payload and return the target's normalised response."""
        ...

    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]:
        """Return the ordered steps the agent took during this session."""
        ...

    async def reset(self, session_id: str) -> None:
        """Discard session state, including any planted content."""
        ...


class BaseTargetAdapter(abc.ABC):
    """Base class supplying the lifecycle plumbing shared by all built-in adapters."""

    #: Stable adapter id used in target configuration and reproduction commands.
    adapter_type: str = "base"

    @abc.abstractmethod
    async def discover_capabilities(self) -> TargetCapabilities:
        """Enumerate tools and channels. Runs once per scan, before attack selection."""

    @abc.abstractmethod
    async def start_session(self, context: SessionContext) -> str: ...

    @abc.abstractmethod
    async def send_input(self, session_id: str, payload: AttackPayload) -> TargetResponse: ...

    @abc.abstractmethod
    async def get_trajectory(self, session_id: str) -> list[TrajectoryStep]: ...

    async def reset(self, session_id: str) -> None:
        """Default: nothing to clean up. Override when the target holds session state."""
        return None

    def observed_tenant(self, session_id: str) -> str | None:
        """The tenant the *target* says this session is acting as, if it says at all.

        Distinct from the tenant AgentShield asked for. One is a claim by the system under
        test, the other is our intent, and every tenant-scoped judgement needs the first:
        without an authenticated principal there is nothing to compare a returned record
        against, so cross-tenant evaluation degrades to "no findings" - the one output a
        security tool must never produce by accident.

        Adapters that cannot observe it return None and the trajectory is attributed from
        the scan configuration. If neither is available, `enforce_tenant_context` reports the
        gap, so the suite never passes empty.
        """
        return None

    async def collect(self, session_id: str, response: TargetResponse) -> Trajectory:
        """Assemble the full `Trajectory` for a finished attempt.

        Adapters that cannot report internal steps still produce a valid trajectory
        containing the final output, so output-level evaluators (data leakage, refusal)
        remain applicable.
        """
        steps = await self.get_trajectory(session_id)
        return Trajectory(
            session_id=session_id,
            steps=steps,
            tenant_id=self.observed_tenant(session_id),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            estimated_cost_usd=response.estimated_cost_usd,
            duration_seconds=response.duration_seconds,
        )

    async def aclose(self) -> None:
        """Release adapter-level resources (HTTP clients, MCP sessions)."""
        return None

    async def __aenter__(self) -> BaseTargetAdapter:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class TargetError(RuntimeError):
    """The target failed in a way that is not a security finding.

    Distinguishing "the agent did something unsafe" from "the target returned 502" is
    essential: the first is a finding, the second is a retry.
    """

    def __init__(self, message: str, *, retryable: bool = True, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
