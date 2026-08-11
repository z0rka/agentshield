"""The trajectory: what the agent actually did.

This is the central artefact of AgentShield. Requests and responses tell you almost nothing
about an agentic failure; the ordered sequence of retrievals, tool calls, approvals and outputs
tells you everything. Every evaluator is a pure function of (Trajectory, SecurityPolicy).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentshield.models.common import StepType


class ToolCall(BaseModel):
    """A normalised tool invocation lifted out of a TOOL_CALL step."""

    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    #: Index of the owning step in the trajectory, so evidence can point at it.
    step_index: int = -1
    call_id: str | None = None

    def argument_text(self) -> str:
        """All argument values flattened to text, for pattern scanning."""
        return _flatten(self.arguments)


class TrajectoryStep(BaseModel):
    """One observable event in the agent's execution."""

    model_config = ConfigDict(extra="forbid")

    sequence_number: int
    step_type: StepType
    tool_name: str | None = None
    #: Free-form content: the prompt, the model text, the retrieved document, the tool result.
    content: str = ""
    #: Structured payload when the target exposes one (tool arguments, tool result JSON).
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int | None = None
    trace_id: str | None = None
    #: Where this content came from. Untrusted provenance is what makes indirect injection
    #: detectable: an instruction that entered via RETRIEVAL or TOOL_RESULT is data, not a command.
    source: str | None = None
    error: str | None = None

    @property
    def is_untrusted_content(self) -> bool:
        return self.step_type in {StepType.RETRIEVAL, StepType.TOOL_RESULT}

    def searchable_text(self) -> str:
        """Everything in this step that could carry a leaked value."""
        return f"{self.content}\n{_flatten(self.data)}"


class Trajectory(BaseModel):
    """Ordered steps plus the accounting the budget evaluators need."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    steps: list[TrajectoryStep] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_seconds: float = 0.0
    #: Populated by the adapter when the target reports the tenant it authenticated as.
    tenant_id: str | None = None
    truncated: bool = False

    def __len__(self) -> int:
        return len(self.steps)

    def of_type(self, *types: StepType) -> list[TrajectoryStep]:
        wanted = set(types)
        return [s for s in self.steps if s.step_type in wanted]

    def tool_calls(self, name: str | None = None) -> list[ToolCall]:
        """Tool invocations in order, optionally filtered by tool name."""
        calls: list[ToolCall] = []
        for index, step in enumerate(self.steps):
            if step.step_type is not StepType.TOOL_CALL or step.tool_name is None:
                continue
            if name is not None and step.tool_name != name:
                continue
            arguments = step.data.get("arguments")
            calls.append(
                ToolCall(
                    name=step.tool_name,
                    arguments=arguments if isinstance(arguments, dict) else {},
                    step_index=index,
                    call_id=step.data.get("call_id"),
                )
            )
        return calls

    def tool_names(self) -> list[str]:
        return [call.name for call in self.tool_calls()]

    def result_for(self, call: ToolCall) -> tuple[int, TrajectoryStep] | None:
        """The TOOL_RESULT that answered `call`, matched by call_id then by position.

        Returns the list index too: evidence references positions in `steps`, and a target's
        self-reported `sequence_number` is not guaranteed to be the same thing.
        """
        for index in range(call.step_index + 1, len(self.steps)):
            step = self.steps[index]
            if step.step_type is not StepType.TOOL_RESULT:
                continue
            if call.call_id and step.data.get("call_id") and step.data["call_id"] != call.call_id:
                continue
            return index, step
        return None

    def final_output(self) -> str:
        outputs = self.of_type(StepType.FINAL_OUTPUT)
        return outputs[-1].content if outputs else ""

    def searchable_text(self) -> str:
        return "\n".join(step.searchable_text() for step in self.steps)

    def add(self, step: TrajectoryStep) -> None:
        self.steps.append(step)


def _flatten(value: Any) -> str:
    """Render nested structures as text so regex scanning cannot be evaded by nesting."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{k}={_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)
