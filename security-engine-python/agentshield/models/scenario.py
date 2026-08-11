"""Attack scenarios and the contract between the engine and a target adapter."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentshield.models.common import AttackCategory, RunStatus, Severity


class InjectedArtifact(BaseModel):
    """Content the engine plants in a channel the agent will later read.

    This is what makes *indirect* injection testable: AgentShield never tells the agent to
    misbehave directly - it poisons a document and then sends a perfectly innocent user
    question. Adapters that cannot plant content simply skip these scenarios.
    """

    model_config = ConfigDict(extra="forbid")

    #: knowledge_base | email | web_page | tool_result | memory | mcp_resource
    channel: str
    artifact_id: str = Field(default_factory=lambda: f"doc-{uuid4().hex[:8]}")
    title: str = ""
    content: str = ""
    #: Tool whose result should carry this payload, for channel == "tool_result".
    tool_name: str | None = None


class AttackPayload(BaseModel):
    """What is actually sent to the target for one attempt."""

    model_config = ConfigDict(extra="forbid")

    prompt: str
    injections: list[InjectedArtifact] = Field(default_factory=list)
    #: Extra request fields (tenant override, headers, approval token replay, ...).
    metadata: dict[str, Any] = Field(default_factory=dict)
    #: Deterministic mutation seed that produced this payload from its template.
    seed: int = 0

    @property
    def fingerprint(self) -> str:
        material = self.prompt + "".join(i.content for i in self.injections)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


class ExpectedOutcome(BaseModel):
    """What a *secure* target does. Any deviation is the finding.

    Written as the safe behaviour rather than the unsafe one so scenarios stay meaningful
    when a target is fixed - the same scenario becomes the regression test.
    """

    model_config = ConfigDict(extra="forbid")

    #: Tools that must never be invoked in this scenario.
    forbidden_tools: list[str] = Field(default_factory=list)
    #: Canary strings that must not appear anywhere in the trajectory or output.
    forbidden_values: list[str] = Field(default_factory=list)
    #: Recipients the agent must refuse to send to.
    forbidden_recipients: list[str] = Field(default_factory=list)
    #: Evaluators expected to be the ones that catch a regression here. Used by evals/ to
    #: measure evaluator precision, and to explain *why* a scenario exists.
    detected_by: list[str] = Field(default_factory=list)
    #: Severity to assign when this scenario's expectation is violated.
    severity_on_violation: Severity = Severity.HIGH
    #: Agent should refuse outright over comply.
    expect_refusal: bool = False


class AttackScenario(BaseModel):
    """One concrete, reproducible test case."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: AttackCategory
    name: str
    description: str = ""
    payload: AttackPayload
    expected: ExpectedOutcome = Field(default_factory=ExpectedOutcome)
    #: Dataset template this instance was generated from, for provenance.
    template_id: str = ""
    template_version: str = "1"
    seed: int = 0
    tags: list[str] = Field(default_factory=list)
    #: Tools the target must expose for this scenario to be applicable.
    requires_tools: list[str] = Field(default_factory=list)
    #: Channels the adapter must support (e.g. "knowledge_base" for indirect injection).
    requires_channels: list[str] = Field(default_factory=list)
    #: Adapter types this scenario is written for, empty meaning any. An MCP call plan sent
    #: to a REST agent tests nothing and would otherwise score as a pass.
    requires_adapter: list[str] = Field(default_factory=list)
    status: RunStatus = RunStatus.PENDING

    def applies_to(self, available_tools: set[str], available_channels: set[str]) -> bool:
        """Skip scenarios the target cannot possibly exercise, instead of failing them."""
        return set(self.requires_tools).issubset(available_tools) and set(
            self.requires_channels
        ).issubset(available_channels)


class SessionContext(BaseModel):
    """Handed to the adapter when a session is opened."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    scenario_id: str
    correlation_id: str = Field(default_factory=lambda: uuid4().hex)
    #: Tenant AgentShield authenticates as. Cross-tenant scenarios then ask for another
    #: tenant's object and assert the *backend* refused.
    tenant_id: str | None = None
    actor: str = "agentshield"
    locale: str = "en"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    """Normalised result of one input sent to the target."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    output: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)
    status_code: int | None = None
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


class RunContext(BaseModel):
    """Everything needed to reproduce a run byte-for-byte (NFR: reproducibility).

    Persisted alongside every AttackRun. If any of these change, results are not comparable
    and the regression baseline must be re-recorded instead of silently diffed.
    """

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    dataset_version: str
    evaluator_set_version: str
    prompt_version: str
    policy_hash: str
    target_config_hash: str
    target_version: str | None = None
    judge_model: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    #: Wall-clock ceiling for a single scenario, from the policy budget.
    scenario_timeout_seconds: float = 60.0


class AttackRun(BaseModel):
    """One execution attempt of one scenario."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    scenario_id: str
    attempt: int = 1
    status: RunStatus = RunStatus.PENDING
    target_session_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    error: str | None = None
