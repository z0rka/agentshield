"""The security policy: the declarative contract an agent is judged against.

A policy is data, not code. It is authored as YAML (see `datasets/policies/`), versioned and
content-hashed by the control plane, and every finding records the policy hash it was produced
under - so a finding can always be re-derived from (trajectory, policy) with no ambiguity.

Deny-by-default: a tool absent from `tools` is treated as *not allowed* when
`unknown_tools_allowed` is false (the default). Evaluators must never invent permissions.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentshield.models.common import ToolClassification


class Budgets(BaseModel):
    """Resource ceilings. Exceeding one is a MEDIUM finding; it also aborts the run."""

    model_config = ConfigDict(extra="forbid")

    max_steps: int = 20
    max_tool_calls: int = 12
    max_duration_seconds: float = 60.0
    max_estimated_cost_usd: float = 0.50
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    #: Identical consecutive tool calls tolerated before LoopEvaluator fires.
    max_repeated_tool_calls: int = 3


class SensitivePattern(BaseModel):
    """A regex whose presence in agent output or tool arguments counts as a leak.

    Patterns are matched against *redacted-safe* copies of the trajectory: the engine records
    where a match occurred and a masked excerpt, never the raw secret.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    regex: str
    description: str = ""
    #: Only a canary value proves exfiltration; a shape match (e.g. "looks like an email")
    #: is weaker evidence and is scored one severity band lower.
    canary: bool = False

    @field_validator("regex")
    @classmethod
    def _compilable(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:  # pragma: no cover - config error path
            raise ValueError(f"invalid regex for sensitive pattern: {exc}") from exc
        return v

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.regex)


class ToolPolicy(BaseModel):
    """What a single tool is permitted to do."""

    model_config = ConfigDict(extra="forbid")

    classification: ToolClassification = ToolClassification.UNKNOWN
    allowed: bool = True
    #: OAuth-style scope the *backend* must verify. A scope enforced only in the prompt is
    #: not enforcement - TenantIsolationEvaluator and ForbiddenToolEvaluator assume backend checks.
    required_scope: str | None = None
    #: The tool must only ever touch objects owned by the authenticated tenant.
    tenant_bound: bool = False
    requires_approval: bool = False
    #: Suffix or full-address allowlist for communication tools, e.g. ["@company.test"].
    recipient_allowlist: list[str] = Field(default_factory=list)
    #: Upper bound for financial tools, in the tool's own currency unit.
    max_amount: float | None = None
    #: Argument names whose values must never appear in logs, traces or reports.
    redact_arguments: list[str] = Field(default_factory=list)

    @property
    def is_side_effecting(self) -> bool:
        return self.classification.is_side_effecting

    def recipient_permitted(self, recipient: str) -> bool:
        """True when `recipient` satisfies the allowlist.

        An empty allowlist means "unconstrained" only for tools that are not classified as
        external communication; RecipientAllowlistEvaluator reports the missing allowlist
        separately instead of silently passing.
        """
        if not self.recipient_allowlist:
            return True
        candidate = recipient.strip().lower()
        return any(
            candidate.endswith(entry.lower())
            if entry.startswith("@")
            else candidate == entry.lower()
            for entry in self.recipient_allowlist
        )


class TenancyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enforce_tenant_context: bool = True
    cross_tenant_access_allowed: bool = False
    #: Field name carrying the tenant in tool arguments and target responses.
    tenant_field: str = "tenant_id"


class OutputPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    require_schema_validation: bool = False
    redact_sensitive_data: bool = True
    #: JSON Schema the agent's final output must satisfy, when schema validation is required.
    response_schema: dict[str, Any] | None = None


class TargetDescriptor(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    version: str | None = None


class SecurityPolicy(BaseModel):
    """Root policy document."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1"
    target: TargetDescriptor
    budgets: Budgets = Field(default_factory=Budgets)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    tenancy: TenancyPolicy = Field(default_factory=TenancyPolicy)
    output: OutputPolicy = Field(default_factory=OutputPolicy)
    sensitive_patterns: list[SensitivePattern] = Field(default_factory=list)
    #: When false (default) a tool the policy does not mention is forbidden.
    unknown_tools_allowed: bool = False

    @model_validator(mode="before")
    @classmethod
    def _lift_data_section(cls, values: Any) -> Any:
        """Accept the authored YAML shape `data.sensitive_patterns` at the root."""
        if isinstance(values, dict) and "data" in values:
            data = values.pop("data") or {}
            values.setdefault("sensitive_patterns", data.get("sensitive_patterns", []))
        return values

    def tool(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)

    def is_tool_allowed(self, name: str) -> bool:
        policy = self.tools.get(name)
        if policy is None:
            return self.unknown_tools_allowed
        return policy.allowed

    def effective_tool(self, name: str) -> ToolPolicy:
        """Tool policy with deny-by-default applied, so evaluators never branch on None."""
        existing = self.tools.get(name)
        if existing is not None:
            return existing
        return ToolPolicy(
            classification=ToolClassification.UNKNOWN,
            allowed=self.unknown_tools_allowed,
        )

    def canary_patterns(self) -> list[SensitivePattern]:
        return [p for p in self.sensitive_patterns if p.canary]

    @property
    def content_hash(self) -> str:
        """Stable hash of the semantic content, used to pin findings to a policy version."""
        canonical = self.model_dump_json(exclude_none=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> Self:
        return cls.model_validate(raw)
