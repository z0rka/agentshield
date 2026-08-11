"""Evaluation results and findings.

An `EvaluationResult` is what a single evaluator says about a single trajectory.
A `Finding` is what survives deduplication and reaches the report - with evidence a human
can check, a reproduction a machine can re-run, and a remediation someone can implement.

The distinction matters for trust: an evaluator may fire many times across a scan, but a
report with fifty copies of the same issue is noise. Fingerprinting collapses them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentshield.models.common import AttackCategory, FindingStatus, Severity


class Evidence(BaseModel):
    """Pointers into the trajectory that justify the finding.

    Excerpts are redacted before they get here - a report must be shareable. If a canary
    secret was leaked we prove it by naming the canary, not by reprinting the value.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    #: Indices into Trajectory.steps that a reviewer should look at first.
    step_indices: list[int] = Field(default_factory=list)
    #: Short redacted excerpts keyed by what they show, e.g. {"tool_arguments": "to=att***"}.
    excerpts: dict[str, str] = Field(default_factory=dict)
    tool_names: list[str] = Field(default_factory=list)
    #: The policy clause that was violated, e.g. "tools.send_email.recipient_allowlist".
    policy_path: str | None = None


class Reproduction(BaseModel):
    """Everything needed to re-run exactly this attack.

    This is what turns a finding into a regression test: the same scenario, the same seed,
    the same policy hash, replayed after the fix.
    """

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    template_id: str = ""
    seed: int = 0
    dataset_version: str = ""
    policy_hash: str = ""
    prompt: str = ""
    injections: list[dict[str, Any]] = Field(default_factory=list)
    #: Ready-to-run command that reproduces this single case.
    command: str = ""
    #: True only when a reduced payload was *observed* to reproduce the same fingerprint.
    #: `prompt` and `injections` then hold the reduced form; the command still replays the
    #: original scenario, which is what a regression test wants.
    minimized: bool = False
    #: Live target calls minimisation spent on this finding.
    probes: int = 0
    #: What minimisation did, or why it did not run. A reproduction that is not minimal should
    #: say so in the report instead of leaving the reader to guess whether anyone tried.
    note: str = ""


class Remediation(BaseModel):
    """Concrete fixes, ordered by leverage."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    #: Each entry is an actionable control, e.g. "Enforce recipient allowlist in send_email".
    controls: list[str] = Field(default_factory=list)
    #: Optional policy or code snippet illustrating the fix.
    example: str | None = None
    references: list[str] = Field(default_factory=list)


class EvaluationResult(BaseModel):
    """One evaluator's verdict on one trajectory.

    `violated=False` results are kept: proving a control *held* is what makes the post-fix
    regression run meaningful ("Approval compliance: 100%").
    """

    model_config = ConfigDict(extra="forbid")

    evaluator: str
    violated: bool
    category: AttackCategory
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    evidence: Evidence | None = None
    #: Deterministic evaluators are 1.0. LLM judges report their own confidence and can
    #: never, on their own, produce a CRITICAL finding.
    confidence: float = 1.0
    deterministic: bool = True
    #: The evaluator did not run at all: no credentials, or the call failed. Distinct from
    #: `violated=False`, which means it ran and found nothing. Collapsing the two is how a
    #: missing API key comes to look like a clean scan.
    skipped: bool = False

    @property
    def is_actionable(self) -> bool:
        return self.violated


class Finding(BaseModel):
    """A deduplicated, severity-assigned, reproducible security issue."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: uuid4().hex)
    #: Human-facing stable code, e.g. "AS-INJECTION-004".
    code: str = ""
    scan_id: str = ""
    scenario_id: str = ""
    category: AttackCategory
    severity: Severity
    title: str
    description: str = ""
    evidence: Evidence
    reproduction: Reproduction
    remediation: Remediation | None = None
    status: FindingStatus = FindingStatus.OPEN
    #: Stable identity across scans: same fingerprint == same issue. Drives dedup,
    #: "first_seen", and the CI new-vs-known comparison against a baseline.
    fingerprint: str = ""
    #: Evaluators that independently confirmed this. Multiple deterministic confirmations
    #: are the strongest signal available.
    detected_by: list[str] = Field(default_factory=list)
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    occurrences: int = 1

    @property
    def confirmed_deterministically(self) -> bool:
        return bool(self.detected_by)


class ScanSummary(BaseModel):
    """Aggregate result of a scan. What CI gates on."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str
    target_name: str = ""
    policy_hash: str = ""
    dataset_version: str = ""
    scenarios_selected: int = 0
    scenarios_executed: int = 0
    scenarios_skipped: int = 0
    scenarios_errored: int = 0
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost_usd: float = 0.0

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    @property
    def critical(self) -> int:
        return self.count(Severity.CRITICAL)

    @property
    def high(self) -> int:
        return self.count(Severity.HIGH)

    @property
    def medium(self) -> int:
        return self.count(Severity.MEDIUM)

    @property
    def low(self) -> int:
        return self.count(Severity.LOW)

    def passed(self, fail_on: Severity = Severity.HIGH) -> bool:
        """CI gate: fail when any finding is at or above `fail_on`."""
        return not any(f.severity.at_least(fail_on) for f in self.findings)
