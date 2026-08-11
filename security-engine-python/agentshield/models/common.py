"""Enumerations shared between the control plane and the engine.

Every value here has a matching Java enum constant. They are compared by *name*, so the
names must not drift. `contracts/api/enums.json` is the single source both sides validate
against in CI.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """See docs/severity-model.md for the assignment rules.

    Ordering matters: `Severity.CRITICAL.rank` is used for CI gating and for picking the
    winning severity when several evaluators fire on one scenario.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AttackCategory(StrEnum):
    """Attack suites. Maps to the OWASP Agentic / LLM Top 10 families."""

    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    TOOL_ABUSE = "TOOL_ABUSE"
    DATA_LEAKAGE = "DATA_LEAKAGE"
    CROSS_TENANT = "CROSS_TENANT"
    APPROVAL_BYPASS = "APPROVAL_BYPASS"
    UNBOUNDED_CONSUMPTION = "UNBOUNDED_CONSUMPTION"
    IMPROPER_OUTPUT_HANDLING = "IMPROPER_OUTPUT_HANDLING"
    TOOL_RESULT_POISONING = "TOOL_RESULT_POISONING"
    MEMORY_POISONING = "MEMORY_POISONING"


#: Suite alias used by the CLI (`--suite owasp-agentic`).
SUITE_ALIASES: dict[str, tuple[AttackCategory, ...]] = {
    "owasp-agentic": tuple(AttackCategory),
    "injection": (
        AttackCategory.DIRECT_PROMPT_INJECTION,
        AttackCategory.INDIRECT_PROMPT_INJECTION,
        AttackCategory.TOOL_RESULT_POISONING,
    ),
    "data": (AttackCategory.DATA_LEAKAGE, AttackCategory.CROSS_TENANT),
    "agency": (
        AttackCategory.TOOL_ABUSE,
        AttackCategory.APPROVAL_BYPASS,
        AttackCategory.IMPROPER_OUTPUT_HANDLING,
    ),
    "smoke": (
        AttackCategory.DIRECT_PROMPT_INJECTION,
        AttackCategory.INDIRECT_PROMPT_INJECTION,
    ),
}


class StepType(StrEnum):
    """A trajectory step. Adapters normalise every target's native format into these."""

    USER_INPUT = "USER_INPUT"
    MODEL_OUTPUT = "MODEL_OUTPUT"
    RETRIEVAL = "RETRIEVAL"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    APPROVAL_REQUEST = "APPROVAL_REQUEST"
    APPROVAL_RESULT = "APPROVAL_RESULT"
    FINAL_OUTPUT = "FINAL_OUTPUT"
    ERROR = "ERROR"


class ToolClassification(StrEnum):
    """How much damage a tool can do. Drives which evaluators apply to it."""

    READ = "READ"
    SENSITIVE_READ = "SENSITIVE_READ"
    WRITE = "WRITE"
    FINANCIAL_WRITE = "FINANCIAL_WRITE"
    EXTERNAL_COMMUNICATION = "EXTERNAL_COMMUNICATION"
    CODE_EXECUTION = "CODE_EXECUTION"
    UNKNOWN = "UNKNOWN"

    @property
    def is_side_effecting(self) -> bool:
        return self in _SIDE_EFFECTING


_SIDE_EFFECTING = frozenset(
    {
        ToolClassification.WRITE,
        ToolClassification.FINANCIAL_WRITE,
        ToolClassification.EXTERNAL_COMMUNICATION,
        ToolClassification.CODE_EXECUTION,
    }
)


class ScanStatus(StrEnum):
    """Owned by the control plane. The engine reports progress; it never decides status."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    DISCOVERING = "DISCOVERING"
    RUNNING = "RUNNING"
    EVALUATING = "EVALUATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}


class RunStatus(StrEnum):
    """Outcome of one attack scenario execution against the target."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    TARGET_ERROR = "TARGET_ERROR"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    CANCELLED = "CANCELLED"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
