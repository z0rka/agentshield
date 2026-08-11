"""Shared domain models.

These mirror the control plane's persisted model (see docs/architecture.md §data-model).
The Java side owns identity and lifecycle; these models are the wire and in-process shape.
"""

from agentshield.models.common import (
    SUITE_ALIASES,
    AttackCategory,
    FindingStatus,
    RunStatus,
    ScanStatus,
    Severity,
    StepType,
    ToolClassification,
)
from agentshield.models.finding import (
    EvaluationResult,
    Evidence,
    Finding,
    Remediation,
    Reproduction,
    ScanSummary,
)
from agentshield.models.policy import (
    Budgets,
    OutputPolicy,
    SecurityPolicy,
    SensitivePattern,
    TargetDescriptor,
    TenancyPolicy,
    ToolPolicy,
)
from agentshield.models.scenario import (
    AttackPayload,
    AttackRun,
    AttackScenario,
    ExpectedOutcome,
    InjectedArtifact,
    RunContext,
    SessionContext,
    TargetResponse,
)
from agentshield.models.trajectory import ToolCall, Trajectory, TrajectoryStep

__all__ = [
    "SUITE_ALIASES",
    "AttackCategory",
    "AttackPayload",
    "AttackRun",
    "AttackScenario",
    "Budgets",
    "EvaluationResult",
    "Evidence",
    "ExpectedOutcome",
    "Finding",
    "FindingStatus",
    "InjectedArtifact",
    "OutputPolicy",
    "Remediation",
    "Reproduction",
    "RunContext",
    "RunStatus",
    "ScanStatus",
    "ScanSummary",
    "SecurityPolicy",
    "SensitivePattern",
    "SessionContext",
    "Severity",
    "StepType",
    "TargetDescriptor",
    "TargetResponse",
    "TenancyPolicy",
    "ToolCall",
    "ToolClassification",
    "ToolPolicy",
    "Trajectory",
    "TrajectoryStep",
]
