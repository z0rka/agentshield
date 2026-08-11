"""Evaluator registry.

Every evaluator runs on every trajectory. That is intentional: an APPROVAL_BYPASS scenario
that happens to also leak a canary should report both, because the attacker will not respect
our taxonomy either. Categories organise the *report*, not the *checks*.
"""

from __future__ import annotations

from agentshield.evaluators.approval import (
    ApprovalComplianceEvaluator,
    ToolArgumentMutationEvaluator,
)
from agentshield.evaluators.base import EvaluationContext, Evaluator
from agentshield.evaluators.data import RecipientAllowlistEvaluator, SensitiveDataLeakEvaluator
from agentshield.evaluators.injection import InjectionComplianceEvaluator
from agentshield.evaluators.llm_judge import (
    DeceptionJudge,
    JudgeClient,
    PolicyComplianceJudge,
    RefusalQualityJudge,
    SemanticInjectionJudge,
)
from agentshield.evaluators.manifest import (
    DangerousToolCombinationEvaluator,
    ToolDescriptionInjectionEvaluator,
)
from agentshield.evaluators.memory import MemoryIntegrityEvaluator
from agentshield.evaluators.output import SchemaValidityEvaluator, UnsafeOutputSinkEvaluator
from agentshield.evaluators.resources import BudgetEvaluator, LoopEvaluator
from agentshield.evaluators.tenancy import TenantIsolationEvaluator
from agentshield.evaluators.tools import ExternalSideEffectEvaluator, ForbiddenToolEvaluator
from agentshield.models.finding import EvaluationResult
from agentshield.models.policy import SecurityPolicy
from agentshield.models.trajectory import Trajectory
from agentshield.telemetry import set_attributes, span

#: The mandatory deterministic set. Order is report order.
DETERMINISTIC_EVALUATORS: tuple[type[Evaluator], ...] = (
    ForbiddenToolEvaluator,
    ApprovalComplianceEvaluator,
    ToolArgumentMutationEvaluator,
    SensitiveDataLeakEvaluator,
    RecipientAllowlistEvaluator,
    TenantIsolationEvaluator,
    InjectionComplianceEvaluator,
    ExternalSideEffectEvaluator,
    UnsafeOutputSinkEvaluator,
    SchemaValidityEvaluator,
    BudgetEvaluator,
    LoopEvaluator,
    ToolDescriptionInjectionEvaluator,
    DangerousToolCombinationEvaluator,
    MemoryIntegrityEvaluator,
)

SEMANTIC_EVALUATORS: tuple[type[Evaluator], ...] = (
    SemanticInjectionJudge,
    RefusalQualityJudge,
    DeceptionJudge,
    PolicyComplianceJudge,
)


def deterministic_evaluators() -> list[Evaluator]:
    return [cls() for cls in DETERMINISTIC_EVALUATORS]


def semantic_evaluators(client: JudgeClient | None = None) -> list[Evaluator]:
    return [cls(client) for cls in SEMANTIC_EVALUATORS]  # type: ignore[call-arg]


def evaluator_by_name(name: str) -> Evaluator:
    for cls in (*DETERMINISTIC_EVALUATORS, *SEMANTIC_EVALUATORS):
        if cls.name == name:
            return cls()  # type: ignore[call-arg]
    raise KeyError(f"unknown evaluator: {name}")


def run_evaluators(
    evaluators: list[Evaluator],
    trajectory: Trajectory,
    policy: SecurityPolicy,
    context: EvaluationContext,
) -> list[EvaluationResult]:
    """Run every evaluator, isolating failures.

    One evaluator raising must not lose the results of the eleven that succeeded - a scan
    that reports nothing because of a bug in a helper is the worst possible outcome for a
    security tool. The failure is surfaced as an INFO result so it is visible rather than
    swallowed.
    """
    results: list[EvaluationResult] = []
    for evaluator in evaluators:
        try:
            with span("evaluate", **{"evaluator.name": evaluator.name}) as current:
                verdicts = evaluator.run(trajectory, policy, context)
                set_attributes(
                    current,
                    **{"evaluator.violations": sum(1 for v in verdicts if v.violated)},
                )
            results.extend(verdicts)
        except Exception as exc:  # noqa: BLE001
            results.append(
                EvaluationResult(
                    evaluator=evaluator.name,
                    violated=False,
                    category=evaluator.category,
                    title=f"{evaluator.name} raised {type(exc).__name__}",
                    description=(
                        f"Evaluator failed and produced no verdict: {exc}. Coverage for this "
                        "check is missing from the scan."
                    ),
                    deterministic=evaluator.deterministic,
                    confidence=0.0,
                    skipped=True,
                )
            )
    return results
