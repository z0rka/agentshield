"""Repeated sampling for evaluators that can disagree with themselves.

The case worth guarding is the quiet one: a judge with no credentials skips every run, and a
naive counter reads ten identical skips as perfect agreement.
"""

from __future__ import annotations

from itertools import cycle
from pathlib import Path

import pytest

from agentshield.evals import FixtureSet, StabilityRunner, gate_stability, load_fixtures
from agentshield.evaluators.base import EvaluationContext, Evaluator
from agentshield.models.common import AttackCategory, Severity
from agentshield.models.finding import EvaluationResult, Evidence
from agentshield.models.policy import SecurityPolicy
from agentshield.models.trajectory import Trajectory

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "evals" / "fixtures"
POLICIES = REPO / "datasets" / "policies"


@pytest.fixture(scope="module")
def fixtures() -> FixtureSet:
    return FixtureSet(load_fixtures(FIXTURES, POLICIES))


class ScriptedJudge(Evaluator):
    """A judge whose verdicts follow a fixed cycle, so a test can pick the instability."""

    name = "ScriptedJudge"
    category = AttackCategory.INDIRECT_PROMPT_INJECTION
    deterministic = False
    max_severity = Severity.HIGH

    def __init__(self, verdicts: list[bool | None]) -> None:
        # None means "did not run", which is what a missing API key produces.
        self._verdicts = cycle(verdicts)

    def evaluate(
        self, trajectory: Trajectory, policy: SecurityPolicy, context: EvaluationContext
    ) -> list[EvaluationResult]:
        verdict = next(self._verdicts)
        if verdict is None:
            return [
                EvaluationResult(
                    evaluator=self.name,
                    violated=False,
                    category=self.category,
                    severity=Severity.INFO,
                    title=f"{self.name} skipped",
                    confidence=0.0,
                    deterministic=False,
                    skipped=True,
                )
            ]
        return [
            EvaluationResult(
                evaluator=self.name,
                violated=verdict,
                category=self.category,
                severity=Severity.HIGH if verdict else Severity.INFO,
                title="scripted",
                evidence=Evidence(summary="scripted") if verdict else None,
                confidence=0.8,
                deterministic=False,
            )
        ]


def test_a_judge_that_never_ran_is_unavailable_not_unanimous(fixtures):
    report = StabilityRunner([ScriptedJudge([None])], runs=4).run(fixtures)

    assert report.unavailable() == ["ScriptedJudge"]
    assert report.agreement("ScriptedJudge") is None
    assert gate_stability(report, min_agreement=0.9)


def test_a_coin_flipping_judge_fails_the_gate(fixtures):
    report = StabilityRunner([ScriptedJudge([True, False])], runs=4).run(fixtures)

    agreement = report.agreement("ScriptedJudge")
    assert agreement == pytest.approx(0.5)
    assert report.flipped("ScriptedJudge")
    assert gate_stability(report, min_agreement=0.9)


def test_a_consistent_judge_passes_the_gate(fixtures):
    report = StabilityRunner([ScriptedJudge([True])], runs=4).run(fixtures)

    assert report.agreement("ScriptedJudge") == pytest.approx(1.0)
    assert report.flipped("ScriptedJudge") == []
    assert not gate_stability(report, min_agreement=0.9)


def test_majority_verdict_ignores_the_minority_run(fixtures):
    report = StabilityRunner([ScriptedJudge([True, True, True, False])], runs=4).run(fixtures)

    sample = report.for_evaluator("ScriptedJudge")[0]
    assert sample.majority_fired is True
    assert sample.agreement == pytest.approx(0.75)
    assert sample.flipped


def test_skipped_runs_do_not_count_towards_the_rate(fixtures):
    """Two real runs, both firing, plus two skips is unanimous, not 50%."""
    report = StabilityRunner([ScriptedJudge([True, None])], runs=4).run(fixtures)

    sample = report.for_evaluator("ScriptedJudge")[0]
    assert sample.runs == 4
    assert sample.skipped == 2
    assert sample.usable_runs == 2
    assert sample.fire_rate == pytest.approx(1.0)


def test_one_run_is_rejected():
    with pytest.raises(ValueError, match="at least 2 runs"):
        StabilityRunner([ScriptedJudge([True])], runs=1)


def test_the_shipped_judges_have_no_credentials_here(fixtures):
    """Documents the default: judges are off, and that reads as unmeasured, not clean."""
    from agentshield.evaluators.registry import semantic_evaluators

    report = StabilityRunner(semantic_evaluators(), runs=2).run(fixtures)

    assert set(report.unavailable()) == set(report.evaluators())
    assert gate_stability(report, min_agreement=0.9)
