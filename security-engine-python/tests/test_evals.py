"""The harness that scores the evaluators.

A metric nobody has tried to break is decoration. The tests that matter here are the ones
that feed the harness a broken evaluator and an unmeasured one, and check it says so.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.evals import EvalRunner, FixtureError, FixtureSet, gate, load_fixtures
from agentshield.evaluators.base import EvaluationContext, Evaluator
from agentshield.evaluators.registry import deterministic_evaluators
from agentshield.models.common import AttackCategory, Severity
from agentshield.models.finding import EvaluationResult, Evidence
from agentshield.models.policy import SecurityPolicy
from agentshield.models.trajectory import Trajectory

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "evals" / "fixtures"
POLICIES = REPO / "datasets" / "policies"


@pytest.fixture(scope="module")
def fixture_set() -> FixtureSet:
    return FixtureSet(load_fixtures(FIXTURES, POLICIES))


class AlwaysFires(Evaluator):
    """Stands in for an evaluator that has regressed into flagging everything."""

    name = "SensitiveDataLeakEvaluator"
    category = AttackCategory.DATA_LEAKAGE

    def evaluate(
        self, trajectory: Trajectory, policy: SecurityPolicy, context: EvaluationContext
    ) -> list[EvaluationResult]:
        return [
            EvaluationResult(
                evaluator=self.name,
                violated=True,
                category=self.category,
                severity=Severity.CRITICAL,
                title="everything is a leak",
                evidence=Evidence(summary="none"),
            )
        ]


class NeverFires(Evaluator):
    """Stands in for an evaluator that has silently stopped working."""

    name = "SensitiveDataLeakEvaluator"
    category = AttackCategory.DATA_LEAKAGE

    def evaluate(
        self, trajectory: Trajectory, policy: SecurityPolicy, context: EvaluationContext
    ) -> list[EvaluationResult]:
        return [self._passed("nothing to see")]


def test_an_evaluator_that_flags_everything_loses_precision(fixture_set):
    report = EvalRunner([AlwaysFires()]).run(fixture_set)

    confusion = report.confusions["SensitiveDataLeakEvaluator"]
    assert confusion.false_positives > 0
    assert confusion.precision is not None and confusion.precision < 1.0
    assert gate(report, min_precision=0.95, require_full_coverage=False)


def test_an_evaluator_that_stopped_working_loses_recall(fixture_set):
    report = EvalRunner([NeverFires()]).run(fixture_set)

    confusion = report.confusions["SensitiveDataLeakEvaluator"]
    assert confusion.false_negatives > 0
    assert confusion.recall == 0.0
    assert any(f.kind == "missed" for f in report.failures)


def test_an_evaluator_with_no_fixtures_is_unmeasured_not_perfect(fixture_set):
    """The dangerous default. Never firing must not read as never being wrong."""
    report = EvalRunner(deterministic_evaluators()).run(fixture_set)
    report.unmeasured = {"SomeUncoveredEvaluator"}

    assert "SomeUncoveredEvaluator" not in report.confusions
    assert not gate(report, min_precision=0.95, require_full_coverage=False)
    assert gate(report, min_precision=0.95, require_full_coverage=True)


def test_the_shipped_evaluators_pass_their_own_gate(fixture_set):
    report = EvalRunner(deterministic_evaluators()).run(fixture_set)

    assert not gate(report, min_precision=0.95, require_full_coverage=True), report.failures
    assert report.fixtures_scored >= 15


def test_every_deterministic_evaluator_has_coverage(fixture_set):
    report = EvalRunner(deterministic_evaluators()).run(fixture_set)

    assert report.unmeasured == set(), f"no fixtures for: {sorted(report.unmeasured)}"


def test_ambiguous_fixtures_are_recorded_but_not_scored(fixture_set):
    report = EvalRunner(deterministic_evaluators()).run(fixture_set)

    assert report.ambiguous, "the ambiguous set exists so disagreement is visible"
    assert report.fixtures_scored == len(fixture_set.scored())


def test_a_fixture_naming_an_unknown_evaluator_fails(fixture_set):
    """Otherwise the case reads as passing forever: an absent evaluator cannot disagree."""
    subset = FixtureSet([f for f in fixture_set.scored()][:1])
    report = EvalRunner([]).run(subset)

    assert any(f.kind == "unknown evaluator" for f in report.failures)
    assert gate(report, min_precision=0.95, require_full_coverage=False)


def test_malformed_fixture_reports_the_file_not_a_traceback(tmp_path):
    broken = tmp_path / "broken.yaml"
    broken.write_text("id: X\ndescription: a colon: inside a scalar\n", encoding="utf-8")

    with pytest.raises(FixtureError, match="broken.yaml"):
        load_fixtures(tmp_path, POLICIES)


def test_fixture_referencing_a_missing_policy_fails(tmp_path):
    orphan = tmp_path / "orphan.yaml"
    orphan.write_text(
        "id: X\nlabel: true_positive\npolicy: no-such-policy\n"
        "trajectory:\n  - user: hello\n",
        encoding="utf-8",
    )

    with pytest.raises(FixtureError, match="no-such-policy"):
        load_fixtures(tmp_path, POLICIES)
