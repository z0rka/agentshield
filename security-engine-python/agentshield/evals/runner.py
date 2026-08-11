"""Score a set of evaluators against labelled fixtures."""

from __future__ import annotations

from agentshield.evals.fixture import Fixture, FixtureSet
from agentshield.evals.scoring import Report
from agentshield.evals.stability import Sample, StabilityReport
from agentshield.evaluators.base import Evaluator
from agentshield.evaluators.registry import run_evaluators


class EvalRunner:
    """Runs fixtures through a fixed set of evaluators and scores the outcome."""

    def __init__(self, evaluators: list[Evaluator]) -> None:
        self.evaluators = evaluators
        self._names = {evaluator.name for evaluator in evaluators}

    def run(self, fixtures: FixtureSet) -> Report:
        report = Report(ambiguous=[f.id for f in fixtures.ambiguous()])

        for fixture in fixtures.scored():
            self._score(fixture, report)
            report.fixtures_scored += 1

        report.unmeasured = self._names - fixtures.evaluators_covered()
        self._reject_unknown_names(fixtures, report)
        return report

    def _score(self, fixture: Fixture, report: Report) -> None:
        results = run_evaluators(
            self.evaluators, fixture.trajectory, fixture.policy, fixture.context
        )
        fired = {result.evaluator: result for result in results if result.violated}

        for name in sorted(fixture.expect.must_fire):
            confusion = report.record(name)
            result = fired.get(name)
            if result is None:
                confusion.false_negatives += 1
                report.fail(fixture.id, name, "missed", "expected to fire, did not")
                continue

            confusion.true_positives += 1
            floor = fixture.expect.severity_at_least
            if floor is not None and not result.severity.at_least(floor):
                report.fail(
                    fixture.id,
                    name,
                    "under-rated",
                    f"reported {result.severity}, expected at least {floor}",
                )

        for name in sorted(fixture.expect.must_not_fire):
            confusion = report.record(name)
            result = fired.get(name)
            if result is None:
                confusion.true_negatives += 1
                continue

            confusion.false_positives += 1
            report.fail(
                fixture.id,
                name,
                "false positive",
                result.title or "fired on legitimate behaviour",
            )

    def _reject_unknown_names(self, fixtures: FixtureSet, report: Report) -> None:
        """A fixture naming an evaluator that does not exist measures nothing.

        Left unchecked this reads as a passing case forever, because an evaluator that cannot
        run also cannot disagree with the label.
        """
        for fixture in fixtures.scored():
            for name in sorted(fixture.expect.scored_evaluators() - self._names):
                report.fail(fixture.id, name, "unknown evaluator", "not in the evaluator set")


class StabilityRunner:
    """Samples non-deterministic evaluators repeatedly over the same fixtures."""

    def __init__(self, evaluators: list[Evaluator], *, runs: int = 5) -> None:
        if runs < 2:
            # One run measures a verdict. Stability needs at least a second one to disagree
            # with the first, so a `runs=1` request is a mistake, not a cheap mode.
            raise ValueError("stability needs at least 2 runs per fixture")
        self.evaluators = evaluators
        self.runs = runs

    def run(self, fixtures: FixtureSet) -> StabilityReport:
        report = StabilityReport(runs_per_fixture=self.runs)

        for fixture in fixtures.fixtures:
            samples = {
                evaluator.name: Sample(fixture.id, evaluator.name)
                for evaluator in self.evaluators
            }
            for _ in range(self.runs):
                results = run_evaluators(
                    self.evaluators, fixture.trajectory, fixture.policy, fixture.context
                )
                for result in results:
                    sample = samples.get(result.evaluator)
                    if sample is None:
                        continue
                    sample.runs += 1
                    if result.skipped:
                        sample.skipped += 1
                    elif result.violated:
                        sample.fired += 1

            report.samples.extend(samples.values())

        return report


def gate(report: Report, *, min_precision: float, require_full_coverage: bool) -> list[str]:
    """Reasons the run should fail the build. Empty means it passes."""
    reasons = []

    for name, precision in report.below_precision(min_precision):
        reasons.append(f"{name}: precision {precision:.2f} below {min_precision:.2f}")

    for failure in report.failures:
        if failure.kind in {"unknown evaluator", "under-rated"}:
            reasons.append(f"{failure.fixture_id}/{failure.evaluator}: {failure.detail}")

    if require_full_coverage and report.unmeasured:
        reasons.append("no fixtures cover: " + ", ".join(sorted(report.unmeasured)))

    return reasons
