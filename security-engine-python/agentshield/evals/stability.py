"""Repeated sampling for evaluators that do not give the same answer twice.

A deterministic evaluator is scored once because a second run cannot disagree with the first.
An LLM judge can, so a single run tells you its verdict and nothing about whether that verdict
is reliable. A judge that fires on six runs out of ten is not "60% right"; it is unusable on
that case, and averaging it into a precision figure hides exactly that.

So judges are sampled N times per fixture and reported on two axes: what the majority said,
and how often the minority disagreed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean


@dataclass(slots=True)
class Sample:
    """How one evaluator behaved across repeated runs of one fixture."""

    fixture_id: str
    evaluator: str
    runs: int = 0
    fired: int = 0
    skipped: int = 0

    @property
    def usable_runs(self) -> int:
        return self.runs - self.skipped

    @property
    def fire_rate(self) -> float | None:
        return self.fired / self.usable_runs if self.usable_runs else None

    @property
    def majority_fired(self) -> bool | None:
        rate = self.fire_rate
        return None if rate is None else rate > 0.5

    @property
    def agreement(self) -> float | None:
        """How lopsided the runs were: 1.0 is unanimous, 0.5 is a coin flip."""
        rate = self.fire_rate
        return None if rate is None else max(rate, 1.0 - rate)

    @property
    def flipped(self) -> bool:
        return 0 < self.fired < self.usable_runs


@dataclass(slots=True)
class StabilityReport:
    samples: list[Sample] = field(default_factory=list)
    runs_per_fixture: int = 0

    def for_evaluator(self, evaluator: str) -> list[Sample]:
        return [s for s in self.samples if s.evaluator == evaluator]

    def evaluators(self) -> list[str]:
        return sorted({s.evaluator for s in self.samples})

    def unavailable(self) -> list[str]:
        """Evaluators that never produced a verdict on any fixture.

        Reported separately and never as stable. A judge with no credentials skips every run,
        and "skipped ten times out of ten" would otherwise compute as perfect agreement.
        """
        return [
            name
            for name in self.evaluators()
            if all(sample.usable_runs == 0 for sample in self.for_evaluator(name))
        ]

    def agreement(self, evaluator: str) -> float | None:
        rates = [
            sample.agreement
            for sample in self.for_evaluator(evaluator)
            if sample.agreement is not None
        ]
        return mean(rates) if rates else None

    def flipped(self, evaluator: str) -> list[Sample]:
        return [sample for sample in self.for_evaluator(evaluator) if sample.flipped]

    def as_table(self) -> str:
        header = f"{'Evaluator':<30}{'Agreement':>11}{'Flipped':>9}{'Cases':>7}"
        lines = [header, "-" * len(header)]
        for name in self.evaluators():
            agreement = self.agreement(name)
            lines.append(
                f"{name:<30}"
                f"{'          -' if agreement is None else f'{agreement:>11.2f}'}"
                f"{len(self.flipped(name)):>9}"
                f"{len(self.for_evaluator(name)):>7}"
            )
        return "\n".join(lines)


def gate_stability(
    report: StabilityReport, *, min_agreement: float
) -> list[str]:
    """Reasons a judge should not be trusted yet. Empty means it may be enabled."""
    reasons = []

    for name in report.unavailable():
        reasons.append(f"{name}: never produced a verdict, so nothing was measured")

    for name in report.evaluators():
        if name in report.unavailable():
            continue
        agreement = report.agreement(name)
        if agreement is not None and agreement < min_agreement:
            flipped = ", ".join(sample.fixture_id for sample in report.flipped(name)[:4])
            reasons.append(
                f"{name}: agreement {agreement:.2f} below {min_agreement:.2f}"
                + (f" (flipped on {flipped})" if flipped else "")
            )

    return reasons
