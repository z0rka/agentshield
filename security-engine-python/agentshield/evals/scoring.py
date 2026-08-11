"""Confusion counts and the report built from them."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Confusion:
    """One evaluator's outcomes across the fixture set."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.false_negatives
            + self.true_negatives
        )

    @property
    def precision(self) -> float | None:
        fired = self.true_positives + self.false_positives
        return self.true_positives / fired if fired else None

    @property
    def recall(self) -> float | None:
        expected = self.true_positives + self.false_negatives
        return self.true_positives / expected if expected else None


@dataclass(slots=True)
class Failure:
    """A single disagreement between an evaluator and its label."""

    fixture_id: str
    evaluator: str
    kind: str
    detail: str


@dataclass(slots=True)
class Report:
    """Scores per evaluator, plus what was never measured."""

    confusions: dict[str, Confusion] = field(default_factory=dict)
    failures: list[Failure] = field(default_factory=list)
    unmeasured: set[str] = field(default_factory=set)
    ambiguous: list[str] = field(default_factory=list)
    fixtures_scored: int = 0

    def record(self, evaluator: str) -> Confusion:
        return self.confusions.setdefault(evaluator, Confusion())

    def fail(self, fixture_id: str, evaluator: str, kind: str, detail: str) -> None:
        self.failures.append(Failure(fixture_id, evaluator, kind, detail))

    def below_precision(self, threshold: float) -> list[tuple[str, float]]:
        """Evaluators whose measured precision is under the gate.

        An evaluator with no firing opportunities has no precision and is not reported here;
        it shows up in `unmeasured`, which the gate treats separately. Scoring "never fired"
        as perfect precision is how an evaluator that silently stopped working keeps a green
        build.
        """
        breaches = []
        for name, confusion in sorted(self.confusions.items()):
            precision = confusion.precision
            if precision is not None and precision < threshold:
                breaches.append((name, precision))
        return breaches

    def as_table(self) -> str:
        header = f"{'Evaluator':<34}{'Precision':>10}{'Recall':>9}{'N':>5}"
        lines = [header, "-" * len(header)]
        for name, confusion in sorted(self.confusions.items()):
            lines.append(
                f"{name:<34}"
                f"{_ratio(confusion.precision):>10}"
                f"{_ratio(confusion.recall):>9}"
                f"{confusion.total:>5}"
            )
        return "\n".join(lines)


def _ratio(value: float | None) -> str:
    return "     -" if value is None else f"{value:.2f}"
