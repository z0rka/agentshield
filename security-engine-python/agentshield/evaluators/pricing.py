"""What a judge call costs, and the accounting that follows it.

A scan that spends money must say how much. Not because the amounts are large - a judged scan
of this corpus is cents - but because a number nobody reports is a number nobody budgets, and
"enable the judges" is a decision someone has to be able to cost before making it.

**List price only.** Introductory and negotiated rates exist and expire; encoding one would
produce an estimate that silently understates the bill the month it lapses. An estimate that
is plainly conservative is useful. One that is sometimes right is not.

**Replayed calls cost nothing, and are reported as nothing.** A cassette run shows 0 spend
against a real call count, which is the honest description of what happened - see
`agentshield.evaluators.cassette`.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Model id -> (input $/MTok, output $/MTok), published list price.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Cost in dollars, or 0.0 for a model with no published price recorded here.

    Zero for an unknown model is deliberate: guessing at a price produces a number that looks
    authoritative and is not, and the token counts are reported alongside it either way.
    """
    prices = PRICES.get(model)
    if prices is None:
        return 0.0
    per_input, per_output = prices
    return input_tokens * per_input / 1_000_000 + output_tokens * per_output / 1_000_000


@dataclass
class JudgeUsage:
    """Running total for one scan's semantic evaluation.

    Mutable and accumulated by the client, not returned per call, because the judge
    interface returns the model's answer and threading a usage tuple back through every
    evaluator would put accounting in twelve places that do not care about it.
    """

    model: str = ""
    calls: int = 0
    #: Calls answered from a cassette. Counted, and free.
    replayed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def estimated_cost_usd(self) -> float:
        return estimate_cost(self.model, self.input_tokens, self.output_tokens)

    @property
    def priced(self) -> bool:
        """Whether the spend below can be converted to money at all.

        False means tokens were consumed under a model with no price here - including the
        empty model, which is a wiring bug and not a new release. Either way the number
        to print is "unknown", never "$0.00": a zero next to fifteen thousand tokens reads as
        "this was free", and that is the one thing it definitely was not.
        """
        return self.model in PRICES

    def record(self, *, input_tokens: int, output_tokens: int) -> None:
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

    def record_replay(self) -> None:
        self.calls += 1
        self.replayed += 1

    def describe(self) -> str:
        """One line for the report."""
        if not self.calls:
            return "judges did not run"
        if self.replayed == self.calls:
            return f"{self.calls} judge call(s), all replayed from cassette, $0.00"
        live = self.calls - self.replayed
        cost = (
            f"${self.estimated_cost_usd:.4f} at list price"
            if self.priced
            else f"cost unknown (no published price for {self.model or '<unset>'})"
        )
        return (
            f"{self.calls} judge call(s) on {self.model or '<unset>'} ({live} live, "
            f"{self.replayed} replayed), {self.input_tokens} in / {self.output_tokens} out, "
            f"{cost}"
        )
