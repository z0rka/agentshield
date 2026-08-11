"""Delta debugging over an indexed list of removable units.

Zeller and Hildebrandt's ddmin, unchanged in shape. The algorithm is textbook; what matters
here is the contract around it.

**The oracle decides what "still fails" means, and that choice is the whole design.** A
minimiser whose oracle answers "something went wrong" will cheerfully reduce a prompt-injection
payload down to a string that trips a different control, then present the result as a minimal
reproduction of the original finding. `minimizer.py` therefore matches on a fingerprint.

**The guarantee is 1-minimality**, not global minimality: no single remaining unit can be
dropped without losing the failure. A smaller subset removing two units at once may well
exist. Claiming more than 1-minimality would be a lie about a result that cost N live requests.

This module knows nothing about attacks, payloads or HTTP. It takes a count and a coroutine.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

#: Answers "does the input restricted to these unit indices still trigger the same failure?"
Oracle = Callable[[frozenset[int]], Awaitable[bool]]

#: Enough to converge on a payload of ten or so segments, small enough that a scan does not
#: quietly turn into a load test against someone's agent.
DEFAULT_PROBE_BUDGET = 24


@dataclass(frozen=True, slots=True)
class Reduction:
    """What survived, and how much confidence the result carries."""

    #: Indices kept, ascending.
    kept: tuple[int, ...]
    #: Units the caller started with.
    total: int
    #: Oracle calls actually made. Cache hits are free and are not counted.
    probes: int
    #: No single kept unit can be removed. False when the budget ran out first.
    one_minimal: bool
    #: The budget was reached before the algorithm converged.
    exhausted: bool

    @property
    def removed(self) -> int:
        return self.total - len(self.kept)


class _BudgetExhausted(Exception):
    """Internal signal: stop and keep the best candidate found so far."""


class _ProbeLimit:
    """Counts, caps and caches oracle calls.

    The cache is not a micro-optimisation. ddmin re-tests identical candidates whenever the
    granularity changes, and against a live agent every repeat is another request, another few
    cents, and - because agents are not deterministic - another chance of a different answer to
    a question already asked. Answering it once keeps the reduction reproducible.
    """

    def __init__(self, oracle: Oracle, budget: int) -> None:
        self._oracle = oracle
        self._budget = budget
        self._answered: dict[frozenset[int], bool] = {}
        self.used = 0

    async def __call__(self, candidate: frozenset[int]) -> bool:
        if candidate in self._answered:
            return self._answered[candidate]
        if self.used >= self._budget:
            raise _BudgetExhausted
        self.used += 1
        verdict = await self._oracle(candidate)
        self._answered[candidate] = verdict
        return verdict


async def ddmin(
    unit_count: int,
    oracle: Oracle,
    *,
    budget: int = DEFAULT_PROBE_BUDGET,
) -> Reduction:
    """Find a 1-minimal subset of `range(unit_count)` that the oracle still calls failing.

    The caller must already know the full set fails. ddmin never tests it, and never grows a
    candidate: the result is always a subset of what it was given.
    """
    if unit_count <= 1:
        kept = tuple(range(max(unit_count, 0)))
        return Reduction(
            kept=kept, total=len(kept), probes=0, one_minimal=True, exhausted=False
        )

    probe = _ProbeLimit(oracle, budget)
    kept = list(range(unit_count))
    granularity = 2
    one_minimal = False
    exhausted = False

    try:
        while True:
            if len(kept) < 2:
                # A single unit that cannot be split is 1-minimal by definition.
                one_minimal = True
                break

            chunks = _partition(kept, granularity)

            # Phase 1: can one chunk alone carry the failure? The big win, when it lands.
            narrowed = await _first_failing(probe, [frozenset(chunk) for chunk in chunks])
            if narrowed is not None:
                kept = sorted(narrowed)
                granularity = 2
                continue

            # Phase 2: can any single chunk be dropped? Smaller steps, but they compose.
            whole = frozenset(kept)
            narrowed = await _first_failing(probe, [whole - frozenset(c) for c in chunks])
            if narrowed is not None:
                kept = sorted(narrowed)
                granularity = max(granularity - 1, 2)
                continue

            if granularity >= len(kept):
                # Chunks are single units and neither phase removed one: nothing left to drop.
                one_minimal = True
                break

            granularity = min(granularity * 2, len(kept))
    except _BudgetExhausted:
        exhausted = True

    return Reduction(
        kept=tuple(kept),
        total=unit_count,
        probes=probe.used,
        one_minimal=one_minimal,
        exhausted=exhausted,
    )


async def _first_failing(
    probe: _ProbeLimit, candidates: Sequence[frozenset[int]]
) -> frozenset[int] | None:
    """The first candidate the oracle still calls failing, or None if none do."""
    for candidate in candidates:
        if candidate and await probe(candidate):
            return candidate
    return None


def _partition(items: list[int], parts: int) -> list[list[int]]:
    """Split into `parts` near-equal chunks, largest first. Empty chunks are dropped."""
    size, remainder = divmod(len(items), parts)
    chunks: list[list[int]] = []
    start = 0
    for index in range(parts):
        end = start + size + (1 if index < remainder else 0)
        if end > start:
            chunks.append(items[start:end])
        start = end
    return chunks
