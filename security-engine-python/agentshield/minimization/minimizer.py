"""Reducing a reproduction to the part that actually matters.

A finding arrives carrying the payload that produced it: a template-generated prompt of several
sentences and, for indirect injection, a poisoned document of several more. Most of that text
is scaffolding. Whoever picks the ticket up has to read all of it to work out which clause
defeated the control, and that reading is where triage time goes. Minimisation answers the
question mechanically.

It is not free - every candidate is another request to a live agent - so three rules bound it.

**Reproduce the same defect, not any defect.** The oracle matches the finding's fingerprint. A
minimiser that stops at "something is still wrong" hands back a minimal reproduction of a
different bug, which is worse than no minimisation at all because it looks like an answer.

**Spend one budget, shared, worst finding first.** The budget is per scan. A scan with thirty
findings must not become six hundred extra requests against someone's production agent.

**Never trade a working reproduction for a smaller one.** If minimisation is cut short, errors,
or cannot confirm its own result, the original payload stays, `minimized` stays False, and the
note says which of those happened.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass

from agentshield.minimization.ddmin import DEFAULT_PROBE_BUDGET, Reduction, ddmin
from agentshield.minimization.segments import assemble, describe, segment_payload
from agentshield.models.common import Severity
from agentshield.models.finding import Finding
from agentshield.models.scenario import AttackPayload, AttackScenario

log = logging.getLogger(__name__)

#: Runs one scenario against the target and reports the fingerprints of every defect it
#: reproduced. Collapsing "execute" and "judge" into one call keeps this module free of the
#: adapter and the evaluator registry, and makes the oracle testable with a dictionary.
Probe = Callable[[AttackScenario], Awaitable[set[str]]]

#: Floor on a finding's share of the budget. Below roughly this many probes ddmin cannot make
#: even one cut, so a smaller share would spend requests and return the original payload.
_MIN_SHARE = 4


@dataclass(frozen=True, slots=True)
class MinimizationBudget:
    """How much live traffic minimisation is allowed to generate."""

    #: Ceiling for the whole scan, across all findings. A scan of the demo corpus produces
    #: around a dozen severe findings, and a payload of seven segments needs the high teens to
    #: converge - so this is roughly "every severe finding gets a real attempt", and no more.
    total_probes: int = 200
    #: Ceiling for any single finding, so one stubborn payload cannot eat the scan's budget.
    per_finding_probes: int = DEFAULT_PROBE_BUDGET
    #: Findings below this are reported with the full payload. Triage time is spent on the
    #: severe ones, and so is the request budget.
    severity_floor: Severity = Severity.HIGH


class ReproductionMinimizer:
    """Shrinks each finding's reproduction, or explains why it did not."""

    def __init__(self, probe: Probe, budget: MinimizationBudget | None = None) -> None:
        self._probe = probe
        self._budget = budget or MinimizationBudget()
        self._spent = 0

    @property
    def probes_spent(self) -> int:
        return self._spent

    async def minimize_all(
        self, findings: Iterable[Finding], scenarios: Iterable[AttackScenario]
    ) -> None:
        """Minimise in descending severity, in place.

        The budget is shared out, not served first-come. Left to itself, one stubborn
        payload converges slowly, spends the entire scan allowance, and every finding after it
        is reported unminimised - which reads as if minimisation were broken. Each eligible
        finding therefore gets an equal share of whatever is left when its turn comes, and the
        savings from an easy one flow to those behind it.
        """
        by_id = {scenario.id: scenario for scenario in scenarios}
        ordered = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
        pairs = [(f, by_id.get(f.reproduction.scenario_id)) for f in ordered]
        awaiting = sum(1 for f, s in pairs if self._ineligible(f, s) is None)

        for finding, scenario in pairs:
            share = None
            if self._ineligible(finding, scenario) is None and awaiting > 0:
                share = max(self._remaining() // awaiting, _MIN_SHARE)
                awaiting -= 1
            await self.minimize(finding, scenario, cap=share)

    async def minimize(
        self, finding: Finding, scenario: AttackScenario | None, *, cap: int | None = None
    ) -> None:
        """Minimise one finding's reproduction, in place, or record why it was skipped."""
        refusal = self._why_not(finding, scenario)
        if refusal is not None:
            finding.reproduction.note = refusal
            return

        assert scenario is not None  # _why_not rejects None
        try:
            await self._reduce(finding, scenario, cap)
        except Exception as exc:  # noqa: BLE001 - a failed optimisation must not fail the scan
            log.warning("minimisation of %s failed: %s", finding.code or finding.id, exc)
            finding.reproduction.minimized = False
            finding.reproduction.note = f"minimisation aborted: {type(exc).__name__}"

    def _ineligible(self, finding: Finding, scenario: AttackScenario | None) -> str | None:
        """Reasons that do not depend on how much budget is left."""
        if scenario is None:
            return "originating scenario is not available in this run"
        if not finding.severity.at_least(self._budget.severity_floor):
            return f"severity below the {self._budget.severity_floor} minimisation floor"
        if not finding.confirmed_deterministically:
            # Only deterministic evaluators drive the oracle, so a judge-only finding could
            # never be observed again and every probe spent on it would be wasted.
            return "no deterministic evaluator confirmed this finding"
        return None

    def _why_not(self, finding: Finding, scenario: AttackScenario | None) -> str | None:
        static = self._ineligible(finding, scenario)
        if static is not None:
            return static
        if self._remaining() <= 1:
            return "scan-wide minimisation budget is spent"
        return None

    async def _reduce(self, finding: Finding, scenario: AttackScenario, cap: int | None) -> None:
        segments = segment_payload(scenario.payload)
        if len(segments) < 2:
            finding.reproduction.note = "payload is a single segment"
            return

        # One probe is reserved for the confirmation run below, which is what lets
        # `minimized=True` always mean "observed to reproduce", never "inferred to".
        budget = min(
            self._budget.per_finding_probes,
            cap if cap is not None else self._budget.per_finding_probes,
            self._remaining() - 1,
        )

        async def oracle(candidate: frozenset[int]) -> bool:
            return await self._reproduces(
                finding, scenario, assemble(scenario.payload, segments, candidate)
            )

        reduction = await ddmin(len(segments), oracle, budget=budget)
        finding.reproduction.probes = reduction.probes

        if not reduction.removed:
            # Nothing came off. Converged means the payload is genuinely 1-minimal; out of
            # budget means nothing at all was established, and saying otherwise would dress a
            # budget shortfall up as a result.
            finding.reproduction.minimized = reduction.one_minimal
            finding.reproduction.note = (
                "every segment is load-bearing; the payload is already minimal"
                if reduction.one_minimal
                else f"probe budget reached after {reduction.probes} probe(s), nothing removed"
            )
            return

        reduced = assemble(scenario.payload, segments, reduction.kept)
        finding.reproduction.probes = reduction.probes + 1
        if not await self._reproduces(finding, scenario, reduced):
            # Either the reduction was luck against a stochastic agent, or the target changed
            # behaviour mid-scan. Either way the long payload is the one known to work.
            finding.reproduction.note = (
                f"reduced payload did not reproduce on confirmation after "
                f"{reduction.probes} probe(s); keeping the full payload"
            )
            return

        finding.reproduction.prompt = reduced.prompt
        finding.reproduction.injections = [a.model_dump() for a in reduced.injections]
        finding.reproduction.minimized = True
        finding.reproduction.note = _note(describe(segments, reduction.kept), reduction)

    async def _reproduces(
        self, finding: Finding, scenario: AttackScenario, payload: AttackPayload
    ) -> bool:
        self._spent += 1
        candidate = scenario.model_copy(update={"payload": payload})
        return finding.fingerprint in await self._probe(candidate)

    def _remaining(self) -> int:
        return max(self._budget.total_probes - self._spent, 0)


def _note(summary: str, reduction: Reduction) -> str:
    if reduction.exhausted:
        return f"{summary}; probe budget reached first, so a smaller payload may exist"
    if reduction.one_minimal:
        return f"{summary}; no further single segment can be removed"
    return summary
