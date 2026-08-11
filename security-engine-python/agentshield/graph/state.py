"""Scan state carried through the graph.

One mutable object threaded through every node. It is intentionally not the source of truth:
the control plane owns scan status in PostgreSQL, and this state is the engine's working copy
for a single execution. If the worker dies mid-scan, this is discarded and rebuilt from the
control plane's record of which scenarios already completed.
"""

from __future__ import annotations

import asyncio
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentshield.adapters.base import BaseTargetAdapter, TargetCapabilities
from agentshield.attacks.catalog import AttackCatalog
from agentshield.attacks.selection import ThreatModel
from agentshield.evaluators.pricing import JudgeUsage
from agentshield.minimization import MinimizationBudget
from agentshield.models.common import AttackCategory, RunStatus, Severity
from agentshield.models.finding import EvaluationResult, Finding, ScanSummary
from agentshield.models.policy import SecurityPolicy
from agentshield.models.scenario import AttackScenario, RunContext
from agentshield.models.trajectory import Trajectory


@dataclass(slots=True)
class ScenarioExecution:
    """The outcome of running one scenario, before evaluation."""

    scenario: AttackScenario
    status: RunStatus = RunStatus.PENDING
    trajectory: Trajectory | None = None
    session_id: str | None = None
    error: str | None = None
    attempts: int = 1
    duration_seconds: float = 0.0

    @property
    def evaluable(self) -> bool:
        """Only a completed run with a trajectory can be judged.

        A timeout still produces findings (unbounded consumption), but through the budget
        path and not the evaluator path.
        """
        return self.trajectory is not None and self.status in {
            RunStatus.SUCCESS,
            RunStatus.BUDGET_EXCEEDED,
            RunStatus.TIMEOUT,
        }


class CancellationToken:
    """Cooperative cancellation, pollable and awaitable.

    Set by the control plane through the engine's `/scans/{id}/cancel` endpoint. Two ways to
    observe it, because the pipeline needs both:

    * `cancelled` for the checks between scenarios, where the next unit of work simply is not
      started;
    * `wait()` for the checks *during* one, where a request is already in flight.

    The second exists because polling alone made cancellation almost useless. A scenario can
    sit in `send_input` for the whole scenario timeout, and with the default concurrency ten of
    them can be doing it at once, so "cancel" meant "stop starting new work and then wait a
    minute". Racing the adapter call against this event ends the request instead.

    Cancellation can arrive on a different thread from the loop running the scan - the API
    process and the worker are not the same shape - so the threading primitive stays
    authoritative and the asyncio one is woken through the loop that owns it.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._async_event: asyncio.Event | None = None

    def cancel(self) -> None:
        self._event.set()
        with self._lock:
            loop, event = self._loop, self._async_event
        if loop is not None and event is not None:
            # `call_soon_threadsafe` is the only safe way to touch an asyncio.Event from
            # outside its loop; setting it directly loses the wakeup silently.
            with suppress(RuntimeError):  # loop already closed: nothing left to wake
                loop.call_soon_threadsafe(event.set)

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        """Block until cancelled, binding to the running loop on first use."""
        with self._lock:
            if self._async_event is None:
                self._loop = asyncio.get_running_loop()
                self._async_event = asyncio.Event()
                if self._event.is_set():
                    # Cancelled before anyone waited. Checked inside the lock so a cancel
                    # racing this bind cannot slip between the two.
                    self._async_event.set()
            event = self._async_event
        await event.wait()


@dataclass(slots=True)
class ScanState:
    """Everything one scan execution needs and produces."""

    scan_id: str
    policy: SecurityPolicy
    target_config: dict[str, Any]
    correlation_id: str = ""
    #: Where the policy was loaded from, when it was a file. The scan itself needs only the
    #: parsed object, but a reproduction command needs something a reader can pass to
    #: `--policy`, and neither the object nor its hash is that. Empty when the policy arrived
    #: from the control plane, where no path exists on the machine running the replay.
    policy_source: str = ""

    # -- configuration ---------------------------------------------------------
    requested_categories: set[AttackCategory] | None = None
    max_scenarios: int = 50
    variants_per_template: int = 1
    base_seed: int = 0
    concurrency: int = 10
    scenario_timeout_seconds: float = 60.0
    max_attempts: int = 2
    run_semantic_evaluators: bool = False
    #: Delta-debug each severe finding's payload down to the part that still triggers it.
    #: Costs live target calls, bounded by `minimization_budget`.
    minimize_reproductions: bool = True
    minimization_budget: MinimizationBudget = field(default_factory=MinimizationBudget)

    # -- runtime ---------------------------------------------------------------
    adapter: BaseTargetAdapter | None = None
    #: Override for the semantic evaluators' backend. Left unset a scan talks to the real API;
    #: a replay cassette here is how tests exercise the judge path without spending anything.
    judge_client: Any | None = None
    #: Token and cost accounting for semantic evaluation. Stays at zero when judges are off,
    #: which is the normal case and is what the report should then say.
    judge_usage: JudgeUsage = field(default_factory=JudgeUsage)
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    capabilities: TargetCapabilities | None = None
    threat_model: ThreatModel | None = None
    catalog: AttackCatalog | None = None
    run_context: RunContext | None = None

    # -- accumulated results ---------------------------------------------------
    scenarios: list[AttackScenario] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    executions: list[ScenarioExecution] = field(default_factory=list)
    results: list[tuple[AttackScenario, EvaluationResult]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: ScanSummary | None = None

    # -- control flow ----------------------------------------------------------
    #: Routing signal read by the conditional edge after execute_attack.
    outcome: str = "pending"
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def note_error(self, message: str) -> None:
        """Record a non-fatal problem. Surfaced in the report as reduced coverage."""
        self.errors.append(message)

    @property
    def executed(self) -> list[ScenarioExecution]:
        return [e for e in self.executions if e.evaluable]

    @property
    def errored(self) -> list[ScenarioExecution]:
        return [e for e in self.executions if e.status is RunStatus.TARGET_ERROR]

    def violations(self) -> list[tuple[AttackScenario, EvaluationResult]]:
        return [(s, r) for s, r in self.results if r.violated]

    def worst_severity(self) -> Severity:
        return max(
            (f.severity for f in self.findings),
            key=lambda s: s.rank,
            default=Severity.INFO,
        )
