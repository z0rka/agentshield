"""What this engine instance is doing right now.

Not a source of truth. Scan state lives in the control plane, so any instance can pick up any
scan and losing one takes nothing with it. This registry exists for exactly one reason:
cancellation has to be able to reach a task that is currently executing *here*.

A class over a module-level dict. The dict was shared by the lifespan hook and every
route by import, which made "who may mutate this" unanswerable and left no place to put the
invariants. Here the registry is created once, handed to the app, and the rules - a scan is
registered for exactly the span of its run, cancelling an unknown scan is not an error - live
next to the data.
"""

from __future__ import annotations

from collections.abc import Iterator

from agentshield.graph.state import ScanState


class RunningScans:
    """The scans executing on this instance."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanState] = {}

    def __len__(self) -> int:
        return len(self._scans)

    def __iter__(self) -> Iterator[ScanState]:
        return iter(list(self._scans.values()))

    def __contains__(self, scan_id: object) -> bool:
        return scan_id in self._scans

    def register(self, state: ScanState) -> None:
        self._scans[state.scan_id] = state

    def release(self, scan_id: str) -> None:
        """Forget a finished scan. Idempotent: a double release is not an error."""
        self._scans.pop(scan_id, None)

    def get(self, scan_id: str) -> ScanState | None:
        return self._scans.get(scan_id)

    def cancel(self, scan_id: str) -> bool:
        """Request cooperative cancellation.

        Returns False when the scan is not running here - which is not a failure. It may be on
        another instance, or already finished; the control plane knows which, this instance
        does not.
        """
        state = self._scans.get(scan_id)
        if state is None:
            return False
        state.cancellation.cancel()
        return True

    def cancel_all(self) -> None:
        """Used on shutdown so in-flight scans stop instead of being killed mid-session."""
        for state in list(self._scans.values()):
            state.cancellation.cancel()

    def as_dict(self) -> dict[str, ScanState]:
        """Escape hatch for the Kafka worker, which shares this registry.

        Exposed intentionally and named so it is obvious at the call site that raw access is
        being taken; the worker predates this class and takes a plain mapping.
        """
        return self._scans
