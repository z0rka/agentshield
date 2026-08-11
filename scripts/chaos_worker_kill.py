#!/usr/bin/env python3
"""Kill the worker mid-scan and check the scan still finishes exactly once.

    python scripts/chaos_worker_kill.py

The architecture makes a specific durability claim:

    A worker commits the request offset only after publishing its result stream, so a killed
    worker receives the request again. Event ids and database constraints make that replay
    idempotent.

`EventReplayChaosIT` proves the second sentence against a real database, by handing the
consumer the same events twice. It cannot prove the first, because the offset commit is a Kafka
behaviour and that test has no Kafka. This script is where the sentence is settled: a real
broker, a real worker, and `taskkill /F` in the middle of a scan.

Two failures are possible and they are opposites, so both are asserted:

* **work lost** - the replacement worker never receives the scan, and it sits unfinished
  forever while a CI job waits on it;
* **work duplicated** - the replay lands a second copy of every finding, and the report
  double-counts a system that has one defect.

A third outcome would be worse than either: the scan completing because the first worker had
already finished before the kill landed. That proves nothing at all, so the run refuses rather
than reporting a pass it did not earn.

Exit 0 means a killed worker costs nothing but time.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from smoke_multiprocess import (
    CONTROL_PLANE,
    DEV_EMAIL,
    DEV_PASSWORD,
    IS_WINDOWS,
    Harness,
    SmokeFailure,
    configure_scan,
    ok,
    preflight,
    request,
    run_scan,
    start_control_plane,
    start_demo_target,
    start_infrastructure,
    start_worker,
    step,
    wait_for,
)

#: How long to wait for the worker to pick the scan up before giving up on the experiment. The
#: scan itself takes far longer than this; the point is only to catch it in flight.
PICKUP_TIMEOUT = 90.0

#: After the replacement worker starts, the replayed scan gets this long to finish. Generous:
#: a rebalance has to happen before it sees anything, and a flaky timeout here would look like
#: lost work when it is only a slow consumer group.
RECOVERY_TIMEOUT = 300.0


def wait_until_running(harness: Harness, auth: tuple[str, str], scan_id: str) -> None:
    """Block until the worker has actually taken the scan, not merely been sent it."""
    step(8, "Wait for the worker to pick the scan up")

    def running() -> bool:
        status, scan = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}", auth=auth)
        if status != 200 or not isinstance(scan, dict):
            return False
        state = scan.get("status")
        if state in {"COMPLETED", "FAILED", "CANCELLED"}:
            # Killing a worker that already finished tests nothing, and reporting that as a
            # pass is the failure this script exists to avoid making.
            raise SmokeFailure(
                f"scan reached {state} before it could be interrupted; the experiment did not "
                "run. Re-run, or widen the corpus so the scan takes longer than the pickup."
            )
        return state in {"RUNNING", "DISCOVERING", "EVALUATING"}

    wait_for("the scan to reach RUNNING", running, timeout=PICKUP_TIMEOUT, interval=1.0)
    ok("worker is mid-scan")


def kill_worker(harness: Harness) -> None:
    """Terminate the worker the way a crash would: no shutdown hook, no offset commit."""
    step(9, "Kill the worker")

    worker = next(p for p in harness.processes if p.name == "worker")
    if IS_WINDOWS:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(worker.process.pid)],
            capture_output=True,
            check=False,
        )
    else:
        worker.process.kill()
    worker.process.wait(timeout=30)

    # Removed from the harness so teardown does not try to kill it again, and so the restart
    # below appends a fresh entry and does not shadow a dead one.
    harness.processes.remove(worker)
    ok(f"worker killed (pid {worker.process.pid}), offset never committed")


def restart_worker(harness: Harness) -> None:
    step(10, "Start a replacement worker")
    start_worker(harness)


def verify_replay_happened(harness: Harness, scan_id: str) -> None:
    """The replacement must have taken the scan itself, not inherited a finished one.

    Without this the script passes in precisely the case it exists to reject: the first worker
    completes and commits between the status check and the kill landing, the scan is already
    done, and every later assertion is satisfied by work the crash never touched. "Completed"
    and "recovered" look identical from the outside; only the replacement's own log separates
    them.

    Reading `worker.log` works because `Harness.spawn` opens it with "w", so the restart
    truncated the dead worker's output and anything here belongs to the replacement.
    """
    replacement = harness.processes[-1]
    log = replacement.log_path.read_text(encoding="utf-8", errors="replace")

    if f"scan {scan_id} accepted" not in log:
        raise SmokeFailure(
            "the replacement worker never accepted the scan, so nothing was replayed and this "
            "run proves nothing about recovery. Either the first worker finished before the "
            "kill landed, or the offset was committed early and the work was silently dropped."
        )
    ok("replacement worker accepted the scan: the replay genuinely happened")


def verify_recovery(harness: Harness, auth: tuple[str, str], scan_id: str) -> dict:
    """The scan must finish, and finish once."""
    step(11, "Verify the replayed scan completes exactly once")

    final: dict = {}

    def completed() -> bool:
        status, scan = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}", auth=auth)
        if status != 200 or not isinstance(scan, dict):
            return False
        if scan.get("status") in {"COMPLETED", "FAILED", "CANCELLED"}:
            final.update(scan)
            return True
        return False

    wait_for(
        "the replayed scan to reach a terminal state",
        completed,
        timeout=RECOVERY_TIMEOUT,
        interval=3.0,
        on_timeout=lambda: (
            "The scan never finished after the worker was replaced. Work was lost: the offset "
            "was committed before the results were published, or the replacement never joined "
            "the consumer group.\n" + harness.processes[-1].tail(30)
        ),
    )

    if final.get("status") != "COMPLETED":
        raise SmokeFailure(f"scan ended as {final.get('status')}, not COMPLETED")
    ok(f"scan reached COMPLETED after the kill (status {final['status']})")
    return final


def verify_no_duplicates(auth: tuple[str, str], scan_id: str) -> None:
    """Replay must not double-count. This is the half a restart is most likely to break."""
    status, body = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}/findings", auth=auth)
    if status != 200 or not isinstance(body, list):
        raise SmokeFailure(f"could not read findings: HTTP {status}")

    fingerprints = [f.get("fingerprint") for f in body]
    duplicated = {f for f in fingerprints if fingerprints.count(f) > 1}
    if duplicated:
        raise SmokeFailure(
            f"{len(duplicated)} fingerprint(s) appear more than once after the replay: "
            f"{sorted(duplicated)[:5]}. The scan was reprocessed and the findings were "
            "written twice, so every count in the report is inflated."
        )

    codes = [f.get("code") for f in body]
    if len(codes) != len(set(codes)):
        raise SmokeFailure("two findings share a code after the replay")

    ok(f"{len(body)} finding(s), no fingerprint written twice")


def main() -> int:
    harness = Harness()
    auth = (DEV_EMAIL, DEV_PASSWORD)
    started = time.monotonic()

    print("AgentShield chaos test: worker killed mid-scan")
    try:
        java_home = preflight()
        start_infrastructure(harness)
        start_demo_target(harness)
        start_control_plane(harness, java_home)
        start_worker(harness)

        project_id, target_id, policy_id = configure_scan(auth)
        scan_id = run_scan(auth, project_id, target_id, policy_id)

        wait_until_running(harness, auth, scan_id)
        kill_worker(harness)
        restart_worker(harness)

        verify_recovery(harness, auth, scan_id)
        verify_replay_happened(harness, scan_id)
        verify_no_duplicates(auth, scan_id)

        print(f"\nPASSED in {time.monotonic() - started:.0f}s")
        print("a killed worker costs time, not work")
        return 0

    except SmokeFailure as failure:
        print(f"\nFAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 1
    finally:
        harness.teardown()


if __name__ == "__main__":
    raise SystemExit(main())
