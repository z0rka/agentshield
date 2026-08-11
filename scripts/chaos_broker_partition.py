#!/usr/bin/env python3
"""Cut the broker off mid-scan and check nothing is lost when it comes back.

    python scripts/chaos_broker_partition.py

A killed worker is the easy outage: the process is gone, Kafka rebalances, someone else picks
the work up. A broker that is *unreachable* is harder, because every component stays alive and
believing. The relay keeps writing outbox rows it cannot publish, the worker keeps polling a
socket that answers nothing, and the control plane keeps accepting requests. Nothing crashes,
and that is why the failure can go unnoticed until the queue drains days later.

The transactional outbox exists for this. A scan requested during the partition commits its
row and its event in one transaction; publishing is a separate, retried step. So the claim is:

    an outage delays scans, it does not lose them.

The partition is a real one - `docker network disconnect` on the broker container - and not a
stopped container, because stopping Kafka closes sockets and every client learns immediately.
Disconnecting leaves them hanging, which is the case that finds bugs.

Exit 0 means a scan requested during a broker outage still runs after it heals.
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
    ROOT,
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

#: How long the broker stays unreachable. Long enough that every client has retried and
#: logged, short enough that the consumer group does not need a full session rebuild.
PARTITION_SECONDS = 20.0

#: After the network is restored, the delayed scan gets this long. Generous: the relay backs
#: off exponentially, so the first publish after healing can wait several seconds by design.
HEAL_TIMEOUT = 300.0


def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "infra" / "docker-compose.yml"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _kafka_container() -> str:
    result = _compose("ps", "-q", "kafka")
    container = result.stdout.strip().splitlines()
    if not container:
        raise SmokeFailure("could not find the kafka container; is the stack up?")
    return container[0]


def _networks(container: str) -> list[str]:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
         container],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.split()


def partition_broker(container: str, networks: list[str]) -> None:
    step(8, "Cut the broker off the network")
    for network in networks:
        subprocess.run(
            ["docker", "network", "disconnect", network, container],
            capture_output=True, check=False,
        )
    ok(f"kafka disconnected from {networks}; clients are now hanging, not erroring")


def heal_broker(container: str, networks: list[str]) -> None:
    step(10, "Reconnect the broker")
    for network in networks:
        subprocess.run(
            ["docker", "network", "connect", network, container],
            capture_output=True, check=False,
        )
    ok("kafka reconnected")


def request_scan_during_outage(auth, project_id, target_id, policy_id) -> str:
    """The API must keep working while the broker is unreachable.

    This is the property the outbox buys. If creating a scan needs a live broker, an outage
    turns into a user-visible failure and the whole pattern was pointless.
    """
    step(9, "Request a scan while the broker is unreachable")
    scan_id = run_scan(auth, project_id, target_id, policy_id)

    status, scan = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}", auth=auth)
    if status != 200 or not isinstance(scan, dict):
        raise SmokeFailure(f"scan {scan_id} is not readable during the outage (HTTP {status})")
    ok(f"scan {scan_id} accepted and persisted with the broker down (status {scan['status']})")
    return scan_id


def verify_delivery_after_heal(harness: Harness, auth, scan_id: str) -> None:
    step(11, "Verify the delayed scan runs once the broker is back")

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
        "the delayed scan to finish",
        completed,
        timeout=HEAL_TIMEOUT,
        interval=3.0,
        on_timeout=lambda: (
            "The scan never ran after the broker returned. Its outbox row was written but "
            "never published, so the relay gave up permanently and never retried - an "
            "outage that loses work is the failure the outbox exists to prevent.\n"
            + harness.processes[-1].tail(30)
        ),
    )

    if final.get("status") != "COMPLETED":
        raise SmokeFailure(f"delayed scan ended as {final.get('status')}, not COMPLETED")
    ok("the scan requested during the outage completed after healing")

    status, body = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}/findings", auth=auth)
    if status != 200 or not isinstance(body, list) or not body:
        raise SmokeFailure("the delayed scan produced no findings; it did not really run")

    fingerprints = [f.get("fingerprint") for f in body]
    if len(fingerprints) != len(set(fingerprints)):
        raise SmokeFailure(
            "a fingerprint was written twice. The relay republished after the outage and the "
            "consumer accepted the duplicate, so the report double-counts."
        )
    ok(f"{len(body)} finding(s), none duplicated by the republish")


def main() -> int:
    harness = Harness()
    auth = (DEV_EMAIL, DEV_PASSWORD)
    started = time.monotonic()
    container = ""
    networks: list[str] = []

    print("AgentShield chaos test: broker partitioned mid-flight")
    try:
        java_home = preflight()
        start_infrastructure(harness)
        start_demo_target(harness)
        start_control_plane(harness, java_home)
        start_worker(harness)

        project_id, target_id, policy_id = configure_scan(auth)

        container = _kafka_container()
        networks = _networks(container)
        partition_broker(container, networks)
        try:
            scan_id = request_scan_during_outage(auth, project_id, target_id, policy_id)
            time.sleep(PARTITION_SECONDS)
        finally:
            heal_broker(container, networks)

        verify_delivery_after_heal(harness, auth, scan_id)

        print(f"\nPASSED in {time.monotonic() - started:.0f}s")
        print("a broker outage delays scans, it does not lose them")
        return 0

    except SmokeFailure as failure:
        print(f"\nFAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 1
    finally:
        # Reconnect before teardown even on failure: a container left detached from its network
        # makes `docker compose down` hang, and the next run inherits the mess.
        if container and networks:
            heal_broker(container, networks)
        harness.teardown()


if __name__ == "__main__":
    raise SystemExit(main())
