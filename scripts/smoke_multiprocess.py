#!/usr/bin/env python3
"""Multi-process smoke test: the whole distributed path, for real.

    python scripts/smoke_multiprocess.py

Every other test in this repository stubs at least one boundary. The Python end-to-end tests
drive the pipeline in-process; the Java integration tests assert what lands in the outbox and
stop there. Both are correct and neither proves the claim the architecture actually makes:

    POST /api/projects/{id}/scans
      -> scan row + outbox entry in one transaction
      -> OutboxRelay publishes to Kafka
      -> Python worker consumes security.scan.created
      -> worker pulls policy + decrypted credentials over the internal endpoint
      -> LangGraph executes attacks against a live target over HTTP
      -> worker publishes findings and lifecycle events back to Kafka
      -> control plane consumes them idempotently
      -> scan reaches COMPLETED with findings and trajectory persisted

Each hop has its own failure mode, and the interesting ones only appear when the processes are
genuinely separate: a serialiser mismatch, a topic name typo, an event the consumer silently
drops, a credential that never reaches the worker. This script is what catches those.

Exit code 0 means the chain works end to end.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "artifacts" / "smoke"

CONTROL_PLANE = "http://127.0.0.1:8080"
JAEGER_QUERY = "http://127.0.0.1:16686"

#: OTel service names, which are what Jaeger groups spans by. They must match
#: `spring.application.name` and the engine's `OTEL_SERVICE_NAME`, or the join check looks for
#: services that do not exist and reports a failure that is really a typo here.
CONTROL_PLANE_SERVICE = "agentshield-control-plane"
ENGINE_SERVICE = "agentshield-security-engine"

DEMO_TARGET_PORT = 8090
DEMO_TARGET_URL = f"http://127.0.0.1:{DEMO_TARGET_PORT}"

# Must match DevDataSeeder. Deterministic so this script never scrapes a log line.
DEV_EMAIL = "engineer@company.test"
DEV_PASSWORD = "agentshield-dev"
INTERNAL_TOKEN = "smoke-internal-token"
CANARY = "AGENTSHIELD_SECRET_7F93A"

# 32 zero bytes: a throwaway AES key for a throwaway database.
CREDENTIAL_KEY = base64.b64encode(bytes(32)).decode()

IS_WINDOWS = os.name == "nt"


class SmokeFailure(RuntimeError):
    """A step of the chain did not work."""


# ---------------------------------------------------------------------------------
# process and output plumbing
# ---------------------------------------------------------------------------------


@dataclass
class Managed:
    """A child process plus the log file its output is streaming into."""

    name: str
    process: subprocess.Popen
    log_path: Path

    def alive(self) -> bool:
        return self.process.poll() is None

    def tail(self, lines: int = 30) -> str:
        if not self.log_path.is_file():
            return "(no output)"
        content = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])


@dataclass
class Harness:
    processes: list[Managed] = field(default_factory=list)
    compose_started: bool = False
    keep_running: bool = False

    def spawn(self, name: str, command: list[str], *, cwd: Path, env: dict[str, str]) -> Managed:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / f"{name}.log"
        handle = log_path.open("w", encoding="utf-8")
        # New process group so teardown can signal the whole tree: Gradle forks a daemon and a
        # bootRun child, and killing only the launcher leaves the JVM holding port 8080.
        creation = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
        popen = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            creationflags=creation,
            start_new_session=not IS_WINDOWS,
        )
        managed = Managed(name=name, process=popen, log_path=log_path)
        self.processes.append(managed)
        return managed

    def teardown(self) -> None:
        if self.keep_running:
            print("\n--keep-running: leaving processes and containers up")
            for managed in self.processes:
                print(f"  {managed.name}: pid {managed.process.pid}, log {managed.log_path}")
            return

        for managed in reversed(self.processes):
            if not managed.alive():
                continue
            try:
                if IS_WINDOWS:
                    # taskkill /T reaches the Gradle daemon and the forked JVM; terminate()
                    # alone only stops the launcher and leaves the port bound.
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(managed.process.pid)],
                        capture_output=True,
                        check=False,
                    )
                else:
                    os.killpg(os.getpgid(managed.process.pid), signal.SIGTERM)
                managed.process.wait(timeout=20)
            except Exception:  # noqa: BLE001 - teardown must never mask the real failure
                managed.process.kill()

        if self.compose_started:
            subprocess.run(
                ["docker", "compose", "-f", str(ROOT / "infra" / "docker-compose.yml"),
                 "down", "-v", "--remove-orphans"],
                capture_output=True,
                check=False,
            )


def step(number: int, title: str) -> None:
    print(f"\n[{number}] {title}")
    sys.stdout.flush()


def ok(message: str) -> None:
    print(f"    OK  {message}")
    sys.stdout.flush()


# ---------------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------------


def request(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict | list | None]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = response.read()
            return response.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as error:
        payload = error.read()
        try:
            return error.code, json.loads(payload) if payload else None
        except json.JSONDecodeError:
            return error.code, {"raw": payload.decode(errors="replace")}


def wait_for(
    description: str,
    check,
    *,
    timeout: float,
    interval: float = 2.0,
    on_timeout=None,
) -> None:
    """Poll `check` until it returns truthy, or fail with context.

    Polling over sleeping a fixed amount: JVM startup on a cold Gradle cache is wildly
    variable, and a fixed sleep is either flaky or slow. It is never both right.
    """
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(interval)

    detail = on_timeout() if on_timeout else ""
    raise SmokeFailure(
        f"timed out after {timeout:g}s waiting for {description}"
        + (f"\n  last error: {last_error}" if last_error else "")
        + (f"\n{detail}" if detail else "")
    )


# ---------------------------------------------------------------------------------
# steps
# ---------------------------------------------------------------------------------


#: Every port this test needs to own. Anything already listening here belongs to something
#: else, and the test would talk to it, not to the stack it started.
REQUIRED_PORTS = {
    5432: "PostgreSQL",
    9092: "Kafka",
    8080: "control plane",
    DEMO_TARGET_PORT: "demo target",
}


def _port_is_free(port: int) -> bool:
    import socket

    with socket.socket() as probe:
        probe.settimeout(1.0)
        return probe.connect_ex(("127.0.0.1", port)) != 0


def _check_ports() -> None:
    """Fail immediately when a port is taken.

    Learned the hard way: another project's PostgreSQL held 5432, compose started its own
    container without publishing the port, and the control plane spent six minutes failing to
    authenticate against a database that was never ours. A conflict has to be named at second
    zero, not diagnosed from a stack trace later.
    """
    taken = [f"{port} ({role})" for port, role in sorted(REQUIRED_PORTS.items())
             if not _port_is_free(port)]
    if taken:
        raise SmokeFailure(
            "these ports are already in use: " + ", ".join(taken)
            + "\n  Stop whatever owns them, or the test will drive the wrong process."
            + "\n  `docker ps --format '{{.Names}}\\t{{.Ports}}'` shows the usual culprits."
        )


def preflight() -> Path:
    step(1, "Preflight")

    if shutil.which("docker") is None:
        raise SmokeFailure("docker is not on PATH")
    probe = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=60, check=False)
    if probe.returncode != 0:
        raise SmokeFailure(f"docker is not running: {probe.stderr.strip()[:200]}")
    ok(f"docker {probe.stdout.strip()}")

    java_home = find_jdk21()
    ok(f"JDK 21 at {java_home}")

    try:
        import aiokafka  # noqa: F401
    except ImportError as exc:
        raise SmokeFailure(
            "aiokafka is not installed; run "
            "pip install -e './security-engine-python[kafka]'"
        ) from exc
    ok("aiokafka available")

    wrapper = ROOT / "control-plane-java" / ("gradlew.bat" if IS_WINDOWS else "gradlew")
    if not wrapper.is_file():
        raise SmokeFailure(f"gradle wrapper missing at {wrapper}")
    ok("gradle wrapper present")

    _check_ports()
    ok(f"ports free: {', '.join(str(p) for p in sorted(REQUIRED_PORTS))}")

    return java_home


def find_jdk21() -> Path:
    """Locate a JDK 21. Gradle's toolchain needs one to start, before it can provision any."""
    candidates: list[Path] = []
    if os.getenv("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]))
    jdks = Path.home() / ".jdks"
    if jdks.is_dir():
        candidates.extend(sorted(p for p in jdks.iterdir() if "21" in p.name))

    for candidate in candidates:
        java = candidate / "bin" / ("java.exe" if IS_WINDOWS else "java")
        if not java.is_file():
            continue
        probe = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=False)
        if 'version "21' in probe.stderr or 'version "21' in probe.stdout:
            return candidate

    raise SmokeFailure(
        "no JDK 21 found. Set JAVA_HOME to a Java 21 installation "
        "(this machine has one under ~/.jdks)."
    )


def start_infrastructure(harness: Harness) -> None:
    step(2, "Infrastructure (PostgreSQL + Kafka)")
    compose = ROOT / "infra" / "docker-compose.yml"

    result = subprocess.run(
        ["docker", "compose", "-f", str(compose), "up", "-d",
         "postgres", "kafka", "jaeger", "otel-collector"],
        capture_output=True, text=True, timeout=300, check=False,
    )
    if result.returncode != 0:
        raise SmokeFailure(f"docker compose up failed:\n{result.stderr[:800]}")
    harness.compose_started = True

    def healthy() -> bool:
        probe = subprocess.run(
            ["docker", "compose", "-f", str(compose), "ps", "--format", "json"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        states = []
        for line in probe.stdout.strip().splitlines():
            if line.strip():
                states.append(json.loads(line))
        wanted = {"postgres", "kafka"}  # the collector has no healthcheck to wait on
        healthy_services = {
            entry.get("Service")
            for entry in states
            if entry.get("Health") in ("healthy", "") and entry.get("State") == "running"
        }
        return wanted.issubset(healthy_services)

    wait_for("postgres and kafka to become healthy", healthy, timeout=240, interval=5)
    ok("postgres and kafka healthy")


def start_demo_target(harness: Harness) -> None:
    step(3, "Vulnerable demo target")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "demo-targets")
    harness.spawn(
        "demo-target",
        # -u: stdout is a file here, so Python would block-buffer it and the log would stay
        # empty until the process exits - exactly when it stops being useful.
        [sys.executable, "-u", "-m", "demo_targets.vulnerable_support_agent",
         "--host", "127.0.0.1", "--port", str(DEMO_TARGET_PORT)],
        cwd=ROOT,
        env=env,
    )

    def up() -> bool:
        status, body = request("GET", f"{DEMO_TARGET_URL}/health", timeout=5)
        return status == 200 and isinstance(body, dict) and body.get("status") == "ok"

    wait_for("demo target", up, timeout=90, interval=1.5,
             on_timeout=lambda: harness.processes[-1].tail())
    ok(f"demo target listening on {DEMO_TARGET_URL}")


def start_control_plane(harness: Harness, java_home: Path) -> None:
    step(4, "Java control plane")
    env = dict(os.environ)
    env.update({
        "JAVA_HOME": str(java_home),
        "AGENTSHIELD_INTERNAL_TOKEN": INTERNAL_TOKEN,
        "AGENTSHIELD_CREDENTIAL_KEY": CREDENTIAL_KEY,
        "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
        "POSTGRES_URL": "jdbc:postgresql://localhost:5432/agentshield",
        "SPRING_PROFILES_ACTIVE": "local",
        # Tracing is on and pointed at the collector this script starts, so the trace
        # context the control plane stamps on the event can be checked at the far end.
        "MANAGEMENT_TRACING_ENABLED": "true",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318",
    })
    # Absolute path: on Windows a bare "gradlew.bat" is resolved against the *parent's* PATH,
    # not against cwd, so a relative name fails with WinError 2 no matter what cwd says.
    wrapper = ROOT / "control-plane-java" / ("gradlew.bat" if IS_WINDOWS else "gradlew")
    harness.spawn(
        "control-plane",
        [str(wrapper), "bootRun", "--no-daemon", "-q"],
        cwd=ROOT / "control-plane-java",
        env=env,
    )
    managed = harness.processes[-1]

    def up() -> bool:
        if not managed.alive():
            raise SmokeFailure(
                f"control plane exited early:\n{managed.tail(40)}"
            )
        status, body = request("GET", f"{CONTROL_PLANE}/actuator/health", timeout=5)
        return status == 200 and isinstance(body, dict) and body.get("status") == "UP"

    # Generous: a cold Gradle cache downloads Spring Boot before anything starts.
    wait_for("control plane health", up, timeout=600, interval=5,
             on_timeout=lambda: managed.tail(40))
    ok(f"control plane UP at {CONTROL_PLANE}")


def start_worker(harness: Harness) -> None:
    step(5, "Python Kafka worker")
    env = dict(os.environ)
    env.update({
        "AGENTSHIELD_CONTROL_PLANE_URL": CONTROL_PLANE,
        "AGENTSHIELD_INTERNAL_TOKEN": INTERNAL_TOKEN,
        "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
        "AGENTSHIELD_DATASETS": str(ROOT / "datasets"),
        "AGENTSHIELD_LOG_LEVEL": "INFO",
        # Without these the engine's tracing stays off - it is opt-in - and the worker adopts
        # the incoming trace context only to discard it, exporting nothing. Jaeger then holds
        # the control plane's half of the trace and nothing else, and step 10 can assert the
        # traceparent arrived but never that the two halves joined.
        #
        # 4317, not 4318: the engine exports over gRPC and the control plane over HTTP. They
        # share an env var name and need different ports - the sort of thing
        # that looks configured and silently drops every span.
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317",
        "OTEL_SERVICE_NAME": ENGINE_SERVICE,
    })
    harness.spawn(
        "worker",
        [sys.executable, "-u", "-m", "agentshield.messaging.worker"],
        cwd=ROOT,
        env=env,
    )
    managed = harness.processes[-1]

    def subscribed() -> bool:
        if not managed.alive():
            raise SmokeFailure(f"worker exited early:\n{managed.tail(40)}")
        # Keyed on the worker's own readiness line, emitted after the consumer and producer
        # have both started. "The process is alive" is not readiness - it would race the
        # consumer group join and the first event would land before anyone was listening.
        return "worker ready" in managed.log_path.read_text(encoding="utf-8", errors="replace")

    wait_for("worker to join the consumer group", subscribed, timeout=120, interval=2,
             on_timeout=lambda: managed.tail(40))
    ok("worker consuming security.scan.lifecycle")


def configure_scan(auth: tuple[str, str]) -> tuple[str, str, str]:
    step(6, "Register target and policy through the API")

    status, projects = request("GET", f"{CONTROL_PLANE}/api/projects", auth=auth)
    if status != 200 or not projects:
        raise SmokeFailure(
            f"could not list projects (status {status}): {projects}. "
            "The 'local' profile should have seeded one via DevDataSeeder."
        )
    project_id = projects[0]["id"]
    ok(f"project {projects[0]['name']} ({project_id})")

    status, target = request(
        "POST", f"{CONTROL_PLANE}/api/projects/{project_id}/targets",
        auth=auth,
        body={
            "name": f"demo-{int(time.time())}",
            "type": "DEMO_TARGET",
            "baseUrl": DEMO_TARGET_URL,
            "configuration": {"tenant_id": "tenant-a", "timeout_seconds": 30},
        },
    )
    if status != 201:
        raise SmokeFailure(f"target creation failed ({status}): {target}")
    ok(f"target {target['id']} (config hash {target['configurationHash']})")

    policy_text = (ROOT / "datasets" / "policies" / "support-agent.yml").read_text("utf-8")
    status, policy = request(
        "POST", f"{CONTROL_PLANE}/api/projects/{project_id}/policies",
        auth=auth,
        body={"name": "support-agent", "content": policy_text},
    )
    if status not in (200, 201):
        raise SmokeFailure(f"policy creation failed ({status}): {policy}")
    ok(f"policy {policy['id']} v{policy['version']} (hash {policy['contentHash']})")

    return project_id, target["id"], policy["id"]


def run_scan(auth: tuple[str, str], project_id: str, target_id: str, policy_id: str) -> str:
    step(7, "Start a scan (API -> outbox -> Kafka)")
    idempotency_key = f"smoke-{int(time.time())}"

    status, scan = request(
        "POST", f"{CONTROL_PLANE}/api/projects/{project_id}/scans",
        auth=auth,
        headers={"Idempotency-Key": idempotency_key},
        body={
            "targetId": target_id,
            "policyId": policy_id,
            "suites": ["INDIRECT_PROMPT_INJECTION", "DATA_LEAKAGE"],
            "maxScenarios": 12,
        },
    )
    if status != 201:
        raise SmokeFailure(f"scan creation failed ({status}): {scan}")
    ok(f"scan {scan['id']} status {scan['status']}")

    # Idempotency across the real HTTP boundary. A unit test cannot reach this one.
    status_again, replay = request(
        "POST", f"{CONTROL_PLANE}/api/projects/{project_id}/scans",
        auth=auth,
        headers={"Idempotency-Key": idempotency_key},
        body={"targetId": target_id, "policyId": policy_id, "maxScenarios": 12},
    )
    if status_again != 200 or replay["id"] != scan["id"]:
        raise SmokeFailure(
            f"idempotency broken: replay returned {status_again} / {replay.get('id')}, "
            f"expected 200 / {scan['id']}"
        )
    ok("replayed Idempotency-Key returned the original scan (200, same id)")

    return scan["id"]


def await_completion(harness: Harness, auth: tuple[str, str], scan_id: str) -> dict:
    step(8, "Wait for the worker to drive the scan to a terminal state")
    terminal = {"COMPLETED", "FAILED", "CANCELLED"}
    seen: set[str] = set()
    final: dict = {}

    def done() -> bool:
        nonlocal final
        status, scan = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}", auth=auth)
        if status != 200:
            raise SmokeFailure(f"scan lookup failed ({status}): {scan}")
        if scan["status"] not in seen:
            seen.add(scan["status"])
            print(f"    ... {scan['status']}")
        final = scan
        return scan["status"] in terminal

    worker = next(p for p in harness.processes if p.name == "worker")
    wait_for("scan to reach a terminal state", done, timeout=300, interval=3,
             on_timeout=lambda: "worker log:\n" + worker.tail(40))

    if final["status"] != "COMPLETED":
        raise SmokeFailure(
            f"scan ended as {final['status']} ({final.get('errorCode')})\n"
            f"worker log:\n{worker.tail(40)}"
        )
    ok(f"scan COMPLETED, states observed: {sorted(seen)}")
    return final


def verify(auth: tuple[str, str], scan_id: str, scan: dict) -> None:
    step(9, "Verify what crossed the whole chain")

    if scan["findingCount"] <= 0:
        raise SmokeFailure(
            "scan completed with zero findings. The target is deliberately vulnerable, so "
            "this means findings did not survive the Kafka round trip."
        )
    ok(f"{scan['findingCount']} findings persisted "
       f"({scan['criticalCount']} critical, {scan['highCount']} high)")

    if scan["criticalCount"] <= 0:
        raise SmokeFailure("no critical findings; the flagship injection chain did not reproduce")

    status, findings = request("GET", f"{CONTROL_PLANE}/api/scans/{scan_id}/findings", auth=auth)
    if status != 200 or not findings:
        raise SmokeFailure(f"finding listing failed ({status}): {findings}")

    for finding in findings:
        for field_name in ("evidence", "reproduction", "remediation", "description", "title"):
            if CANARY in str(finding.get(field_name, "")):
                raise SmokeFailure(
                    f"finding {finding['code']} leaked the raw canary through {field_name}. "
                    "Redaction must hold across the Kafka boundary, not only in-process."
                )
    ok(f"no raw canary in any of {len(findings)} persisted findings")

    detected = [f for f in findings if f.get("detectedBy")]
    if not detected:
        raise SmokeFailure("no finding recorded its detecting evaluator; provenance was lost")
    ok(f"{len(detected)} findings carry deterministic evaluator attribution")

    codes = sorted({f["code"] for f in findings})
    print(f"    findings: {', '.join(codes[:6])}{' ...' if len(codes) > 6 else ''}")


# ---------------------------------------------------------------------------------


def verify_trace(harness: Harness) -> None:
    """Assert the two services share one trace, not merely one traceparent string.

    The log check below proves *propagation*: the control plane stamped a context, it survived
    the queue, the worker read it. That is necessary and not sufficient - a worker that adopts
    the context and then exports nothing looks identical in the log to one that joins the
    trace correctly, and the whole point of the feature is a single trace a human can open.

    So the second half queries Jaeger and requires one trace id carrying spans from *both*
    services. That is the claim the roadmap makes, and it is only checkable here.
    """
    step(10, "Verify the trace context crossed the queue")

    worker = next(p for p in harness.processes if p.name == "worker")
    log = worker.log_path.read_text(encoding="utf-8", errors="replace")

    accepted = [line for line in log.splitlines() if "traceparent=" in line]
    if not accepted:
        raise SmokeFailure(
            "the worker never logged a traceparent; it did not accept a scan event"
        )

    carried = [line for line in accepted if "traceparent=none" not in line]
    if not carried:
        raise SmokeFailure(
            "the worker accepted the scan with no trace context. The control plane did not "
            "stamp one, so the engine's spans start a second, unrelated trace: "
            + accepted[-1]
        )

    ok(f"worker adopted trace context from the control plane ({len(carried)} event(s))")
    _verify_trace_joined()


def _verify_trace_joined() -> None:
    """Find one trace in Jaeger containing spans from the control plane and the engine.

    Polled, because a single sample races the export. Spans leave each process on a `BatchSpanProcessor` timer and
    then pass through a collector, so the export finishes some seconds after the scan does -
    a single query races that and fails on a system that is working.
    """
    found: dict[str, object] = {}

    def joined() -> bool:
        traces = _jaeger(f"/api/traces?service={ENGINE_SERVICE}&lookback=1h&limit=30") or {}
        for trace in traces.get("data") or []:
            # `processes` maps each span's processID to the service that emitted it, so the
            # set of service names in one trace is exactly what "did these join?" means.
            emitters = {p.get("serviceName") for p in (trace.get("processes") or {}).values()}
            if {CONTROL_PLANE_SERVICE, ENGINE_SERVICE} <= emitters:
                found.update(trace=trace, emitters=emitters)
                return True
        return False

    def diagnose() -> str:
        known = set((_jaeger("/api/services") or {}).get("data") or [])
        missing = {CONTROL_PLANE_SERVICE, ENGINE_SERVICE} - known
        if missing:
            return (
                f"Jaeger has no spans at all from {sorted(missing)} (it knows {sorted(known)}). "
                "Each process exports only when its own OTEL_EXPORTER_OTLP_ENDPOINT is set, "
                "and the engine speaks gRPC on 4317 while the control plane speaks HTTP on "
                "4318 - a service missing here usually means the wrong port for its protocol."
            )
        return (
            "both services reported spans, but no single trace contains both. The worker "
            "started its own root span and never continued the one the control plane "
            "stamped, so the two halves are unlinkable in Jaeger."
        )

    wait_for("a trace spanning both services", joined, timeout=90, interval=3,
             on_timeout=diagnose)

    trace = found["trace"]
    ok(
        f"one trace spans both services: {trace['traceID']} "  # type: ignore[index]
        f"({len(trace.get('spans') or [])} spans, {sorted(found['emitters'])})"  # type: ignore[union-attr]
    )


def _jaeger(path: str) -> dict | None:
    try:
        status, body = request("GET", f"{JAEGER_QUERY}{path}", timeout=15.0)
    except OSError as exc:
        raise SmokeFailure(f"Jaeger query API unreachable at {JAEGER_QUERY}: {exc}") from exc
    return body if status == 200 and isinstance(body, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="leave containers and processes up afterwards, for debugging",
    )
    args = parser.parse_args()

    harness = Harness(keep_running=args.keep_running)
    auth = (DEV_EMAIL, DEV_PASSWORD)
    started = time.monotonic()

    print("AgentShield multi-process smoke test")
    print(f"logs: {LOG_DIR}")

    try:
        java_home = preflight()
        start_infrastructure(harness)
        start_demo_target(harness)
        start_control_plane(harness, java_home)
        start_worker(harness)

        project_id, target_id, policy_id = configure_scan(auth)
        scan_id = run_scan(auth, project_id, target_id, policy_id)
        scan = await_completion(harness, auth, scan_id)
        verify(auth, scan_id, scan)
        verify_trace(harness)

        elapsed = time.monotonic() - started
        print(f"\nPASSED in {elapsed:.0f}s")
        print("API -> outbox -> Kafka -> worker -> target -> Kafka -> PostgreSQL")
        return 0

    except SmokeFailure as failure:
        print(f"\nFAILED: {failure}", file=sys.stderr)
        return 1
    except OSError as failure:
        # Spawning a child can fail for reasons that have nothing to do with the chain under
        # test (missing binary, permissions). Report it as such, not as a stack trace.
        print(f"\nFAILED to start a process: {failure}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    finally:
        harness.teardown()


if __name__ == "__main__":
    sys.exit(main())
