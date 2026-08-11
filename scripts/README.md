# Scripts

## `smoke_multiprocess.py`

The only test in the repository that stubs nothing.

```bash
python scripts/smoke_multiprocess.py
python scripts/smoke_multiprocess.py --keep-running   # leave everything up to poke at
```

Every other suite cuts the chain somewhere:

| Suite | What it proves | Where it stubs |
|---|---|---|
| `pytest security-engine-python/tests` | The pipeline finds real vulnerabilities | Drives the engine in-process, over an ASGI transport |
| `ScanLifecycleIT` | Scan row and outbox entry commit together | Stops at the outbox; Kafka never runs |
| `test_worker.py` | The worker publishes correct, redacted events | Fake dispatch and a recording publisher |
| **`smoke_multiprocess.py`** | **All of it, as separate processes** | **nothing** |
| **`chaos_worker_kill.py`** | **A killed worker loses no work and duplicates none** | **nothing** |
| **`chaos_broker_partition.py`** | **A broker outage delays scans, it does not lose them** | **nothing** |

The failures it exists to catch only appear when the processes are genuinely separate: a
serialiser mismatch, a topic-name typo, an event the consumer silently drops, a credential
that never reaches the worker, redaction that holds in-process but not across the wire.

### What it does

1. Preflight - Docker, a JDK 21, `aiokafka`, the Gradle wrapper.
2. `docker compose up -d postgres kafka`, waits for both to report healthy.
3. Starts the vulnerable demo target on `:8090`.
4. Starts the control plane under the `local` profile (`gradlew bootRun`), waits for
   `/actuator/health`.
5. Starts the Python Kafka worker.
6. Registers a target and a policy through the public API.
7. `POST /api/projects/{id}/scans`, then replays the same `Idempotency-Key` and asserts the
   original scan comes back with 200 - idempotency across a real HTTP boundary, not a mock.
8. Polls until the scan reaches a terminal state, printing each state it passes through.
9. Asserts: status `COMPLETED`; findings persisted; at least one CRITICAL; every finding
   carries its detecting evaluator; **no raw canary** in any persisted finding.
10. Tears everything down, including `docker compose down -v`.

Exit 0 means `API -> outbox -> Kafka -> worker -> target -> Kafka -> PostgreSQL` works.

### Requirements

- Docker running
- A JDK 21 (found via `JAVA_HOME`, or under `~/.jdks`)
- `pip install -e "./security-engine-python[kafka]" -e ./cli -e ./demo-targets`

Logs for every child process land in `artifacts/smoke/`. They are also uploaded by the CI
job, because the only thing worse than a flaky distributed test is a flaky distributed test
with no logs.

### Where the credentials come from

The control plane has no signup endpoint - self-service registration for a tool that generates
adversarial traffic against production systems is not a default anyone wants. That leaves a
bootstrap problem, solved by `DevDataSeeder`: under the `local` and `demo` profiles only, and
only when the workspace table is empty, it creates a workspace, three users covering all three
roles, a project and a CI token, with identifiers derived from fixed names so this script can
address them without scraping log output.

If you see the well-known-credentials warning in a deployment log, the wrong profile is active.

### When it fails

The script prints the tail of the relevant child process's log with the failure. Common causes:

| Symptom | Cause |
|---|---|
| `these ports are already in use` | Another stack owns one of them. Preflight names which. |
| Timeout on step 2 | Docker Desktop still starting |
| `control plane exited early` | Usually Flyway or Hibernate validation - read `artifacts/smoke/control-plane.log` |
| Timeout on step 8 | The worker is not consuming; check `artifacts/smoke/worker.log` for the internal-token 401 |
| `zero findings` | Findings did not survive the Kafka round trip - the interesting failure, and the reason this test exists |
