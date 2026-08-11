# Development

## Requirements

| Component | Needs | Notes |
|---|---|---|
| Security engine, CLI, demo targets | Python 3.12+ | Runs standalone, no infrastructure |
| Control plane | JDK 21, Docker | Gradle wrapper provisions Gradle itself |
| Local stack | Docker | PostgreSQL, Kafka, OTel collector, Jaeger |

## Python side

```bash
python -m venv .venv
source .venv/bin/activate                          # Linux, macOS
pip install -e "./security-engine-python[dev,api,kafka,otel,graph,mcp]" -e ./cli -e ./demo-targets
pytest security-engine-python/tests -q
python contracts/validate.py
```

Everything on the Python side runs with **no LLM API key and no infrastructure**. The demo
agent's planner is rule-based, so tests are deterministic and free. Set `ANTHROPIC_API_KEY` and
pass `--judges` only when you want the semantic evaluators.

The end-to-end tests drive the real pipeline against the real demo target over an in-process
ASGI transport - no sockets, no ports, no sleeps, but every layer under test is the one that
runs in production, including the HTTP adapter.

## Java side

```bash
cd control-plane-java
./gradlew test          # unit tests
./gradlew build         # includes Testcontainers integration tests, needs Docker
```

The repository includes the Gradle 8.10.2 wrapper, and the build declares a Java 21
toolchain. The toolchain covers compilation and test execution; it does not cover the JVM
Gradle runs on, and that one comes from `JAVA_HOME`.

**`JAVA_HOME` must already be 17 or newer or the build cannot start.** The Spring Boot plugin
is loaded during configuration, before a toolchain applies, so an old default JDK fails with:

```
Could not resolve org.springframework.boot:spring-boot-gradle-plugin:3.3.4
  Dependency requires at least JVM runtime version 17. This build uses a Java 8 JVM.
```

which reads like a network problem and is not one.

```bash
export JAVA_HOME=/path/to/jdk-21                    # Linux, macOS, Git Bash
```

```powershell
$env:JAVA_HOME = "C:\path\to\jdk-21"              # this PowerShell session
[Environment]::SetEnvironmentVariable(
    "JAVA_HOME", "C:\path\to\jdk-21", "User")     # and every future one
```

`setx` is the usual advice and is a trap here: it sets the variable for *later* sessions and
leaves the current one unchanged, so the next command in the same terminal fails identically.

Opening `control-plane-java` in IntelliJ works too: it uses its own Gradle distribution and
whichever JDK is registered for the project.

On Windows the wrapper is `gradlew.bat`; elsewhere it is `./gradlew`.

## Multi-process smoke test

The only check that stubs no boundary. Boots PostgreSQL, Kafka, the control plane, the worker
and a target as separate processes, then drives a real scan through all of them.

```bash
python scripts/smoke_multiprocess.py
```

Needs Docker, a JDK 21 and the `kafka` extra. Runs in about a minute once caches are warm; logs
for every child process land in `artifacts/smoke/`. See [../scripts/README.md](../scripts/README.md).

Run it after touching anything on a boundary - serialisers, topic names, event shapes, the
internal dispatch endpoint. The other suites intentionally stop short of those, so they cannot
tell you when one breaks.

## Tracing

Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set, so an ordinary run needs no collector.

```bash
docker compose -f infra/docker-compose.yml up -d jaeger otel-collector

export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
agentshield scan --target http://127.0.0.1:8090 \
  --policy ./datasets/policies/support-agent.yml --suite smoke --tenant tenant-a
```

Traces land in Jaeger at http://localhost:16686 under `agentshield-cli`. The tree is
`scan` -> `node.*` -> `attack` -> `evaluate`, with the attributes listed in
[architecture.md](architecture.md#observability).

Instrumentation lives on the executor in `graph/runner.py`, not in the nodes: the nodes stay
pure functions with no telemetry imports.

## Local infrastructure

```bash
docker compose -f infra/docker-compose.yml up -d
```

| Service | URL |
|---|---|
| PostgreSQL | `localhost:5432` (`agentshield`/`agentshield`) |
| Kafka | `localhost:9092` |
| Jaeger UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |

Add `--profile demo` to run the demo targets as containers on 8090 (vulnerable) and 8091
(hardened).

## Distributed engine mode

Set the same `AGENTSHIELD_INTERNAL_TOKEN` on both processes. The token protects the narrow
control-plane endpoint from which a worker fetches decrypted target configuration; credentials
are never placed on Kafka.

```bash
# terminal 1
cd control-plane-java
./gradlew bootRun

# terminal 2 (starts FastAPI and the Kafka consumer in one process)
AGENTSHIELD_CONTROL_PLANE_URL=http://localhost:8080 \
KAFKA_BOOTSTRAP_SERVERS=localhost:9092 \
python -m agentshield.api.app
```

The worker commits a `security.scan.created` offset only after it has published the result
stream. If it is killed mid-scan, Kafka redelivers the request; deterministic event ids and
database uniqueness make the replay idempotent.

## Layout

### Control plane

Package **by feature first, by layer within the feature**. A change to targets touches one
top-level package; a change to how the API is shaped touches one sub-package inside it.

```
io/agentshield/controlplane/
  <feature>/domain/       entities and value objects - no Spring, no HTTP
  <feature>/repository/   Spring Data interfaces
  <feature>/application/  services: authorisation, transactions, orchestration
  <feature>/api/          controllers
  <feature>/api/dto/      request and response records

  shared/domain/          BaseEntity, WorkspaceScoped
  shared/error/           exception hierarchy, no HTTP status anywhere
  shared/web/             ApiError and the handler that maps codes to statuses
  security/domain/        Principal, Role, Permission
  security/access/        AccessGuard and the principal provider behind it
  security/web/           filter and filter chain
  event/messaging/        the Kafka consumer
  workspace/bootstrap/    DevDataSeeder
```

Three rules keep this honest:

- **Dependencies point inward.** `api` may use `application`; `application` may use `domain`
  and `repository`; `domain` depends on nothing of ours. A domain class importing
  `HttpStatus` is the smell this layout exists to prevent.
- **Authorisation is a collaborator, not a static call.** Services take
  `security.access.AccessGuard` in their constructor. There is no `Principal.current()`.
  `SecurityContextHolder` appears in exactly two classes, both in the security feature:
  `security.web.ApiAuthenticationFilter` writes it, `security.access.SecurityContextPrincipalProvider`
  reads it. No service, controller or domain class mentions it.
- **Controllers only speak HTTP.** Binding, delegating and mapping to a DTO. Anything that
  decides authority or calls another system lives in `application` - which is why
  `TargetValidationService` exists and that logic does not sit in the controller.

### Security engine

```
security-engine-python/agentshield/
  models/        domain models, mirroring the control plane's schema
  adapters/      the only code that knows what a target looks like
  attacks/       corpus loading, mutation, threat-model-driven selection
  evaluators/    pure (trajectory, policy) -> verdict functions
  findings/      fingerprinting, dedup, severity, remediation
  graph/         nodes, plus two executors that drive them
  messaging/     event contracts, dispatch client, publisher, Kafka worker
  reporting/     Markdown for humans, JSON for machines
  api/           app factory, routes, schemas, in-flight registry
  evals/         fixtures, scoring, judge stability
```

## Adding things

**A new attack scenario** - add a template to the right file under `datasets/`. No code. The
corpus tests will reject an unknown evaluator name in `expected.detected_by`, an unbound
variable, or an email address outside a reserved test domain.

**A new evaluator** - subclass `Evaluator`, implement `evaluate`, register it in
`evaluators/registry.py`. Redaction is applied centrally in `Evaluator.run`, so you do not need
to remember it. Write the negative test first: an evaluator that fires on legitimate behaviour
is worse than one that misses.

**A new target type** - implement `BaseTargetAdapter`, register a factory in
`adapters/registry.py`. Report honest `TargetCapabilities`: claiming `supports_trajectory` when
you cannot produce one turns skipped coverage into false passes.

**A new event type** - add the constant to `EventTypes.java` **and** the enum in
`contracts/events/envelope.schema.json`. `contracts/validate.py` fails the build if they drift.

## Conventions

- Evaluators are pure. No network, no clock, no model call.
- Nothing that leaves the engine is unredacted.
- Deny by default, everywhere: unknown tools, unmatched routes, unrecognised event versions.
- A scan that could not run must never look like a scan that found nothing.
