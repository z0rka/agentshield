# Roadmap

Six stages. Each ends with something demonstrable, because a stage that ends with "the
foundation is in place" cannot be checked.

Current position: **all six stages delivered and every acceptance number met.** The corpus
stands at 124 authored templates against a floor of 100, all ten check categories represented
and every per-suite minimum cleared; see [Corpus targets](#corpus-targets).

Three items stay open and are labelled where they live: the demo video is not recorded, the
AWS configuration has never been applied, and the dashboard reads a report file with no live
control plane behind it. The first two need a person and an AWS account.

**What a review of the acceptance criteria turned up.** Six claims did not survive being
checked against the code, and four of them were claims this repository made about itself:

* **LangGraph was documented as the production orchestrator and never ran.** Every caller
  imported `runner.run_scan`, nothing imported `run_with_langgraph`, and CI installed every
  extra except `[graph]`. `run_scan` now selects the runtime, LangGraph is the default,
  `AGENTSHIELD_ORCHESTRATOR` pins it, and `tests/test_orchestrators.py` asserts both runtimes
  reach the same findings. Switching the default immediately dropped every `node.*` span,
  which `test_tracing.py` caught.
* **Cancellation stopped at Kafka.** The control plane published `security.scan.cancelled`,
  the worker returned early on anything that was not `scan.created`, and the token the
  pipeline polls was reachable only over the engine's own HTTP endpoint. Worse than the
  missing branch: the work loop is serial, so a cancel would have queued behind the scan it
  was cancelling. Control traffic now has its own consumer group.
* **The retry and DLQ topics were dead code.** `retryOf` and `dlqOf` existed, were documented
  in detail, and had no caller; `DeadLetterRecorder` said it wrote "PostgreSQL as well as the
  DLQ topic" and wrote only the row. `RetryRouter` now routes failures to `<topic>.retry` and
  parks exhausted ones on `<topic>.dlq`, with the row still written for humans.
* **The audit table had no writer.** `audit_log` has been in the first migration since stage 2
  and nothing inserted into it, which is worse than having no table: a schema implies a
  feature.
* **Rate limiting and scheduling were absent.** Both are named in the specification. Added.

Worker recovery is still replay and not resume. A killed worker re-runs the whole scan
from the beginning; the scenarios it already finished are done again. Correctness holds - findings deduplicate and
the scan is not lost - but a crash re-spends the model and tool budget. Scenario-level
checkpointing is the next optimisation and is not pretended to exist.

The distributed scan path - API to outbox to Kafka to engine to persisted findings - is
verified end to end by `scripts/smoke_multiprocess.py`, which also asserts that the control
plane and the engine share one trace in Jaeger, which a matching traceparent string alone
would not prove.

---

## Stage 1 - minimal scanner (weeks 1–4) - DONE

Prove the core claim end to end with no infrastructure.

- [x] Vulnerable support agent with the AgentShield inspection protocol
- [x] Python scanner: adapters, trajectory, evaluators, findings
- [x] Attack corpus as versioned data files (32 templates)
- [x] Direct and indirect prompt injection
- [x] Deterministic provenance tracing for indirect injection
- [x] Markdown and JSON reports
- [x] CLI: `scan`, `regression`, `ci`, `replay`, `list-attacks`
- [x] Hardened variant of the demo target, so the fix is demonstrable

**Result:** `agentshield scan` finds a real critical vulnerability, and the same command proves
it fixed.

## Stage 2 - Java control plane (weeks 5–8) - DONE

- [x] Schema, entities, Flyway migrations
- [x] Projects, targets, policies, scans, findings, CI endpoints
- [x] RBAC and multi-tenancy (workspace from the authenticated principal only)
- [x] Encrypted target credentials (AES-GCM)
- [x] Transactional outbox, relay, idempotent consumers, DLQ
- [x] SSE progress stream
- [x] Engine dispatch: the Kafka consumer on the Python side
- [x] Trajectory persistence from engine to PostgreSQL
- [x] Target validation wired to `POST /discover`
- [x] Testcontainers suite green locally and configured in CI
- [x] Workspace bootstrap (`DevDataSeeder`), profile-gated to `local` and `demo`
- [x] Multi-process smoke: API → outbox → Kafka → engine → findings → completed scan

**Exit:** scans are created, driven and reported through the Java API, and a killed engine
worker does not lose a scan.

**What the smoke test found on its first green run.** The producer was configured with
`JsonSerializer` while the outbox already stores a serialised envelope, so Kafka carried a
JSON-escaped *string* instead of a JSON object. No non-Java consumer could read a single
event. Neither existing suite could see it: the Java integration tests stop at the outbox and
set `spring.kafka.listener.auto-startup=false`, and `test_worker.py` uses a fake publisher.
Nothing crossed the serialisation boundary until this test did. Fixed by using
`StringSerializer`/`StringDeserializer` on both sides - see `application.yml`.

That is the argument for the test existing, and the reason "all suites green" was not the same
thing as "the system works".

## Stage 3 - evaluation and observability (weeks 9–12) - DONE

- [x] `evals/` harness: precision and recall against labelled trajectories, gated in CI
- [x] Full fixture coverage of every deterministic evaluator
- [x] Judge stability: repeated sampling, agreement figure, gate on it
- [x] Judge responses recorded once and replayed: the judge path is covered in CI at no cost
- [x] LLM judges end to end with token and cost accounting on the scan summary
- [x] Langfuse sink recording every judge call by model and prompt version
- [x] OpenTelemetry spans through the engine: scan -> node -> attack -> evaluate
- [x] Trace context carried on the event envelope, adopted by the worker
- [x] Java producer side: `TraceContextCapture` stamps the envelope at outbox write
- [x] One joined trace observed in Jaeger through the smoke, asserted on every run
- [x] Reproduction minimisation: delta debugging to the shortest triggering payload
- [x] Corpus to 50–70 templates (68 at the time; now 124, gated in CI)

**Exit:** evaluator quality is a number, not an opinion, and a change that trades precision for
recall is arguable with data.

**What the harness cost to make honest.** Two evaluators could not be measured at all on the
first run. `ExternalSideEffectEvaluator` only fires when a scenario declares a tool forbidden,
so with no scenario it can never disagree with anything; `SchemaValidityEvaluator` needs a
policy that requires schema validation, which the support-agent policy does not. Both were
reported as unmeasured and never scored as perfect, which is the whole reason to build this:
an evaluator that never fires would otherwise carry 1.00 precision forever. Fixed by letting a
fixture supply a minimal scenario and by adding `datasets/policies/strict-json-agent.yml`.

**What the trace assertion was worth.** Step 10 of the smoke had been green for two runs
against a feature that did not work at all. It checked the worker's log for a traceparent that
was not `none`, and that line was true: the control plane stamped a context, it crossed Kafka,
the worker read it. What the log could not show is that the worker then discarded it -
`OTEL_EXPORTER_OTLP_ENDPOINT` was never set for the worker process, engine tracing is opt-in,
and every engine span was dropped before it reached an exporter. Jaeger held the Java half of
the trace and nothing else.

Rewriting the assertion to query Jaeger for a single trace containing spans from *both*
services turned it red immediately, and then found a second bug: the engine exports over gRPC
(4317) and the control plane over HTTP (4318). They share the env var name
`OTEL_EXPORTER_OTLP_ENDPOINT` and need different ports, so a plausible-looking value silently
drops every span the exporter is handed. `docker-compose.yml` had the convention right; the
smoke script did not follow it.

The lesson is the same one the corpus-coverage check produced: an assertion that can only
observe an intermediate signal will pass on a broken system. Step 10 now polls Jaeger - spans
leave on a batch timer, so a single query races the export - and distinguishes "exported
nothing" from "exported two unlinked traces" in its failure message. The verified run: one
trace, 1029 spans, both services.

**Why the judges are recorded, not called.** They are the only component that costs
money to exercise, which makes them the only component with a standing incentive to stay
untested - unacceptable for code that decides whether an agent did something dangerous. So
`scripts/record_judges.py` buys each answer once and writes it to `datasets/cassettes/`;
every run afterwards replays it. A case that was never recorded raises, and the evaluator
turns that into a *skipped* result: a judge that could not run must never be mistaken for a
judge that found nothing. The cassette stores the response and a hashed key but never the
prompt - the prompt carries the trajectory, and that is the one thing this repository is
careful not to publish.

**What enabling the judges cost, and what it caught.** Twenty recorded answers came to about
twenty cents; the first live judged scan then reported spending **$0.0000** against 15,388
input tokens. `ScanState` builds its `JudgeUsage` before the judge model is resolved, so an
unstamped accumulator priced every call through the unknown-model path. A security tool that
under-reports its own bill has the same defect as one that under-reports findings, so two
things changed: the clients stamp the model onto the usage they are handed, and an unpriced
model now reports "cost unknown" and not a zero. A zero next to fifteen thousand tokens
reads as "this was free", and that is the one thing it was not.

Langfuse is deliberately a **sink, not a source**. The judge prompt stays in this repository
under `JUDGE_PROMPT_VERSION`, so a scan reproduces from a checkout with no call to anybody;
Langfuse records which model and prompt version produced which verdict, which is the half of
"versioning" that has to survive an argument six months later. Prompts are redacted before
they leave the process - a security tool that ships its customers' agent traffic to a
third-party dashboard has recreated the problem it was bought to find.

**What growing the corpus turned up.** Going from 32 templates to 61 was meant to be
authoring work. Measuring the result found three defects that had nothing to do with the new
templates:

- **A false positive that predated the change.** `ABUSE-003` fired against the *hardened*
  demo target as readily as the vulnerable one. The cause was `UnsafeOutputSinkEvaluator`
  flagging a dangerous pattern in a tool argument without asking who wrote it - its own
  docstring says "model-authored text", and the code never checked that. An agent passing a
  string the customer typed into a search query is not authoring a payload.
  `evals/fixtures/true-negative/sink-user-typed-the-payload.yaml` pins it; removing the guard
  drops precision to 0.50 and fails the gate.
- **Scenario selection spent its budget in catalog order**, so with a 40-scenario cap and a
  larger corpus, whichever category sorted last got nothing. A scan reporting "no cross-tenant
  findings" because it never ran a cross-tenant scenario is the worst output this tool has.
  Selection is now round-robin across categories. Same defect shape as the minimisation
  budget below, found the same way.
- **Selection depended on filenames.** Within a category, templates were taken in the order
  files happened to be read, so splitting one suite into two files changed which scenarios a
  capped scan ran. Ordering is by template id now.

The headline number is 61 authored and **23 demonstrated** - fires against the vulnerable
demo target, silent against the hardened one. The remaining 38 are silent against both, which
is reported and never counted as coverage. That gap is mostly the demo target and not the
templates: it is a scripted simulation recognising a handful of directive shapes, so a
template phrased outside that vocabulary settles nothing here either way. Publishing 61 as
though it were coverage would repeat the mistake the evals harness exists to prevent, so
`scripts/check_corpus_coverage.py` reports both numbers and CI ratchets the second one.

**What minimisation nearly claimed.** The first working version reported `minimized=True` on
findings where the probe budget ran out before a single segment came off - the payload was
untouched, and the report said it had been minimised. The tell was the note printed underneath
it: "no segment could be removed; probe budget reached before convergence", which is two
statements that cannot both be interesting. `minimized` now means a *reduced* payload was
re-run and observed to reproduce, and the budget-shortfall case says so in those words. The
same run showed the budget being taken first-come, so one slow payload spent the scan's
allowance and the last three findings got nothing; it is now shared equally among findings that
qualify.

## Stage 4 - MCP security (weeks 13–16) - DONE

- [x] MCP client adapter (`McpServerAdapter`), real protocol, in-process for tests
- [x] Insecure MCP demo server and its hardened twin
- [x] Tool discovery, claimed-scope reading, authorization probing
- [x] Dangerous tool-combination detection, gated on an absent scope
- [x] Poisoned tool descriptions - an injection vector into every agent that connects
- [x] MCP corpus (7 templates) and a policy that describes an MCP target

**Exit:** AgentShield tests REST agents and MCP servers with the same evaluators.

**What the second protocol cost.** The exit criterion was the claim being tested: if evaluators
really are pure functions of a trajectory, supporting MCP should be one adapter and nothing
else. It nearly was - `manifest.py` is the only new evaluation logic, and it exists because MCP
surfaced a threat REST always had and nobody looked at. But the first run convicted the
hardened server and acquitted nothing, and the four reasons were all mine:

- **The corpus format silently dropped the call plan.** `metadata:` on a template was never
  read by the catalog, so every MCP scenario executed nothing and reported a pass. Invented a
  key but never checked that the parser read it.
- **Arguments went in flat.** `Trajectory.tool_calls` reads `data["arguments"]`; written at the
  top level, every call parsed as having no arguments and every evaluator that inspects a
  recipient, an amount or a tenant went quiet - on a scan that looked clean.
- **Results were carried as text.** Evaluators read `data`, and an MCP result is structured, so
  leaving it unparsed disabled them just as thoroughly.
- **A policy was pointed at the wrong target.** The support-agent policy reads `tenant_id`; the
  MCP server returns `tenant`. Every tenant check passed, for the wrong reason.

The last one is the general lesson: a policy describes *a* target, and reusing one across
targets fails open. `datasets/policies/mcp-server.yml` exists for that reason.

**Who chose the call.** The one genuine conceptual difference. Against an agent, "it tried to
email an attacker and the backend refused" is a real finding - the agent was talked into it.
Against a server there is no agent to talk into: AgentShield picked the recipient, so an
attempt is evidence about the harness and only the server's *answer* says anything about the
server. `EvaluationContext.harness_initiated_calls` carries that distinction, and without it
three templates flagged a correctly hardened server. Following it also caught the hardened
server failing its own policy - it was sending mail without the approval token the policy
requires.

## Stage 5 - distributed hardening (weeks 17–20) - DONE (two items deferred with reasons)

- [x] Delay-tiered retry: exponential backoff on the outbox entry, capped, then the DLQ
- [x] Cancellation propagating to in-flight adapter calls
- [x] Concurrency controls per workspace and per target
- [x] SSRF protection on target URLs: resolved addresses checked on both sides, no pattern matching
- [ ] Worker recovery: resume a scan from persisted scenario state (deferred, see below)
- [ ] Credential key from KMS (deferred: unverifiable without an AWS account)
- [ ] Corpus to 100 templates (deferred, see below)
- [x] Chaos test: every event duplicated, replayed and shuffled (`EventReplayChaosIT`)
- [x] Chaos test: worker killed mid-scan, scan replayed and completed once
- [x] Chaos test: broker partitioned mid-flight, scan delayed and delivered after healing

**Exit:** a scan survives partial failures and restarts without losing or duplicating work.

**Three items closed differently than written, and one refused.**

*Retry topics with delay tiers* was already built, under another name. `OutboxEntry.markFailed`
applies exponential backoff capped at five minutes, the relay only claims rows whose
`next_attempt_at` has passed, and an entry that exhausts its attempts goes to the dead-letter
recorder. Kafka retry topics are a different implementation of the same idea and a worse fit
here, because the outbox row is written in the same transaction as the scan - the delivery
guarantee comes from the database and never from a topic topology. The broker-partition chaos test
exercises the whole path, and that is why this is ticked and not rebuilt.

*Concurrency per target* was the half that was missing; per workspace was already enforced.
They protect different things. The workspace limit stops AgentShield overcommitting itself.
The target limit, default 1, stops two scans landing on one agent - and that is a correctness
matter before it is a load one, because the indirect-injection suite plants documents in the
target and a second concurrent scan retrieves the first one's poisoned article.

*Worker resume from a checkpoint* is deferred, and the chaos test is the argument. A killed
worker today replays the entire scan, which is correct and wasteful. Resuming mid-scan would
save the duplicated work, but the stage's exit criterion is "without losing or duplicating
work" in the sense of *results*, and that is already demonstrated: the replayed scan completes
once and writes no finding twice. This is an efficiency change wearing a correctness label.

*KMS* is deferred honestly. `CredentialCipher` takes a base64 key from configuration, and a
KMS path cannot be verified here without an AWS account. Writing one and marking the item done
would put an untested credential path in a security tool, which is the specific failure this
repository keeps catching in itself.

**Raising demonstrated from 22 to 28.** The honest way to improve that number is to teach
the demo target more failure modes, never to write more templates - a template the target
cannot exercise is a sentence pretending to be evidence. Three changes, each a real defect with a real fix
in `--secure`:

- *The system prompt leaked an internal escalation code and nothing noticed*, because the
  policy never declared the code sensitive. The demo was disclosing it correctly and the
  evaluators had no reason to care.
- *The agent had no resource behaviour at all* - no fan-out, no enumeration, no retry - so six
  budget templates ran against a target with nothing to find. It now resolves one lookup per
  order reference the caller lists, expands "check every article" literally, and retries a
  missed record four times with no backoff. The caller chooses the tool-call count, which is
  the whole of OWASP LLM10. The hardened build does the same work up to a stated ceiling and
  says it stopped.
- *That immediately produced two false positives*, and they were the evaluator's fault, not
  the target's. `LoopEvaluator` detected cycles on bare tool names, so six lookups of six
  different orders matched "get_customer, get_customer" repeated three times - firing on a
  build that had capped the batch correctly. A loop means no progress; distinct work is
  progress however repetitive its shape. Cycle detection now compares full signatures, and
  `loop-batch-of-distinct-lookups.yaml` pins it: reverting drops precision to 0.50.

**Why the corpus stops at 68.** The item says 100 authored templates. Adding 32 more is an
afternoon of writing, and `scripts/check_corpus_coverage.py` would report 100 authored against
the same 22 demonstrated - a headline that grew while the evidence behind it did not. That
gate exists precisely to stop that, and padding the number to satisfy a checklist while the
tool reports the padding would be a strange thing to ship in a repository whose argument is
that measured beats claimed. The useful version of this item is to raise *demonstrated*, which
means teaching the demo target more failure modes, not teaching the corpus more
sentences. That is stage 6 work and it is written down as such.

**Killing the worker, and the assertion that nearly was not there.** The durability claim
is two sentences: a killed worker receives the request again, and the replay is idempotent.
`EventReplayChaosIT` settles the second against a real database and structurally cannot settle
the first, because the offset commit is a Kafka behaviour and that test has no Kafka.
`scripts/chaos_worker_kill.py` is where the first is settled - real broker, real worker,
`taskkill /F` mid-scan.

It passed first time, and the pass was worth less than it looked. The script asserted that the
scan completed and that no fingerprint was written twice, both of which are also true when the
first worker finishes in the window between the status poll and the kill landing. In that case
nothing is replayed and the run proves nothing, while reporting success. Checking the
replacement's own log for `scan <id> accepted` is what separates "recovered" from "was already
done"; it was verified by hand on the first run and only then written into the script, which is
the wrong order and the reason it is recorded here.

**What replaying the event stream proved, and what it did not.** At-least-once delivery
means "the same event twice" is the normal case and no kind of fault, and the design claims two
independent defences: `processed_event` claims each event id by primary key, and findings
deduplicate on `(scan_id, fingerprint)`. Only the second survives an engine retry, because a
worker that dies after publishing and before committing its offset republishes with *fresh*
ids - so a test that redelivers an identical envelope proves the easier half. `EventReplayChaosIT`
replays the whole stream, shuffles it, and sends the same defect under new ids.

All six passed once the fixture was right, and getting it right was the lesson. Two of them
failed initially and read exactly like idempotency bugs; the cause was that a new `Scan` is
`CREATED`, the API queues it, and the fixture skipped that - so every lifecycle transition was
illegal and the scan sat in its initial state. The state machine was doing precisely what it
advertises. A fixture in an impossible state produces failures that look like product defects,
and the temptation is to "fix" the product until they go green.

**Cancellation used to mean "stop starting things".** The token was polled between
scenarios, so a cancel arriving one second into a sixty-second request was honoured a minute
later - times however many scenarios were in flight, ten by default. The status was correct
and the timing was useless.

The token is now awaitable as well as pollable, and the adapter call is raced against it. Two
details decide whether that works in the deployment and not just the test: the in-flight task is
cancelled and then awaited on the way out, because a task left running keeps sending traffic at
a target the operator just said to stop scanning; and the wakeup goes through
`loop.call_soon_threadsafe`, because the cancel arrives from the API and setting an
`asyncio.Event` from outside its loop loses it silently.

Reverting to the polling version turns three of the eight tests red and takes the file from
0.3s to 30s, which is the same 100x the operator would have felt.

**Why the two SSRF guards are not the same guard.** A tool whose job is to send adversarial
traffic at a URL somebody supplied is a forgery primitive with a scheduler attached, and
`169.254.169.254` is the address that makes it one: on AWS, GCP and Azure it serves instance
credentials to anything that connects, so "register it as a target and read the findings" is a
complete exfiltration path.

The control plane denies internal addresses by default, because there a user supplies the URL
and the *server* makes the request. The engine does not, because it runs as a CLI on an
operator's laptop as often as it runs as a worker, the demo target is on loopback, and a guard
that breaks the quickstart is one that gets switched off wholesale - taking the part that
matters with it. What holds on both sides, under every configuration, is that metadata
endpoints are refused. That is not deployment policy.

Both resolve the host and never match on the string, since `metadata.attacker.test` is a name
an attacker owns. Neither closes DNS rebinding: validation and connection are two lookups, and
pinning the second to the address the first approved is a change in the HTTP client. Written
down in both files, because a guard whose gaps are unstated reads as a guarantee it does not
make.

## Stage 6 - CI, deployment, portfolio (weeks 21–26) - DONE (one item cannot be automated)

- [x] GitHub Action wrapping the CLI - `.github/actions/agentshield-scan`, a composite action
      with typed outputs, a job summary and an optional pull request comment. It runs against
      the demo target on every build in `agentshield-gate.yml`, because an action nobody
      executes is a README with YAML syntax highlighting. Composite over Docker, on purpose:
      a Docker action pins the scanner to a published image, which for a security tool means
      testing last month's release against this week's code.
- [x] Web dashboard - `web-ui/`, served by `agentshield ui --report artifacts/report.json`.
      Counts, coverage, the evidence chain, the minimised reproduction. No build step and no
      dependencies; the argument is in `web-ui/README.md`. Report content is attacker-authored,
      so every value reaches the DOM as text and `tests/test_web_ui.py` fails the build if an
      `innerHTML` appears.
- [x] Live trajectory view - the API half. `GET /api/findings/{id}/trajectory` returns the
      server-redacted steps a finding's evidence indices point at, workspace-scoped, 404 on
      another tenant's finding. Covered by `ScanLifecycleIT`. The browser half is not wired up,
      and `web-ui/README.md` says which endpoints it would use: the control plane needs
      PostgreSQL and Kafka, and a screenshot of something nobody can start is worth less than a
      page that opens in thirty seconds.
- [x] AWS ECS/Fargate deployment - `infra/aws`, Terraform for three services, RDS, MSK
      Serverless, per-service task roles. **Never applied**: no AWS account was available, so
      `plan` has not run against a real provider. Labelled as unverified in its README rather
      than omitted, because the architecture is the reviewable part.
- [ ] **Demo video - not recorded.** It needs a human, a screen and a microphone, and none of
      those can be automated. What could be was: `scripts/demo.py` runs the whole Tier 1
      sequence with section headers and optional pauses, so a take needs one command rather
      than five typed live. `--check` runs it headless and asserts the numbers printed in
      `docs/demo-script.md` match a real run - that check is in CI, and it exists because those
      transcripts were already stale once, describing 32 scenarios and 14 findings long after
      the corpus had moved to 50 and 19.
- [x] Final evaluation report - `docs/evaluation-report.md`. Precision and recall per
      evaluator, corpus coverage, minimisation statistics, and a section on why 1.00 precision
      over 25 hand-authored fixtures is a regression ratchet and no evidence of accuracy.
- [x] Security architecture write-up - `docs/security-architecture.md`. Trust boundaries,
      identity and authorisation, the secrets lifecycle, egress and SSRF, failing safe, supply
      chain, and a table of known gaps.

**Exit:** a stranger can clone the repository, run the demo, and understand the design in
fifteen minutes. `python scripts/demo.py` is that demo, and CI asserts it still does what the
script says it does.

---

## Corpus targets

Acceptance is 100 authored templates with a per-suite floor. **Met: 124 authored, every floor
cleared.**

| Suite | Authored | Floor |
|---|---|---|
| Direct injection | 20 | 20 |
| Indirect injection | 20 | 20 |
| Tool abuse | 15 | 15 |
| Data leakage | 15 | 15 |
| Cross-tenant | 13 | 10 |
| Approval bypass | 10 | 10 |
| Improper output handling | 10 | - |
| Memory poisoning | 10 | - |
| Unbounded consumption | 6 | - |
| Tool-result poisoning | 5 | - |
| **Total** | **124** | **100** |

Unbounded consumption and output handling share a floor of 10 in the specification; between
them they hold 16.

Templates expand into scenarios through mutation, and the count is not reported that way: 124
templates at `--variants 4` executes 496 scenarios, but that is 124 distinct ideas. Counting
mutations is how a corpus doubles on paper without testing anything new.

The more useful number is smaller. Of the 124, **48 have ever produced a finding** against a
live target (`scripts/check_corpus_coverage.py`); the other 76 are silent against every demo
target and may be correct-but-inapplicable or may be broken. Nothing distinguishes those two
cases, so they are not counted as coverage. **Zero flag a hardened target**, which is the
number deciding whether the corpus is usable at all.

Reaching 100 took two things that were not more YAML. Memory poisoning needs a target where a
fact written in one session is read in the next, so the RAG agent had to exist first; improper
output handling needed both sinks the evaluator recognises and an agent that carries a
document's text into a tool argument. A suite whose templates cannot fire inflates this table
and measures nothing.

The demonstrated count moved twice on the way here, and only one of those moves was progress.
It first read 54, then 45 after the RAG target's durable memory was namespaced per session -
that number had been inflated by scenarios reading each other's planted facts, and the fix
took nine spurious demonstrations away. It then reached 48 once the support agent learned to
take a literal search term from a document, which is what let the output-handling suite fire
at all. A gate whose number can drift on its own is worse than no gate, so the drift is
recorded here, and not smoothed over.

## Explicitly out of scope

Network vulnerability scanning, port scanning, malware analysis, exploiting third-party
systems, autonomous pentesting, SQL injection scanning of external sites, automatic execution
of destructive remediation, a custom model, Kubernetes, support for every agent framework, and
any guarantee of complete protection against prompt injection.

That last one is not modesty. Prompt injection is not solved, and a tool claiming to guarantee
protection against it would be lying.
