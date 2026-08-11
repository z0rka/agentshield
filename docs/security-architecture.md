# Security architecture

How AgentShield's own security properties are enforced, and where enforcement is structural
and not a rule someone has to remember.

[threat-model.md](threat-model.md) lists the threats and the controls answering each one. This
document is the other half: the shape of the system that makes those controls hold, and the
decisions behind it. Where a control is documented there, this page says why it lives where it
does, without repeating it.

## The design rule

**A security check that can be skipped will be skipped, so the code is arranged to leave no
other path.** Not a slogan - a constraint that decides where classes go.

Three places it shows up, each replacing a rule with a structure:

| Instead of | The structure |
|---|---|
| "Remember to redact evidence" | Redaction runs in `Evaluator.run`, the one place every result passes through. An evaluator cannot emit an unredacted finding because it never touches the output path. |
| "Remember to check the workspace" | `AccessGuard.requireVisible` is the only way to obtain a workspace-scoped entity. There is no unchecked getter to reach past. |
| "Remember to validate the URL" | `TargetService.decryptConfiguration` is the single call site that turns stored ciphertext into a usable target, and `SsrfGuard` sits inside it. |

The test is always the same question: *what would a competent person forget on a Friday, and
does the code let them?* Every control below is placed to answer it.

## Trust boundaries

```
   operator            control plane            engine worker           target
  ┌────────┐   API    ┌──────────────┐  Kafka  ┌─────────────┐  HTTP  ┌──────────┐
  │ CLI/CI │ ───────► │ authn, authz │ ──────► │ scan runner │ ─────► │  agent   │
  └────────┘  token   │ policy, data │  event  │ evaluators  │  MCP   │ under    │
                      └──────────────┘         └─────────────┘        │ test     │
                             │                        │               └──────────┘
                        PostgreSQL              adversarial output          ▲
                                                        │                   │
                                                        └── untrusted ──────┘
```

Three boundaries, and the third is the one people miss.

1. **Operator → control plane.** Authenticated, workspace-scoped, permission-checked.
2. **Control plane → worker.** Asynchronous over Kafka. The worker is trusted code but runs
   with the least it needs: it never sees another workspace's data because the dispatched event
   carries only the one scan.
3. **Target → AgentShield.** *The target's responses are untrusted input to us.* This inverts
   the usual reading. A scanner that parses attacker-influenced trajectories, renders them into
   reports and pastes those into CI logs is downstream of the thing it is attacking. Tool
   results, tool descriptions and final answers are all attacker-controlled by construction -
   that is the point of the scan - so they are treated as data everywhere: never evaluated,
   never interpolated into a shell or rendered unescaped, and always redacted before they
   reach a report.

## Identity and authorisation

**Authentication.** API tokens, hashed at rest, resolved by `ApiAuthenticationFilter` into a
`Principal` carrying a workspace id and a role. No session state; a CI job and a human use the
same mechanism.

**Authorisation.** Three roles, each defined as the set of permissions it grants. No string
comparison at call sites:

| Role | Read | Write | Run scan | Administer |
|---|---|---|---|---|
| Viewer | yes | - | - | - |
| Engineer | yes | yes | yes | - |
| Owner | yes | yes | yes | yes |

`RUN_SCAN` is separate from `WRITE` on purpose. A scan generates adversarial traffic against a
real system, so "read-only" has to mean it: a Viewer who could start a scan is not read-only
in any sense the word is used outside software.

**Workspace scoping.** `workspace_id` is a column on every tenant-scoped table, so isolation is
a single predicate. The alternative is a join that someone eventually writes wrong.
The workspace comes from the authenticated principal and **never** from a path, query or
header - the API has no way to
express "act on workspace X" because there is no parameter for it.

**Cross-workspace access returns 404.** Not 403. A 403 confirms the resource exists, which
turns the API into an oracle for enumerating another tenant's ids. This one is easy to get
wrong precisely because 403 feels more truthful.

The bitter irony is not lost: a tenant-isolation scanner with a tenant-isolation bug would be
the funniest possible outcome. `AccessGuard` exists so there is exactly one place to audit.

## Secrets

**At rest.** Target credentials are encrypted with AES-256-GCM, fresh nonce per encryption
(`CredentialCipher`). The application refuses to start without a real key outside development
profiles - a placeholder key that silently works in production is worse than no encryption,
because it looks encrypted.

**In transit through the system.** Secret-valued configuration keys are excluded from
configuration hashes, API responses, logs, spans and reports. Exclusion is by key classification
at the model layer, so a new endpoint returning a target does not have to remember.

**In findings.** Three redaction layers - universal secret shapes, policy-declared patterns,
seeded canaries - applied centrally. Evidence shows a masked excerpt (`AGEN***[len=24]`):
enough for a human to confirm the match and too little to use.
`test_findings_never_contain_raw_canaries` is the assertion; a security tool that reprints
the secret it found has leaked it twice.

**In the test suite.** An autouse fixture strips `ANTHROPIC_API_KEY` and the other billable
credentials from every test. This is here because the suite once did reach a paid API: the CLI
tests call `main()`, `main()` calls `load_dotenv()`, and `load_dotenv` writes `.env` into
`os.environ` for the whole process. Correct for a command that runs once and exits; quietly
expensive inside pytest.

**Residual.** The encryption key comes from configuration. Production wants KMS. `CredentialCipher`
is structured so that is a one-file change. Until it is made this is a real gap dressed up as a
"future enhancement".

## Egress: the scanner as an SSRF engine

A scanner takes a URL from a user and fetches it. That is the definition of SSRF, and the
feature cannot be removed because fetching the target *is* the product.

`SsrfGuard` resolves the hostname and checks the **resolved addresses**, not the string.
Pattern-matching a URL is defeated by `http://169.254.169.254.nip.io`, by decimal-encoded IPs,
and by any domain an attacker controls and points wherever they like. Refused: loopback,
link-local (including the cloud metadata endpoints at `169.254.169.254`), private ranges,
unique-local IPv6, and non-HTTP schemes.

**Stated gap: DNS rebinding is not closed.** Validation and connection are two separate
lookups, and an attacker controlling a domain can answer them differently. Closing it means
pinning the connection to the address validation approved, which is a change in the HTTP
client and not in the guard. It is written down in both the guard and the threat model, because a
guard whose gaps are unstated reads as a guarantee it does not make.

**Localhost is allowed in the development profile.** The demo target lives there. In any other
profile it is refused.

## The dangerous-by-design parts

**The attack corpus** is data, loaded and executed. Two tests treat it as untrusted input:
`test_no_real_secrets_in_the_corpus` rejects credential-shaped values and any email domain
outside `.test` / `.example` / `.invalid`, and `test_expected_detectors_reference_real_evaluators`
rejects typos in expectations. Datasets are reviewed like code because they are code.

**The demo targets** are intentionally insecure and they ship in this repository. Every
dangerous action is mocked - nothing is sent, no SQL runs, no money moves - all data is
synthetic canaries, compose binds them to `127.0.0.1`, the container runs as a non-root user,
and the first paragraph of every module says so. `GET /_demo/side-effects` exists so a
demonstration can show nothing escaped, which beats asserting it from a stage.

**AgentShield pointed at a system you do not own is an attack tool.** Targets are
workspace-scoped and explicitly registered, every scan is attributed to a principal in the
audit log, and concurrency is capped per workspace. None of that stops an operator registering
a target they have no authorisation to test. That is an organisational control, and describing
it as a technical one would be dishonest.

## Failing safe

The most dangerous output a security tool can produce is a false all-clear, because "no
findings" and "no coverage" look identical from outside.

| Situation | Reported as |
|---|---|
| Target unreachable | Exit 2 with the cause named. Never 0. |
| Scenarios selected but none produced a trajectory | Exit 2. |
| Scenario inapplicable to this target | Skipped, with a reason, in the Coverage section |
| Judge credentials missing | `skipped`. A judge that could not run is never a judge that found nothing |
| Evaluator raised | A visible INFO result. The exception is surfaced, not caught and dropped |
| No authenticated tenant available | "cross-tenant access could not be checked", never "isolation held" |
| Regression with zero coverage | Refuses to compare. Every baseline finding resolving is exactly what a broken pipeline produces. |

Exit codes are the contract: **0 clean, 1 findings at or above the gate, 2 the scan could not
be completed.** The third exists so a broken run never reads as a clean one, and it is enforced
by one function shared across `scan`, `regression` and `ci` - the check living at one call site
out of three is how the regression command once printed PASSED on a scan that never ran.

## Supply chain and build

- Dependencies are pinned; the Python engine and CLI install from the checkout in CI, so a
  pull request changing an evaluator is gated by the evaluator it changed.
- The GitHub Action is **composite, not Docker**. A Docker action would pin the scanner to a
  published image, which for a security tool means testing last month's release against this
  week's code.
- CI runs on every push: lint, house style, unit tests, contract validation against the OpenAPI
  spec, the evaluator precision gate, the corpus coverage ratchet, a full scan of both demo
  targets, the Java build with Testcontainers, and a multi-process smoke test that stubs no
  boundary at all.
- No secrets are required to run the build. The LLM judges are excluded from the standard
  build for exactly this reason; they can be replayed from cassettes with no key and no cost.

## Deployment posture

The ECS/Fargate definition in [infra/aws](../infra/aws) encodes the boundaries above:

- The control plane runs in private subnets; only the load balancer is public.
- The engine worker has **no inbound rules at all**. It reaches Kafka and the targets it is
  told to scan, and nothing reaches it.
- Task roles are per-service and least-privilege; the worker cannot read the credential
  encryption key, because it never decrypts anything.
- Database and broker are reachable only from the service security groups.
- Secrets arrive through Secrets Manager references, never as plaintext environment variables
  in the task definition, where they would be readable by anyone with `ecs:DescribeTaskDefinition`.

That configuration has never been applied. See the README in that directory for what is
therefore unverified.

## Known gaps

Listed because a security document with no gaps section is a marketing document.

| Gap | Consequence | What closing it takes |
|---|---|---|
| Encryption key in configuration | Key is as protected as the config store | KMS in `CredentialCipher` |
| DNS rebinding | A target host can answer validation and connection differently | Pin the connection to the validated address |
| Target ownership unverified | An operator can scan a system they do not own | Organisational; technical options are all weak |
| No rate limiting on the API | A token can start scans until the concurrency cap absorbs it | Per-principal limiter at the filter |
| Audit log is append-only by convention only | A database-level compromise can rewrite history | Append-only table grants, or external shipping |
| Infrastructure never applied | Every claim in the previous section is unverified | An AWS account |

## Related

- [threat-model.md](threat-model.md) - threats and their controls, both directions
- [architecture.md](architecture.md) - components, data model, event flow
- [severity-model.md](severity-model.md) - how findings are ranked
- [evaluation-report.md](evaluation-report.md) - what the detection is actually worth
