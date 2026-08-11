# Threat model

Two threat models live here. The first is what AgentShield **looks for** in the systems it
tests. The second is what threatens **AgentShield itself** - a tool that generates adversarial
input and holds customers' target credentials is a target in its own right.

---

## Part 1 - what AgentShield tests for

### Trust boundaries in an agentic system

```
        untrusted                       semi-trusted                    trusted
  ┌──────────────────┐          ┌────────────────────────┐      ┌──────────────────┐
  │ user message     │          │ model output           │      │ system prompt    │
  │ retrieved docs   │ ───────► │ tool arguments         │ ───► │ tool handlers    │
  │ tool results     │          │ final answer           │      │ backend + data   │
  │ long-term memory │          └────────────────────────┘      └──────────────────┘
  └──────────────────┘
```

The failure that defines the category: **content crossing from the left column into the
instruction space.** Everything on the left is data. The moment any of it can decide what the
agent does, the person who controls that content controls the agent.

The second failure: treating the middle column as trusted. Model output flowing unvalidated
into SQL, a shell, a URL or a recipient field is the classic injection bug with a new source.

### Adversaries

| Adversary | Reaches | Wants |
|---|---|---|
| External user | The chat surface | System prompt, other users' data, free actions |
| Content author | Documents, tickets, emails the agent retrieves | Exfiltration without ever talking to the agent |
| Compromised tool / MCP server | Tool results, tool descriptions | Steering every agent that connects |
| Malicious tenant | Their own workspace | Other tenants' records |
| Insider | Prompts, policies | Actions above their role |

The content author is the one people underestimate. They never interact with the system. They
write a support article, or a review, or send an email that gets indexed - and the agent brings
their instructions inside the trust boundary on someone else's behalf.

### Attack surface by category

| Category | Entry point | What a secure system does |
|---|---|---|
| Direct injection | User message | Refuses; system prompt not overridable by content |
| Indirect injection | Retrieved documents | Treats retrieved text as data; no tool selection from it |
| Tool-result poisoning | Tool responses | Same, with less inherited trust than a document |
| Memory poisoning | Long-term memory writes | Provenance, tenant scope, confidence on every stored fact |
| Excessive agency | Tool inventory | Narrow tools, backend authorisation, read/write separation |
| Data leakage | Tool results → outbound tools | Redaction at the tool boundary; no read→send path in one session |
| Cross-tenant | Object identifiers | Tenant from the session, enforced at the data layer |
| Approval bypass | Side-effecting tools | Gate in the handler, bound to argument hash, single-use |
| Unbounded consumption | Loops, retries | Ceilings enforced by the runtime, cancellation propagates |
| Improper output handling | Tool arguments | Parameterise and validate at the sink |

### Assumptions

- The target may be non-deterministic; a single clean pass is weak evidence of safety.
- The target may lie about its own capabilities. Discovered tools are cross-checked against the
  policy, and disagreement is itself reported.
- Sandboxing is the target's responsibility. AgentShield never needs a dangerous action to
  actually land - the *decision* is the finding, and blocked execution is one severity band down.

---

## Part 2 - threats to AgentShield

### T1 - Target credential compromise

AgentShield holds credentials for customers' agents, potentially in production.

*Controls:* AES-256-GCM at rest with a per-encryption nonce (`CredentialCipher`); ciphertext
reachable only through `TargetService.decryptConfiguration`, so there is exactly one call site
to audit; secret keys excluded from configuration hashes, responses, logs, spans and reports;
the app refuses to start without a real key outside development profiles.

*Residual:* the key currently comes from configuration. Production wants KMS - the class is
structured so that is a one-file change.

### T2 - AgentShield used to attack a third party

The tool exists to generate adversarial traffic. Pointed at someone else's system it is an
attack tool.

*Controls:* targets are workspace-scoped and explicitly registered; every scan is attributed to
a principal in the audit log; concurrency is capped per workspace; the documentation states
the authorisation requirement in the README, the CLI epilogue and this file.

*Residual:* nothing prevents an operator registering a target they do not own. This is an
organisational control, and pretending otherwise would be dishonest. Full SSRF protection
(refusing link-local, loopback and private ranges) is tracked for stage 5; `requireHttpUrl` is
currently a shallow first guard, and localhost is allowed because the demo target lives there.

### T3 - Cross-tenant leakage inside AgentShield

The bitter irony: a tenant-isolation scanner with a tenant-isolation bug.

*Controls:* `workspace_id` on every tenant-scoped table, so isolation is one predicate rather
than a join; the workspace comes from the authenticated principal and never from a path,
query or header; every cross-package lookup goes through a `require(...)` method that performs
the check, because the way to make a check unskippable is to leave no other way to get the
entity; cross-workspace access returns 404, not 403, so the API is not an oracle for
enumerating other tenants' ids.

### T4 - The scanner leaks the secrets it finds

Findings are pasted into tickets, chat and CI logs.

*Controls:* redaction applied centrally in `Evaluator.run` rather than per evaluator - every
evaluator handles exactly the data it is hunting, so "remember to redact" is a rule the
sixteenth author will forget, and the failure is silent. Three layers: universal secret
shapes, policy-declared patterns, seeded canaries. Evidence names the pattern and shows a
masked excerpt (`AGEN***[len=24]`) - enough to verify, not enough to use. Enforced by
`test_findings_never_contain_raw_canaries`.

### T5 - A false all-clear

The most dangerous output a security tool can produce. "No findings" and "no coverage" look
identical from the outside.

*Controls:* an unreachable target exits 2, never 0; scenarios the target cannot exercise are
reported as skipped with a reason, never as passes; missing judge credentials report `skipped`,
not `passed`; evaluator exceptions surface as visible INFO results over being swallowed;
the report has a Coverage section that states what was *not* tested.

### T6 - Poisoned attack corpus

The datasets are data files. A malicious or careless entry could exfiltrate through the
scanner itself.

*Controls:* `test_no_real_secrets_in_the_corpus` rejects credential-shaped values and any email
domain outside `.test`/`.example`/`.invalid`; `test_expected_detectors_reference_real_evaluators`
rejects typos in expectations; datasets are reviewed like code.

### T7 - Duplicate or lost events

At-least-once delivery means duplicates are the normal case.

*Controls:* `processed_event` claims each event id by primary key inside the handler's
transaction, so two consumers racing on a duplicate cannot both proceed; findings additionally
deduplicate on `(scan_id, fingerprint)`; the outbox marks published only after the broker acks,
so a crash duplicates instead of loses; poison messages go to the DLQ instead of blocking the
partition behind them.

### T8 - Demo targets deployed by accident

They are intentionally insecure, and they are in the repository.

*Controls:* every dangerous action is mocked - nothing is sent, no SQL runs, no money moves;
all data is synthetic canaries; compose binds them to `127.0.0.1` only; the container runs as a
non-root user; the package docstring and every module header say so in the first paragraph.
