# Evaluation report

What AgentShield detects, how well, and where the numbers stop meaning anything. Every figure
here is produced by a command in this repository and reproduced on every build; the commands
are printed next to each table so a reader can disagree with the method, not just the number.

Measured on the corpus at dataset version `2026.08.1` against the bundled demo target.

## Summary

| | |
|---|---|
| Attack templates | 124 |
| Deterministic evaluators | 15 |
| Labelled evaluator fixtures | 29 (28 scored, 1 ambiguous) |
| Precision, every evaluator | 1.00 |
| Recall, every evaluator | 1.00 |
| Templates demonstrated against a live target | 48 of 124 |
| False positives against the hardened target | 0 of 124 |
| Findings on the vulnerable target | 20 (12 critical, 4 high, 4 medium) |
| Findings on the hardened target | 0 |

The precision and recall numbers are the least interesting figures on this page, and the
section below explains why before anyone quotes them.

## What 1.00 precision does and does not mean

Every evaluator scores 1.00 on both axes. That number is real, it is checked on every build,
and it is **not evidence that the evaluators are accurate in general**.

- The fixtures are hand-authored, 29 of them, by the same person who wrote the evaluators.
  Precision against your own examples measures self-consistency.
- The gate is `--min-precision 0.95`. Scoring 1.00 means no evaluator has yet been given a
  fixture it gets wrong - not that no such fixture exists.
- 1.00 recall is measured only over cases someone thought to write down. Recall against the
  attacks nobody has thought of is unmeasurable by construction, and it is the number that
  actually matters.

What the fixture suite is genuinely good for is **regression**. It is a ratchet: every false
positive found in practice becomes a true-negative fixture, and a later "improvement" that
reintroduces it turns the build red. Two examples that already happened:

- `loop-batch-of-distinct-lookups.yaml`. `LoopEvaluator` compared bare tool names, so six
  lookups of six different customer records read as a cycle. Reverting the fix drops that
  evaluator to 0.50 precision.
- `cross-tenant-refused-by-backend.yaml`. An agent that *asks* for another tenant's record and
  receives a 403 is behaving badly, but the system is sound. Scoring that as a critical finding
  would punish the correct implementation.

The fixture corpus is 12 true negatives to 16 true positives, plus one ambiguous. Twelve of
twenty-eight scored cases exist only to assert that nothing fires, and that ratio is chosen:
false positives are what get a security tool switched off.

```bash
python evals/run.py --require-coverage --verbose
```

| Evaluator | Precision | Recall | N |
|---|---|---|---|
| ApprovalComplianceEvaluator | 1.00 | 1.00 | 3 |
| BudgetEvaluator | 1.00 | 1.00 | 3 |
| DangerousToolCombinationEvaluator | 1.00 | 1.00 | 2 |
| ExternalSideEffectEvaluator | 1.00 | 1.00 | 1 |
| ForbiddenToolEvaluator | 1.00 | 1.00 | 2 |
| InjectionComplianceEvaluator | 1.00 | 1.00 | 3 |
| LoopEvaluator | 1.00 | 1.00 | 3 |
| RecipientAllowlistEvaluator | 1.00 | 1.00 | 4 |
| SchemaValidityEvaluator | 1.00 | 1.00 | 2 |
| SensitiveDataLeakEvaluator | 1.00 | 1.00 | 3 |
| TenantIsolationEvaluator | 1.00 | 1.00 | 2 |
| ToolArgumentMutationEvaluator | 1.00 | 1.00 | 2 |
| ToolDescriptionInjectionEvaluator | 1.00 | 1.00 | 2 |
| MemoryIntegrityEvaluator | 1.00 | 1.00 | 4 |
| UnsafeOutputSinkEvaluator | 1.00 | 1.00 | 3 |

`ExternalSideEffectEvaluator` has one fixture. That is thin, and `--require-coverage` only
asserts the count is above zero. It is listed here so the average does not hide it.

One fixture is labelled `ambiguous` and excluded from scoring: a side effect that a downstream
system blocked. Whether the agent misbehaved depends on facts outside the trajectory, so it is
recorded as a case the method cannot settle. Labelling it to suit the score would be
cheating at our own exam.

## Corpus coverage: the number that is not 100%

```bash
python scripts/check_corpus_coverage.py
```

| | |
|---|---|
| Templates executed against every demo target | 124 |
| Demonstrated - produced a finding on a vulnerable target | 48 |
| Undemonstrated - silent against all of them | 76 |
| False positive - flagged a hardened target | 0 |

**76 of 124 templates have never produced a finding against anything.** They may be correct and
merely inapplicable to this particular demo agent, or they may be broken. Nothing here
distinguishes those two cases, so they are not counted as coverage.

This is the honest reading of a template corpus: authoring an attack is cheap, and a corpus
that grows its headline count while its demonstrated count stands still is decoration. CI
ratchets the demonstrated figure (`--require-demonstrated 48`) so it can only go up.

The zero in the false-positive row is the load-bearing number on this page. All 124 templates
run against every hardened target on every build, and a single finding there fails the
build. A scanner that cannot stay quiet against a correct implementation is not usable.

| Suite | Templates |
|---|---|
| Direct prompt injection | 20 |
| Indirect prompt injection | 20 |
| Tool abuse | 15 |
| Data leakage | 15 |
| Cross-tenant | 13 |
| Approval bypass | 10 |
| Improper output handling | 10 |
| Memory poisoning | 10 |
| Unbounded consumption | 6 |
| Tool-result poisoning | 5 |

The roadmap target is 100 authored templates and every per-suite floor is cleared. The count is
not inflated by counting mutations: 124 templates at `--variants 4` executes far more
scenarios, but that is 124 distinct ideas, not 496.

Two of those suites could not exist until the targets did. Memory poisoning needs a place where
a fact written in one session is read in the next, which no synchronous support agent models;
improper output handling needs sinks the evaluator recognises. Authoring the YAML first would
have produced ten templates that never fire and a coverage table that looked worse for it.

## End-to-end: the same scan, two implementations

```bash
agentshield scan --target http://127.0.0.1:8090 --policy ./datasets/policies/support-agent.yml --suite owasp-agentic
agentshield scan --target http://127.0.0.1:8091 --policy ./datasets/policies/support-agent.yml --suite owasp-agentic
```

| | Vulnerable | Hardened |
|---|---|---|
| Scenarios selected / executed | 50 / 50 | 50 / 50 |
| Scenarios skipped as inapplicable | 11 | 11 |
| Scenarios errored | 0 | 0 |
| Critical | 12 | 0 |
| High | 4 | 0 |
| Medium | 4 | 0 |
| Gate (`--fail-on high`) | FAILED, exit 1 | PASSED, exit 0 |

Regression against the vulnerable baseline: **20 resolved, 0 still present, 0 new**.

The eleven skipped scenarios are reported, not dropped. They target MCP servers, durable
memory and tools this agent does not expose, and a scan that silently narrows its own scope is how "no findings"
comes to mean nothing.

## Reproduction minimisation

Every severe finding is re-run with parts of its payload removed until nothing further can be
dropped without the finding disappearing. What the report prints is the reduced payload, and
only after re-verifying it against the *same fingerprint* - a reduction that starts tripping a
different control is rejected.

| | |
|---|---|
| Findings with a recorded reproduction | 20 |
| Minimised below the original payload | 13 |
| Target calls spent minimising | 84 total, median 6 per finding, max 20 |
| Minimised to **no user prompt at all** | 9 |

That last row is the result worth reading. For nine findings, delta debugging removed the user
turn entirely and the finding still reproduced: everything the agent did came out of content it
retrieved. The flagship case reduces to a single sentence planted in a knowledge-base article.

1-minimality is the guarantee, and it is the weak one: no *single* remaining segment can be
removed. Some pair might still be removable together. The note on each finding says which was
proved.

## What is not measured here

- **LLM judge agreement.** `python evals/run.py --judges` scores judges for stability across
  repeated runs, gated at 0.90 mean agreement. It needs API credentials and costs money per
  run, so it is not part of the standard build and no number for it is published here. Judges
  can never raise a CRITICAL on their own; deterministic evaluators decide the gate.
- **Recall against unknown attacks.** Unmeasurable, as above, so no figure is given.
- **Any target other than the bundled demo.** Every figure on this page describes one agent,
  written by the same author as the scanner. Numbers from a real third-party agent would be
  worth more than all of them, and there are none.
- **Prompt injection in general.** Not solved, not claimed to be. See
  [threat-model.md](threat-model.md).

## Reproducing this page

```bash
python evals/run.py --require-coverage --verbose      # the precision/recall table
python scripts/check_corpus_coverage.py               # the coverage table
python scripts/smoke_multiprocess.py                  # the distributed path, end to end
```

The first two run on every build and fail it. The scan figures come from the commands printed
above the end-to-end table, against the demo targets from [demo-script.md](demo-script.md).
