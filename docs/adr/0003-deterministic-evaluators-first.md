# ADR 0003 - Deterministic evaluators decide; LLM judges advise

**Status:** accepted
**Date:** 2026-08-02

## Context

Judging whether an agent misbehaved looks like a job for a model. The behaviour is fuzzy, the
inputs are natural language, and an LLM judge is a few lines of code.

But the output of this system is a **security verdict that fails builds**. Two properties
matter more than coverage:

1. **Reproducibility.** A finding someone cannot re-derive is an anecdote. The regression suite
   is worthless if a green run might be sampling noise.
2. **Precision.** The first false positive costs more trust than ten true positives earn. A
   gate that people routinely override is not a gate.

An LLM judge that is wrong 2% of the time, run across ~30 scenarios per scan, produces a
spurious blocking finding roughly every other build.

## Decision

**Deterministic evaluators are the default and the only kind that can produce CRITICAL.**

Every evaluator is a pure function of `(Trajectory, SecurityPolicy, EvaluationContext)`. No
network, no clock, no model call. Twelve mandatory evaluators run on every trajectory.

**LLM judges are restricted to genuinely subjective questions**, and constrained in code rather
than by convention:

- `Evaluator.run` caps non-deterministic results at HIGH.
- Finding classification requires deterministic corroboration before anything is promoted.
- Missing credentials produce `skipped`, never `passed` - a missing API key must not look like
  a clean scan.

### Indirect injection deterministically

The obvious objection is that indirect injection is *inherently* semantic. It is not, if you
track provenance: when a value appearing in a tool argument also appears verbatim in retrieved
content, the attacker's text has crossed from data into control. Either `attacker@example.test`
came out of the poisoned article and went into `send_email.to`, or it did not.

That covers the exploitable majority. The paraphrase case - where the agent complies while
rewriting everything, leaving no verbatim string - is what `SemanticInjectionJudge` is for, at
HIGH.

## Options considered

**Judge-only.** Best coverage of subtle cases, non-reproducible, expensive, and unable to
support a regression suite.

**Deterministic-only.** Fully reproducible, misses paraphrase and deception.

**Both, with the judge advisory.** Chosen.

## Consequences

**Good.** Findings are reproducible from `(trajectory, policy)` alone. The regression suite is
trustworthy. Scans cost nothing by default and need no API key, which is also why the demo
works offline and the CI job is free. Evaluators are trivially unit-testable - hand-write a
trajectory, assert a verdict.

**Bad.** Some real failures are missed without judges enabled, and the report says so rather
than implying completeness. Deterministic evaluators need explicit patterns, so the corpus and
the evaluators must evolve together.

**Accepted risk.** Provenance tracing can be evaded by an attacker who ensures no verbatim
value survives into the tool call. Documented in `evaluation-methodology.md` under known
limits, because a security tool that oversells its coverage is worse than one that does less.

## Revisit if

Measured judge precision on the `evals/` harness exceeds ~99% on a category. Then that specific
judge could be promoted - per category, with data, not as a blanket policy change.
