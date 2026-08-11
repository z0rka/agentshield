# ADR 0001 - Split the control plane (Java) from the security engine (Python)

**Status:** accepted
**Date:** 2026-08-02

## Context

AgentShield needs two things that pull in opposite directions.

It needs durable multi-tenant state: users, workspaces, encrypted target credentials, scan
lifecycle, audit trail, transactional messaging. This is slow-changing, schema-bound work where
correctness under concurrency and failure matters more than iteration speed.

It also needs to orchestrate LLM-driven attacks against agents, speak MCP, mutate payloads, and
evaluate trajectories. That ecosystem - LangGraph, the MCP SDK, the model clients - is Python,
and is not moving. This half changes weekly and is driven by data files more than by code.

## Options considered

**All Python.** One language, one deployment. But multi-tenant transactional state management
would mean rebuilding what Spring Data, Spring Security and Spring Kafka already do correctly,
and the outbox/idempotency machinery is exactly the sort of thing you want on a well-worn path.

**All Java.** Excellent for the control plane. But the agent-security tooling would have to be
reimplemented or shelled out to, and every new technique in this field lands in Python first.

**Split.** Two deployables, one Kafka boundary.

## Decision

Split, with an explicit ownership rule:

- **Java owns state.** Identity, authorisation, target configuration, scan lifecycle,
  persistence, messaging, reports, audit.
- **Python owns judgement.** Attack generation, mutation, adapters, trajectory analysis,
  evaluators, remediation.

**The Python engine is never the source of truth for scan status.** It reports; the control
plane records. This is the load-bearing part of the decision.

## Consequences

**Good.** Each half uses the ecosystem built for its job. The engine is stateless, so a worker
can be killed and replaced mid-scan and the replacement resumes from what PostgreSQL says
already completed. The Kafka boundary is a natural place for backpressure and retries. The
corpus and evaluators evolve without touching schema or migrations.

**Bad.** Two languages to maintain and two CI pipelines. Shared enums exist in both - mitigated
by `contracts/validate.py`, which fails the build when they drift, but it is a mitigation and
not a cure. Local development needs both toolchains, though the Python half runs standalone,
which is what keeps the contribution path short.

**Accepted risk.** The Kafka boundary adds latency and a failure mode that an in-process call
does not have. Acceptable: scans take seconds to minutes, so tens of milliseconds of queueing
is noise, and the durability the boundary buys is worth more than the latency it costs.

## Revisit if

The engine ever needs to make an authorisation decision. That would mean the ownership split is
in the wrong place, not that the split was wrong.
