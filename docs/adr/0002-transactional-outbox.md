# ADR 0002 - Transactional outbox with at-least-once delivery

**Status:** accepted
**Date:** 2026-08-02

## Context

Creating a scan does two things: write a row, and tell the engine to start work. Done naively
these are two operations against two systems, and they can half-succeed:

- **Row written, event lost.** The scan sits at QUEUED forever. A CI job polls until it times
  out. Nobody can tell this from a scan that is merely slow.
- **Event published, row rolled back.** The engine starts attacking a target on behalf of a
  scan that does not exist.

The second is worse. AgentShield generates adversarial traffic against real systems, so a
phantom scan is unauthorised traffic.

## Decision

**Transactional outbox.** The scan row and an `outbox_entry` are written in one transaction. A
scheduled relay claims due entries with `FOR UPDATE SKIP LOCKED`, publishes to Kafka, and marks
them published only after the broker acknowledges.

**Delivery is at-least-once, and consumers are idempotent.** Exactly-once would require the
broker ack and the `published_at` update to be one atomic operation across two systems, which
is not available. Rather than pretend otherwise, duplicates are treated as the normal case:

- `processed_event` claims each `eventId` by primary key inside the handler's transaction. Two
  consumers racing on the same duplicate cannot both pass - a `SELECT`-then-`INSERT` check
  would let them.
- Findings additionally deduplicate on `(scan_id, fingerprint)`, catching the same defect
  arriving under two different event ids after an engine-side retry.

**Failures are parked, not retried forever.** Exponential backoff capped at five minutes;
after the configured attempts the entry moves to `dead_letter` and stops. A poison message
never blocks the partition behind it.

## Options considered

**Kafka transactions.** Real exactly-once *within Kafka*, but the database write is still
outside the transaction, so the fundamental problem is unsolved. More operational complexity
for a partial fix.

**Publish after commit (`@TransactionalEventListener`).** Simple, and loses events on a crash
between commit and publish. That window is small and it is exactly the window that matters.

**Debezium / CDC.** Correct and powerful. An entire additional deployment for one table's worth
of events at this scale.

**Outbox.** One table, one scheduled job, no new infrastructure.

## Consequences

**Good.** No lost or phantom events. Publication survives a broker outage - entries accumulate
and drain on recovery. `outbox.pendingCount()` is a direct, alertable health signal: a growing
backlog means Kafka is unreachable, and it says so before anyone notices scans hanging.
`SKIP LOCKED` lets several control-plane instances relay concurrently with no coordination.

**Bad.** Publication latency is bounded by the poll interval (500ms default). Every consumer
must be idempotent, forever, including ones written by people who were not here for this
decision - hence `ProcessedEventGuard` being a shared component, never a convention. The
outbox table needs pruning; the partial index on unpublished rows keeps the hot query fast
regardless.

**Accepted risk.** An entry that exhausts its attempts is marked published so the relay stops,
with the `dead_letter` row becoming the record of it. That is a deliberate trade: the alternative
leaves it pending forever and grows the index without bound.

## Revisit if

Sub-100ms publication latency is ever needed, or the event volume outgrows a single relay's
poll. Both would point at CDC.
