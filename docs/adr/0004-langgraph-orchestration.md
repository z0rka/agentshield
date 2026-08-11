# ADR 0004 - LangGraph orchestrates; plain functions do the work

**Status:** accepted
**Date:** 2026-08-02

## Context

A scan is a pipeline with branches: discover, model the threat, select, generate, execute, then
route on the outcome (success, timeout, target error, budget exceeded) into evaluation or
straight to the report.

LangGraph gives checkpointed state so a scan survives a worker restart, streamed node
transitions for the SSE feed, and a trace span per node that lines up with the OpenTelemetry
trace spanning the whole platform. All three are wanted.

The risk is the usual one with orchestration frameworks: the business logic dissolves into the
framework's abstractions, and testing a five-line decision requires standing up a graph runtime.

## Decision

**Nodes are plain `async def (ScanState) -> ScanState` functions** in `graph/nodes.py`. They
import nothing from LangGraph.

**Two executors drive the identical nodes:**

- `graph/graph.py` builds the LangGraph `StateGraph` for production.
- `graph/runner.py` is a sequential executor implementing the same conditional edges in
  ordinary Python.

`runner.py` is the readable definition of the control flow. Every test and the CLI use it, so
the engine has no hard dependency on LangGraph to run a scan - LangGraph is an optional extra.

**State is carried as a single `scan` key** holding the `ScanState` object, over spread
across reducer-managed graph channels. No two nodes write the same field concurrently, so
channel reducers would buy nothing while making node signatures depend on the graph library - 
which is the thing this decision exists to avoid.

## Options considered

**LangGraph-native nodes.** Idiomatic, and every test then needs a graph runtime, and the
pipeline becomes unreadable without knowing the framework.

**No framework.** Simplest, and checkpointing, streaming and per-node tracing would all have to
be built.

**Framework as orchestrator over pure functions.** Chosen. The orchestrator is a detail; the
nodes are the system.

## Consequences

**Good.** Nodes are unit-testable as functions. The control flow is readable without knowing
LangGraph. Swapping the orchestrator - for Temporal, say, when scans need multi-day
human-in-the-loop waits - means writing a third executor, not rewriting the pipeline. Tests run
without the optional dependency.

**Bad.** Two executors can drift. Mitigated by both importing the same `nodes` module and by
the end-to-end tests running through `runner.py` while the graph is exercised separately - but
a node added to one edge list and not the other would not be caught automatically. Worth a
structural test in stage 3.

**Accepted.** Single-key state means LangGraph's channel-level checkpointing is coarse: the
whole `ScanState` is one unit. For scan-level resume that is exactly the right granularity.

## Revisit if

Scans need to suspend for human input mid-flight, or partial-state resume becomes necessary.
Both point at Temporal instead of at finer-grained LangGraph channels.
