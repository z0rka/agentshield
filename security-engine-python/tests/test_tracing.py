"""The shape of the trace a scan emits.

Asserted against an in-memory exporter, not a live collector. A running Jaeger would
only prove that OTLP works, which is library code; what can actually break here is the span
tree, the attribute names the dashboards key on, and whether a secret ever reaches a span.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentshield import telemetry
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.models.common import AttackCategory

TARGET_CONFIG = {"base_url": "http://demo-target", "tenant_id": "tenant-a"}


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    telemetry.install_tracer(provider.get_tracer("agentshield"))
    try:
        yield exporter
    finally:
        telemetry.install_tracer(None)


@pytest.fixture
async def scanned(vulnerable_adapter, policy, spans) -> InMemorySpanExporter:
    state = ScanState(
        scan_id="scan-trace",
        policy=policy,
        target_config=dict(TARGET_CONFIG),
        requested_categories={AttackCategory.INDIRECT_PROMPT_INJECTION},
        max_scenarios=2,
    )
    state.adapter = vulnerable_adapter
    await run_scan(state)
    return spans


def _names(exporter: InMemorySpanExporter) -> list[str]:
    return [span.name for span in exporter.get_finished_spans()]


async def test_a_scan_emits_one_root_span(scanned):
    roots = [s for s in scanned.get_finished_spans() if s.parent is None]

    assert len(roots) == 1
    assert roots[0].name == "scan"
    assert roots[0].attributes["scan.id"] == "scan-trace"


async def test_every_pipeline_node_is_a_span(scanned):
    names = set(_names(scanned))

    for node in ("load_target", "discover_capabilities", "execute_attack", "classify_finding"):
        assert f"node.{node}" in names


async def test_attacks_and_evaluators_appear_under_the_scan(scanned):
    names = _names(scanned)

    assert "attack" in names
    assert "evaluate" in names

    attack = next(s for s in scanned.get_finished_spans() if s.name == "attack")
    assert attack.attributes["attack.category"] == "INDIRECT_PROMPT_INJECTION"
    assert attack.attributes["target.session.id"]


async def test_the_scan_span_carries_the_outcome(scanned):
    root = next(s for s in scanned.get_finished_spans() if s.parent is None)

    assert root.attributes["scan.outcome"] == "success"
    assert root.attributes["scan.findings"] >= 1
    assert "estimated.cost" in root.attributes


async def test_no_span_carries_a_canary_or_a_credential(scanned):
    """A security tool leaking the secret it found into its own trace is the worst outcome."""
    canary = "AGENTSHIELD_SECRET_7F93A"

    for span in scanned.get_finished_spans():
        for key, value in (span.attributes or {}).items():
            assert canary not in str(value), f"{span.name}.{key} leaked the canary"
            assert not any(
                banned in key.lower()
                for banned in ("secret", "token", "password", "credential", "authorization")
            ), f"{span.name} carries a forbidden attribute {key}"


def test_spans_are_inert_until_a_tracer_is_installed():
    """The default. Instrumentation must cost nothing when tracing was never configured."""
    telemetry.install_tracer(None)

    with telemetry.span("scan", **{"scan.id": "x"}) as current:
        assert current is None
        telemetry.set_attributes(current, **{"anything": "safe"})

    assert telemetry.current_traceparent() is None


def test_a_traceparent_can_be_adopted_and_released(spans):
    with telemetry.span("producer"):
        carried = telemetry.current_traceparent()

    assert carried is not None and carried.startswith("00-")

    with telemetry.continue_trace(carried), telemetry.span("consumer"):
        pass

    finished = {s.name: s for s in spans.get_finished_spans()}
    assert finished["consumer"].context.trace_id == finished["producer"].context.trace_id


def test_an_absent_traceparent_starts_a_fresh_trace(spans):
    with telemetry.continue_trace(None), telemetry.span("orphan"):
        pass

    orphan = next(s for s in spans.get_finished_spans() if s.name == "orphan")
    assert orphan.parent is None


def test_forbidden_attributes_are_stripped_before_export(spans):
    with telemetry.span("probe", **{"scan.id": "ok", "api_key": "leak", "tool.name": "x"}):
        pass

    probe = next(s for s in spans.get_finished_spans() if s.name == "probe")
    assert probe.attributes["scan.id"] == "ok"
    assert probe.attributes["tool.name"] == "x"
    assert "api_key" not in probe.attributes


@pytest.fixture(autouse=True)
def _reset_global_provider() -> Iterator[None]:
    """Leave the process as we found it: the OTel provider is global and set-once."""
    yield
    telemetry.install_tracer(None)
    otel_trace._TRACER_PROVIDER = None  # noqa: SLF001 - no public reset exists
