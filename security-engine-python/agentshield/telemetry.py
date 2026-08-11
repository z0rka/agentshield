"""Tracing and structured logging.

One trace spans Java API -> Kafka -> Python worker -> LangGraph node -> adapter -> target ->
tool -> evaluator -> finding. That single trace is what turns "the agent leaked data" into
"here is the retrieval that caused it, 340ms in".

The attribute allowlist below is enforced, not advisory. A security tool that leaks the
secrets it is hunting into its own traces has failed in the most embarrassing way available.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

#: Span attributes carried through the whole pipeline. See docs/architecture.md §observability.
SPAN_ATTRIBUTES = (
    "workspace.id",
    "project.id",
    "target.id",
    "scan.id",
    "scenario.id",
    "attack.category",
    "attack.seed",
    "target.session.id",
    "tool.name",
    "evaluator.name",
    "finding.severity",
    "model.name",
    "prompt.version",
    "token.input",
    "token.output",
    "estimated.cost",
    "retry.count",
)

#: Never emitted, whatever the caller passes.
FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "password",
        "secret",
        "credentials",
        "headers",
        "cookie",
        "set-cookie",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with trace correlation when a span is active."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in getattr(record, "context", {}).items():
            if key.lower() not in FORBIDDEN_ATTRIBUTES:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())


def sanitize(attributes: dict[str, Any]) -> dict[str, Any]:
    """Drop anything on the denylist before it reaches a span or a log line."""
    return {
        key: value
        for key, value in attributes.items()
        if key.lower() not in FORBIDDEN_ATTRIBUTES
        and not any(bad in key.lower() for bad in ("secret", "token", "password", "credential"))
    }


#: Set once by `configure_tracing`. Without it every span below is a no-op, which is what
#: keeps OpenTelemetry an optional dependency of running a scan.
_tracer: Any | None = None


def install_tracer(tracer: Any | None) -> None:
    """Point the module at a tracer, or at nothing.

    The seam that lets a test assert the shape of the trace against an in-memory exporter,
    and lets it put things back afterwards. Reaching into the module global from outside
    would work too, right up until this file changes.
    """
    global _tracer
    _tracer = tracer


def configure_tracing(
    endpoint: str | None = None, service_name: str = "agentshield-security-engine"
) -> bool:
    """Install a tracer provider exporting to the collector. Returns whether it took effect.

    Called once at process start. Until this runs, `trace.get_tracer` hands back a no-op
    tracer: the previous version asked for a tracer without ever configuring a provider, so
    the code read as instrumented and exported nothing.
    """
    global _tracer

    endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logging.getLogger(__name__).warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but the otel extra is not installed"
        )
        return False

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    install_tracer(trace.get_tracer("agentshield"))
    return True


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Start a span, or do nothing when tracing was never configured.

    Yields the span so a caller can add attributes it only learns later, such as the number
    of findings a scan produced.
    """
    if _tracer is None:
        yield None
        return

    with _tracer.start_as_current_span(name) as current:
        for key, value in sanitize(attributes).items():
            current.set_attribute(key, value)
        yield current


def set_attributes(current: Any, **attributes: Any) -> None:
    """Attach attributes to a span that may be None. Saves a null check at each call site."""
    if current is None:
        return
    for key, value in sanitize(attributes).items():
        current.set_attribute(key, value)


def current_traceparent() -> str | None:
    """The active span as a W3C `traceparent`, for carrying across a queue.

    Trace context does not survive a Kafka hop by itself. The producer records this string on
    the message and the consumer restores it, which is what joins the two halves into one
    trace, not two unrelated ones.
    """
    if _tracer is None:
        return None
    from opentelemetry import trace

    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return (
        f"00-{trace.format_trace_id(context.trace_id)}-"
        f"{trace.format_span_id(context.span_id)}-"
        f"{'01' if context.trace_flags.sampled else '00'}"
    )


@contextmanager
def continue_trace(traceparent: str | None) -> Iterator[None]:
    """Adopt a `traceparent` received from elsewhere for the duration of the block."""
    if _tracer is None or not traceparent:
        yield
        return

    from opentelemetry import context as otel_context
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

    token = otel_context.attach(
        TraceContextTextMapPropagator().extract({"traceparent": traceparent})
    )
    try:
        yield
    finally:
        otel_context.detach(token)


def log_context(**attributes: Any) -> dict[str, Any]:
    """Build the `extra={"context": ...}` payload for a structured log call."""
    return {"context": sanitize(attributes)}
