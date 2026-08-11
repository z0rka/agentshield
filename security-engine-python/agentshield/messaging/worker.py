"""Kafka-driven scan worker for the Java control plane.

The control plane publishes only identifiers and configuration hashes.  The worker fetches the
actual policy and decrypted target configuration over a narrow internal HTTP endpoint, executes
the scan, then publishes deterministic, redacted events.  Offsets are committed only after the
scan finishes, so killing the worker causes Kafka to deliver the request again.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

import yaml

from agentshield.config import EngineSettings
from agentshield.graph.runner import run_scan
from agentshield.graph.state import ScanState
from agentshield.messaging.contracts import (
    ATTACK_COMPLETED,
    ATTACK_FAILED,
    FINDING_CREATED,
    SCAN_CANCELLED,
    SCAN_COMPLETED,
    SCAN_CREATED,
    SCAN_EVALUATION_REQUESTED,
    SCAN_FAILED,
    SCAN_STARTED,
    DispatchClient,
    EventEnvelope,
    EventPublisher,
)
from agentshield.messaging.dispatch import ControlPlaneDispatchClient
from agentshield.messaging.payloads import attack_payload, finding_payload
from agentshield.messaging.publisher import KafkaEventPublisher
from agentshield.messaging.suites import categories_from_suites
from agentshield.models.common import RunStatus
from agentshield.policies.loader import parse_policy
from agentshield.redaction import redact
from agentshield.telemetry import (
    configure_logging,
    configure_tracing,
    continue_trace,
    current_traceparent,
)

log = logging.getLogger(__name__)

__all__ = [
    "ScanWorker",
    "main",
    "run_worker_forever",
]


class ScanWorker:
    """Turns one ``security.scan.created`` event into a complete result event stream."""

    def __init__(
        self,
        dispatch: DispatchClient,
        publisher: EventPublisher,
        *,
        running: dict[str, ScanState] | None = None,
        runner: Callable[[ScanState], Awaitable[ScanState]] = run_scan,
    ) -> None:
        self.dispatch = dispatch
        self.publisher = publisher
        self.running = running if running is not None else {}
        self.runner = runner

    async def process(self, source: EventEnvelope) -> None:
        if source.event_type == SCAN_CANCELLED:
            self._cancel(source)
            return
        if source.event_type != SCAN_CREATED:
            return

        # Logged so an operator can jump from a scan to its trace, and so the smoke test can
        # prove the context survived the Kafka hop, over assuming it did.
        log.info(
            "scan %s accepted, traceparent=%s",
            source.payload.get("scanId") or source.aggregate_id,
            source.traceparent or "none",
        )
        with continue_trace(source.traceparent):
            await self._process(source)

    def _cancel(self, source: EventEnvelope) -> None:
        """Stop a scan this worker is running.

        The control plane owns the decision and the status; all this does is reach the
        `CancellationToken` the scan is already polling. That token has existed since stage 5
        and was reachable only over the engine's own HTTP endpoint, which the *worker* does not
        expose - so a cancel travelled as far as Kafka and stopped there. The scan ran to
        completion and the operator watched a CANCELLED row keep spending money.

        Unknown scan ids are normal, not an error: a fan-out topic delivers the cancellation to
        every worker and exactly one of them is running it. Saying so at debug keeps the log
        readable while leaving the trail for the case where *no* worker had it.
        """
        scan_id = str(source.payload.get("scanId") or source.aggregate_id)
        state = self.running.get(scan_id)
        if state is None:
            log.debug("cancellation for scan %s, not running here", scan_id)
            return

        log.info("cancelling scan %s on request from the control plane", scan_id)
        state.cancellation.cancel()

    async def _process(self, source: EventEnvelope) -> None:

        scan_id = str(source.payload.get("scanId") or source.aggregate_id)
        try:
            dispatch = await self.dispatch.fetch(scan_id)
            if dispatch.workspace_id != source.workspace_id:
                raise ValueError("dispatch workspace does not match the signed event envelope")

            policy_raw = yaml.safe_load(dispatch.policy_content)
            if not isinstance(policy_raw, dict):
                raise ValueError("stored policy is not a YAML mapping")
            policy = parse_policy(policy_raw)

            state = ScanState(
                scan_id=scan_id,
                correlation_id=dispatch.correlation_id,
                policy=policy,
                target_config=dispatch.target_config,
                requested_categories=categories_from_suites(dispatch.suites),
                max_scenarios=dispatch.max_scenarios,
                base_seed=dispatch.seed,
            )
            self.running[scan_id] = state
            await self._publish(source, SCAN_STARTED, {"scanId": scan_id})
            try:
                state = await self.runner(state)
            finally:
                self.running.pop(scan_id, None)
                if state.adapter is not None and state.summary is None:
                    await state.adapter.aclose()

            await self._publish(
                source,
                SCAN_EVALUATION_REQUESTED,
                {"scanId": scan_id, "executed": len(state.executions)},
            )
            for execution in state.executions:
                event_type = (
                    ATTACK_COMPLETED
                    if execution.status is not RunStatus.TARGET_ERROR
                    else ATTACK_FAILED
                )
                await self._publish(
                    source,
                    event_type,
                    attack_payload(state, execution),
                    stable_key=execution.scenario.id,
                )

            for finding in state.findings:
                await self._publish(
                    source,
                    FINDING_CREATED,
                    finding_payload(state, finding),
                    stable_key=finding.fingerprint,
                )

            summary = state.summary
            if summary is None:
                raise RuntimeError("scan completed without a summary")
            await self._publish(
                source,
                SCAN_COMPLETED,
                {
                    "scanId": scan_id,
                    "attacks": summary.scenarios_executed,
                    "findings": len(summary.findings),
                    "critical": summary.critical,
                    "high": summary.high,
                    "medium": summary.medium,
                    "low": summary.low,
                },
            )
        except Exception as exc:  # noqa: BLE001 - failures must become durable scan state
            log.exception("scan %s failed", scan_id)
            await self._publish(
                source,
                SCAN_FAILED,
                {
                    "scanId": scan_id,
                    "errorCode": type(exc).__name__,
                    "message": redact(str(exc))[:500],
                },
            )

    async def _publish(
        self,
        source: EventEnvelope,
        event_type: str,
        payload: dict[str, Any],
        *,
        stable_key: str = "",
    ) -> None:
        identity = f"{source.event_id}:{event_type}:{stable_key}"
        envelope = EventEnvelope(
            traceparent=current_traceparent(),
            eventId=uuid.uuid5(uuid.NAMESPACE_URL, identity),
            eventType=event_type,
            aggregateId=source.aggregate_id,
            workspaceId=source.workspace_id,
            correlationId=source.correlation_id,
            occurredAt=datetime.now(UTC),
            payload=payload,
        )
        await self.publisher.publish(envelope)


#: The topic both loops read. One carries the work, the other the instructions about it.
LIFECYCLE_TOPIC = "security.scan.lifecycle"


async def run_worker_forever(
    settings: EngineSettings | None = None,
    *,
    running: dict[str, ScanState] | None = None,
) -> None:
    """Consume scan requests forever, committing only after the result stream is published.

    Two consumers on the same topic, in different groups, and the second one is the whole
    reason cancellation works.

    The work loop is serial by design: it processes one scan to completion and only then
    commits, so killing the worker mid-scan makes Kafka redeliver the request. That is what
    makes recovery correct, and it is also what made cancellation impossible - `process()` for
    a scan takes as long as the scan, and a `security.scan.cancelled` published thirty seconds
    in sat in the same partition *behind* the work it was trying to stop. It arrived after the
    scan it cancelled had finished.

    Control traffic must not queue behind data-plane work, so it gets its own consumer group,
    its own offsets, and a loop that never blocks. The two share a `running` dict; the control
    loop reaches the `CancellationToken` of a scan the work loop is inside.
    """
    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    except ImportError as exc:  # pragma: no cover - depends on deployment extra
        raise RuntimeError("install agentshield-engine[kafka] for worker mode") from exc

    settings = settings or EngineSettings.from_env()
    work = AIOKafkaConsumer(
        LIFECYCLE_TOPIC,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_group_id,
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    control = AIOKafkaConsumer(
        LIFECYCLE_TOPIC,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=f"{settings.kafka_group_id}-control",
        enable_auto_commit=True,
        # `latest`, where the work loop uses `earliest`. A scan request from before this
        # process started is work someone is still waiting for; a cancellation from before it
        # started is an instruction about a scan this worker never had.
        auto_offset_reset="latest",
    )
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        acks="all",
        enable_idempotence=True,
    )
    dispatch = ControlPlaneDispatchClient(
        settings.control_plane_url, settings.control_plane_internal_token
    )
    worker = ScanWorker(dispatch, KafkaEventPublisher(producer), running=running)

    await work.start()
    await control.start()
    await producer.start()
    log.info(
        "worker ready: consuming %s as group %s (+%s-control), control plane %s",
        LIFECYCLE_TOPIC,
        settings.kafka_group_id,
        settings.kafka_group_id,
        settings.control_plane_url or "(unset)",
    )

    control_loop = asyncio.create_task(_consume_control(control, worker))
    try:
        async for message in work:
            envelope = _parse(message)
            if envelope is None:
                await work.commit()
                continue
            if envelope.event_type == SCAN_CANCELLED:
                # Handled by the control loop, which saw it first. Committing here keeps the
                # work group's offsets moving past it.
                await work.commit()
                continue
            await worker.process(envelope)
            await work.commit()
    finally:
        control_loop.cancel()
        with suppress(asyncio.CancelledError):
            await control_loop
        await dispatch.aclose()
        await producer.stop()
        await control.stop()
        await work.stop()


async def _consume_control(consumer: Any, worker: ScanWorker) -> None:
    """Apply control messages the moment they arrive.

    Nothing here blocks and nothing here fails the worker: a control loop that dies takes
    cancellation with it silently, which is worse than one that logs and keeps reading.
    """
    async for message in consumer:
        envelope = _parse(message)
        if envelope is None or envelope.event_type != SCAN_CANCELLED:
            continue
        try:
            await worker.process(envelope)
        except Exception:  # noqa: BLE001 - one bad instruction must not stop the loop
            log.exception("failed to apply a control message")


def _parse(message: Any) -> EventEnvelope | None:
    try:
        return EventEnvelope.model_validate_json(message.value)
    except Exception:  # noqa: BLE001 - malformed input is logged and skipped
        log.exception("discarding malformed event at offset %s", message.offset)
        return None


def main() -> None:
    """Worker entry point.

    Configures logging before anything else. A worker that consumes silently cannot be
    diagnosed in production - "is it wedged, or is nothing being published?" is unanswerable
    without a startup line and a line per scan - and the readiness of a background consumer is
    otherwise invisible to whatever supervises it.
    """
    settings = EngineSettings.from_env()
    configure_logging(settings.log_level)
    configure_tracing(settings.otel_endpoint, service_name=settings.service_name)

    if not settings.kafka_bootstrap_servers:
        raise SystemExit(
            "KAFKA_BOOTSTRAP_SERVERS is required for worker mode; "
            "set it or run the engine as an HTTP service instead"
        )
    if not settings.control_plane_url:
        raise SystemExit(
            "AGENTSHIELD_CONTROL_PLANE_URL is required: the worker pulls policy and "
            "decrypted target configuration from it, since neither belongs on Kafka"
        )

    asyncio.run(run_worker_forever(settings))


if __name__ == "__main__":
    main()
