"""Kafka publisher for redacted engine events."""

from __future__ import annotations

import json
from typing import Any

from agentshield.messaging.contracts import TOPICS, EventEnvelope


class KafkaEventPublisher:
    def __init__(self, producer: Any) -> None:
        self.producer = producer

    async def publish(self, envelope: EventEnvelope) -> None:
        await self.producer.send_and_wait(
            TOPICS[envelope.event_type],
            key=envelope.aggregate_id.encode(),
            value=json.dumps(envelope.wire(), separators=(",", ":")).encode(),
        )
