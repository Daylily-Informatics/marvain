from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


def _require_text(value: str | None, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(frozen=True)
class IntegrationQueueMessage:
    event_id: str
    agent_id: str
    space_id: str | None = None
    integration_message_id: str | None = None
    event_type: str = "integration.event.received"

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _require_text(self.event_id, "event_id"))
        object.__setattr__(self, "agent_id", _require_text(self.agent_id, "agent_id"))
        object.__setattr__(self, "space_id", _optional_text(self.space_id))
        object.__setattr__(self, "integration_message_id", _optional_text(self.integration_message_id))
        normalized_event_type = _require_text(self.event_type, "event_type")
        if normalized_event_type != "integration.event.received":
            raise ValueError("event_type must be integration.event.received")
        object.__setattr__(self, "event_type", normalized_event_type)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_message_body(self) -> str:
        return json.dumps(self.to_dict())


def parse_integration_queue_message(value: str | dict[str, Any]) -> IntegrationQueueMessage:
    payload = value
    if isinstance(value, str):
        payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("integration queue message must be an object")
    return IntegrationQueueMessage(
        event_id=str(payload.get("event_id") or ""),
        agent_id=str(payload.get("agent_id") or ""),
        space_id=payload.get("space_id"),
        integration_message_id=payload.get("integration_message_id"),
        event_type=str(payload.get("event_type") or "integration.event.received"),
    )


def enqueue_integration_event(
    sqs_client: Any,
    *,
    queue_url: str,
    message: IntegrationQueueMessage,
) -> dict[str, Any]:
    queue_url_n = _require_text(queue_url, "queue_url")
    return sqs_client.send_message(
        QueueUrl=queue_url_n,
        MessageBody=message.to_message_body(),
    )
