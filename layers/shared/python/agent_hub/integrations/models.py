from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _require_text(value: str, field_name: str) -> str:
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
class IntegrationMessageCreate:
    agent_id: str
    provider: str
    channel_type: str
    object_type: str
    dedupe_key: str
    space_id: str | None = None
    event_id: str | None = None
    direction: str = "inbound"
    external_thread_id: str | None = None
    external_message_id: str | None = None
    sender: dict[str, Any] = field(default_factory=dict)
    recipients: list[dict[str, Any]] = field(default_factory=list)
    subject: str | None = None
    body_text: str = ""
    body_html: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "received"

    def __post_init__(self) -> None:
        object.__setattr__(self, "agent_id", _require_text(self.agent_id, "agent_id"))
        object.__setattr__(self, "provider", _require_text(self.provider, "provider"))
        object.__setattr__(self, "channel_type", _require_text(self.channel_type, "channel_type"))
        object.__setattr__(self, "object_type", _require_text(self.object_type, "object_type"))
        object.__setattr__(self, "dedupe_key", _require_text(self.dedupe_key, "dedupe_key"))
        object.__setattr__(self, "direction", _require_text(self.direction, "direction"))
        object.__setattr__(self, "status", _require_text(self.status, "status"))
        object.__setattr__(self, "space_id", _optional_text(self.space_id))
        object.__setattr__(self, "event_id", _optional_text(self.event_id))
        object.__setattr__(self, "external_thread_id", _optional_text(self.external_thread_id))
        object.__setattr__(self, "external_message_id", _optional_text(self.external_message_id))
        object.__setattr__(self, "subject", _optional_text(self.subject))
        object.__setattr__(self, "body_html", _optional_text(self.body_html))
        object.__setattr__(self, "body_text", str(self.body_text or ""))
        if not isinstance(self.sender, dict):
            raise ValueError("sender must be a dict")
        if not isinstance(self.recipients, list):
            raise ValueError("recipients must be a list")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dict")


@dataclass(frozen=True)
class IntegrationMessageRecord:
    integration_message_id: str
    agent_id: str
    provider: str
    direction: str
    channel_type: str
    object_type: str
    dedupe_key: str
    created_at: str
    updated_at: str
    space_id: str | None = None
    event_id: str | None = None
    external_thread_id: str | None = None
    external_message_id: str | None = None
    sender: dict[str, Any] = field(default_factory=dict)
    recipients: list[dict[str, Any]] = field(default_factory=list)
    subject: str | None = None
    body_text: str = ""
    body_html: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "received"


@dataclass(frozen=True)
class IntegrationMessageWriteResult:
    message: IntegrationMessageRecord
    inserted: bool
