from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_UNSET = object()


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
    integration_account_id: str | None = None
    action_id: str | None = None
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
    contains_phi: bool = False
    retention_until: str | None = None
    processed_at: str | None = None
    redacted_at: str | None = None

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
        object.__setattr__(self, "integration_account_id", _optional_text(self.integration_account_id))
        object.__setattr__(self, "action_id", _optional_text(self.action_id))
        object.__setattr__(self, "external_thread_id", _optional_text(self.external_thread_id))
        object.__setattr__(self, "external_message_id", _optional_text(self.external_message_id))
        object.__setattr__(self, "subject", _optional_text(self.subject))
        object.__setattr__(self, "body_html", _optional_text(self.body_html))
        object.__setattr__(self, "body_text", str(self.body_text or ""))
        object.__setattr__(self, "retention_until", _optional_text(self.retention_until))
        object.__setattr__(self, "processed_at", _optional_text(self.processed_at))
        object.__setattr__(self, "redacted_at", _optional_text(self.redacted_at))
        if not isinstance(self.sender, dict):
            raise ValueError("sender must be a dict")
        if not isinstance(self.recipients, list):
            raise ValueError("recipients must be a list")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dict")
        if not isinstance(self.contains_phi, bool):
            raise ValueError("contains_phi must be a bool")


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
    integration_account_id: str | None = None
    action_id: str | None = None
    external_thread_id: str | None = None
    external_message_id: str | None = None
    sender: dict[str, Any] = field(default_factory=dict)
    recipients: list[dict[str, Any]] = field(default_factory=list)
    subject: str | None = None
    body_text: str = ""
    body_html: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "received"
    contains_phi: bool = False
    retention_until: str | None = None
    processed_at: str | None = None
    redacted_at: str | None = None


@dataclass(frozen=True)
class IntegrationMessageWriteResult:
    message: IntegrationMessageRecord
    inserted: bool


@dataclass(frozen=True)
class IntegrationAccountCreate:
    agent_id: str
    provider: str
    display_name: str
    credentials_secret_arn: str
    external_account_id: str | None = None
    default_space_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    status: str = "active"

    def __post_init__(self) -> None:
        object.__setattr__(self, "agent_id", _require_text(self.agent_id, "agent_id"))
        object.__setattr__(self, "provider", _require_text(self.provider, "provider"))
        object.__setattr__(self, "display_name", _require_text(self.display_name, "display_name"))
        object.__setattr__(self, "credentials_secret_arn", _require_text(self.credentials_secret_arn, "credentials_secret_arn"))
        object.__setattr__(self, "external_account_id", _optional_text(self.external_account_id))
        object.__setattr__(self, "default_space_id", _optional_text(self.default_space_id))
        object.__setattr__(self, "status", _require_text(self.status, "status"))
        if not isinstance(self.scopes, list):
            raise ValueError("scopes must be a list")
        if not isinstance(self.config, dict):
            raise ValueError("config must be a dict")


@dataclass(frozen=True)
class IntegrationAccountUpdate:
    display_name: str | object = _UNSET
    credentials_secret_arn: str | object = _UNSET
    external_account_id: str | None | object = _UNSET
    default_space_id: str | None | object = _UNSET
    scopes: list[str] | object = _UNSET
    config: dict[str, Any] | object = _UNSET
    status: str | object = _UNSET


@dataclass(frozen=True)
class IntegrationAccountRecord:
    integration_account_id: str
    agent_id: str
    provider: str
    display_name: str
    credentials_secret_arn: str
    created_at: str
    updated_at: str
    external_account_id: str | None = None
    default_space_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    status: str = "active"


@dataclass(frozen=True)
class IntegrationSyncStateRecord:
    integration_account_id: str
    sync_key: str
    updated_at: str
    cursor: str | None = None
    state: dict[str, Any] = field(default_factory=dict)


__all__ = [
    "IntegrationAccountCreate",
    "IntegrationAccountRecord",
    "IntegrationAccountUpdate",
    "IntegrationMessageCreate",
    "IntegrationMessageRecord",
    "IntegrationMessageWriteResult",
    "IntegrationSyncStateRecord",
    "_UNSET",
]
