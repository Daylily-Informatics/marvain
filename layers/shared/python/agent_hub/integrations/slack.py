from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from agent_hub.integrations.models import IntegrationMessageCreate


def _require_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def build_slack_signature(signing_secret: str, *, timestamp: str, body: bytes) -> str:
    base = f"v0:{timestamp}:{body.decode('utf-8')}"
    digest = hmac.new(signing_secret.encode("utf-8"), base.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"v0={digest}"


def verify_slack_request(
    signing_secret: str,
    *,
    timestamp: str,
    signature: str,
    body: bytes,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> None:
    signing_secret_n = _require_text(signing_secret, "signing_secret")
    timestamp_n = _require_text(timestamp, "timestamp")
    signature_n = _require_text(signature, "signature")

    try:
        request_ts = int(timestamp_n)
    except ValueError as exc:
        raise ValueError("invalid Slack request timestamp") from exc

    current_time = int(time.time()) if now is None else int(now)
    if abs(current_time - request_ts) > tolerance_seconds:
        raise ValueError("stale Slack request timestamp")

    expected = build_slack_signature(signing_secret_n, timestamp=timestamp_n, body=body)
    if not hmac.compare_digest(expected, signature_n):
        raise ValueError("invalid Slack signature")


def _infer_channel_type(channel_id: str | None, event: Mapping[str, Any]) -> str:
    explicit = _optional_text(event.get("channel_type"))
    if explicit:
        return explicit
    if channel_id:
        prefix = channel_id[:1].upper()
        if prefix == "D":
            return "dm"
        if prefix in {"C", "G"}:
            return "channel"
    return "slack"


@dataclass(frozen=True)
class SlackWebhookNormalized:
    integration_account_id: str | None = None
    challenge: str | None = None
    ignored_reason: str | None = None
    integration_message: IntegrationMessageCreate | None = None
    event_payload: dict[str, Any] = field(default_factory=dict)


def _ignored_message_reason(event: Mapping[str, Any]) -> str | None:
    if _optional_text(event.get("bot_id")):
        return "ignored_bot_message"
    if _optional_text(event.get("subtype")):
        return "ignored_message_subtype"
    if not _optional_text(event.get("user")):
        return "ignored_message_without_user"
    return None


def normalize_slack_webhook(
    payload: Mapping[str, Any],
    *,
    agent_id: str,
    space_id: str,
    integration_account_id: str | None = None,
) -> SlackWebhookNormalized:
    if not isinstance(payload, Mapping):
        raise ValueError("Slack payload must be an object")

    payload_type = _require_text(payload.get("type"), "type")
    if payload_type == "url_verification":
        return SlackWebhookNormalized(challenge=_require_text(payload.get("challenge"), "challenge"))
    if payload_type != "event_callback":
        raise ValueError(f"unsupported Slack payload type: {payload_type}")

    event = payload.get("event")
    if not isinstance(event, Mapping):
        raise ValueError("event is required")

    team_id = _require_text(payload.get("team_id"), "team_id")
    slack_event_id = _require_text(payload.get("event_id"), "event_id")
    slack_event_type = _require_text(event.get("type"), "event.type")
    if slack_event_type == "message":
        ignored_reason = _ignored_message_reason(event)
        if ignored_reason:
            return SlackWebhookNormalized(ignored_reason=ignored_reason)
    channel_id = _optional_text(event.get("channel"))
    external_thread_id = _optional_text(event.get("thread_ts")) or _optional_text(event.get("ts"))
    external_message_id = _optional_text(event.get("client_msg_id")) or _optional_text(event.get("ts")) or slack_event_id
    body_text = str(event.get("text") or "")

    sender: dict[str, Any] = {"team_id": team_id}
    user_id = _optional_text(event.get("user"))
    if user_id:
        sender["user_id"] = user_id
    bot_id = _optional_text(event.get("bot_id"))
    if bot_id:
        sender["bot_id"] = bot_id

    recipients: list[dict[str, Any]] = []
    if channel_id:
        recipients.append({"channel_id": channel_id})

    channel_type = _infer_channel_type(channel_id, event)
    integration_message = IntegrationMessageCreate(
        agent_id=agent_id,
        space_id=space_id,
        integration_account_id=integration_account_id,
        provider="slack",
        channel_type=channel_type,
        object_type=slack_event_type,
        dedupe_key=f"slack:{team_id}:{slack_event_id}",
        external_thread_id=external_thread_id,
        external_message_id=external_message_id,
        sender=sender,
        recipients=recipients,
        body_text=body_text,
        payload=dict(payload),
    )
    event_payload = {
        "provider": "slack",
        "integration_account_id": integration_account_id,
        "channel_type": channel_type,
        "object_type": slack_event_type,
        "team_id": team_id,
        "slack_event_id": slack_event_id,
        "channel_id": channel_id,
        "thread_ts": external_thread_id,
        "external_message_id": external_message_id,
        "text": body_text,
        "sender": sender,
        "recipients": recipients,
    }
    return SlackWebhookNormalized(
        integration_account_id=integration_account_id,
        integration_message=integration_message,
        event_payload=event_payload,
    )
