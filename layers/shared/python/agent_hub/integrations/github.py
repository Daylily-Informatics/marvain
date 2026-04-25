from __future__ import annotations

import hashlib
import hmac
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


def build_github_signature(webhook_secret: str, *, body: bytes) -> str:
    webhook_secret_n = _require_text(webhook_secret, "webhook_secret")
    digest = hmac.new(webhook_secret_n.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_github_request(
    webhook_secret: str,
    *,
    signature: str,
    body: bytes,
) -> None:
    signature_n = _require_text(signature, "signature")
    expected = build_github_signature(webhook_secret, body=body)
    if not hmac.compare_digest(expected, signature_n):
        raise ValueError("invalid GitHub signature")


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} is required")
    return value


def _join_text_parts(*parts: Any) -> str:
    values = [str(part).strip() for part in parts if str(part or "").strip()]
    return "\n\n".join(values)


def _repository_full_name(payload: Mapping[str, Any]) -> str:
    repository = _require_mapping(payload.get("repository"), "repository")
    return _require_text(repository.get("full_name"), "repository.full_name")


def _sender(payload: Mapping[str, Any]) -> dict[str, Any]:
    sender = payload.get("sender")
    if not isinstance(sender, Mapping):
        return {}
    result: dict[str, Any] = {}
    login = _optional_text(sender.get("login"))
    if login:
        result["login"] = login
    sender_id = _optional_text(sender.get("id"))
    if sender_id:
        result["id"] = sender_id
    return result


def _recipients(repository_full_name: str) -> list[dict[str, Any]]:
    return [{"repository": repository_full_name}]


@dataclass(frozen=True)
class GitHubWebhookNormalized:
    integration_account_id: str | None = None
    ignored_reason: str | None = None
    integration_message: IntegrationMessageCreate | None = None
    event_payload: dict[str, Any] = field(default_factory=dict)


def normalize_github_webhook(
    payload: Mapping[str, Any],
    *,
    event_name: str,
    delivery_id: str,
    agent_id: str,
    space_id: str,
    integration_account_id: str | None = None,
) -> GitHubWebhookNormalized:
    if not isinstance(payload, Mapping):
        raise ValueError("GitHub payload must be an object")

    event_name_n = _require_text(event_name, "event_name")
    delivery_id_n = _require_text(delivery_id, "delivery_id")

    if event_name_n == "ping":
        return GitHubWebhookNormalized(ignored_reason="ignored_ping")

    repository_full_name = _repository_full_name(payload)
    sender = _sender(payload)
    recipients = _recipients(repository_full_name)
    action = _optional_text(payload.get("action"))

    channel_type: str
    object_type: str
    external_thread_id: str | None
    external_message_id: str | None
    body_text: str

    if event_name_n == "issues":
        issue = _require_mapping(payload.get("issue"), "issue")
        issue_number = _require_text(issue.get("number") or payload.get("number"), "issue.number")
        channel_type = "issue"
        object_type = "issue"
        external_thread_id = f"{repository_full_name}#issue:{issue_number}"
        external_message_id = _optional_text(issue.get("id")) or delivery_id_n
        body_text = _join_text_parts(issue.get("title"), issue.get("body"))
    elif event_name_n == "issue_comment":
        comment = _require_mapping(payload.get("comment"), "comment")
        issue = _require_mapping(payload.get("issue"), "issue")
        issue_number = _require_text(issue.get("number") or payload.get("number"), "issue.number")
        is_pull_request = isinstance(issue.get("pull_request"), Mapping)
        channel_type = "pull_request" if is_pull_request else "issue"
        thread_prefix = "pull" if is_pull_request else "issue"
        object_type = "issue_comment"
        external_thread_id = f"{repository_full_name}#{thread_prefix}:{issue_number}"
        external_message_id = _optional_text(comment.get("id")) or delivery_id_n
        body_text = str(comment.get("body") or "")
    elif event_name_n == "pull_request":
        pull_request = _require_mapping(payload.get("pull_request"), "pull_request")
        pull_number = _require_text(pull_request.get("number") or payload.get("number"), "pull_request.number")
        channel_type = "pull_request"
        object_type = "pull_request"
        external_thread_id = f"{repository_full_name}#pull:{pull_number}"
        external_message_id = _optional_text(pull_request.get("id")) or delivery_id_n
        body_text = _join_text_parts(pull_request.get("title"), pull_request.get("body"))
    elif event_name_n == "pull_request_review_comment":
        comment = _require_mapping(payload.get("comment"), "comment")
        pull_request = _require_mapping(payload.get("pull_request"), "pull_request")
        pull_number = _require_text(pull_request.get("number") or payload.get("number"), "pull_request.number")
        channel_type = "pull_request"
        object_type = "pull_request_review_comment"
        external_thread_id = f"{repository_full_name}#pull:{pull_number}"
        external_message_id = _optional_text(comment.get("id")) or delivery_id_n
        body_text = str(comment.get("body") or "")
    else:
        return GitHubWebhookNormalized(ignored_reason=f"ignored_{event_name_n}")

    if not body_text.strip():
        return GitHubWebhookNormalized(ignored_reason="ignored_event_without_text")

    integration_message = IntegrationMessageCreate(
        agent_id=agent_id,
        space_id=space_id,
        integration_account_id=integration_account_id,
        provider="github",
        channel_type=channel_type,
        object_type=object_type,
        dedupe_key=f"github:{delivery_id_n}",
        external_thread_id=external_thread_id,
        external_message_id=external_message_id,
        sender=sender,
        recipients=recipients,
        body_text=body_text,
        payload=dict(payload),
    )
    event_payload = {
        "provider": "github",
        "integration_account_id": integration_account_id,
        "github_event": event_name_n,
        "github_delivery_id": delivery_id_n,
        "action": action,
        "channel_type": channel_type,
        "object_type": object_type,
        "repository": repository_full_name,
        "external_thread_id": external_thread_id,
        "external_message_id": external_message_id,
        "text": body_text,
        "sender": sender,
        "recipients": recipients,
    }
    return GitHubWebhookNormalized(
        integration_account_id=integration_account_id,
        integration_message=integration_message,
        event_payload=event_payload,
    )
