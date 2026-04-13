from __future__ import annotations

import base64
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.utils import getaddresses
from typing import Any, Mapping

from agent_hub.integrations.models import IntegrationMessageCreate
from agent_hub.secrets import get_secret_json

_GMAIL_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GMAIL_API_ROOT = "https://gmail.googleapis.com/gmail/v1/users/me"


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


def _http_json_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> dict[str, Any]:
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    request.add_header("User-Agent", "marvain-gmail/handler")
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


@dataclass(frozen=True)
class GmailCredentials:
    client_id: str
    client_secret: str
    refresh_token: str
    user_email: str


@dataclass(frozen=True)
class GmailMessageRef:
    message_id: str


@dataclass(frozen=True)
class GmailPollNormalized:
    integration_account_id: str
    history_id: str | None = None
    integration_message: IntegrationMessageCreate | None = None
    event_payload: dict[str, Any] = field(default_factory=dict)


def load_gmail_credentials(secret_arn: str) -> GmailCredentials:
    data = get_secret_json(_require_text(secret_arn, "secret_arn"))
    client_id = _require_text(data.get("client_id"), "client_id")
    client_secret = _require_text(data.get("client_secret"), "client_secret")
    refresh_token = _require_text(data.get("refresh_token"), "refresh_token")
    user_email = _require_text(data.get("user_email"), "user_email")
    if client_id == "REPLACE_ME" or client_secret == "REPLACE_ME" or refresh_token == "REPLACE_ME":
        raise ValueError("gmail credentials are not configured")
    return GmailCredentials(
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
        user_email=user_email,
    )


def refresh_gmail_access_token(credentials: GmailCredentials) -> str:
    body = urllib.parse.urlencode(
        {
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "refresh_token": credentials.refresh_token,
            "grant_type": "refresh_token",
        }
    ).encode("utf-8")
    payload = _http_json_request(
        _GMAIL_TOKEN_URL,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )
    return _require_text(payload.get("access_token"), "access_token")


def _gmail_api_request(access_token: str, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
    query = urllib.parse.urlencode(params or {})
    url = f"{_GMAIL_API_ROOT}{path}"
    if query:
        url = f"{url}?{query}"
    return _http_json_request(
        url,
        headers={"Authorization": f"Bearer {_require_text(access_token, 'access_token')}"},
    )


def fetch_gmail_profile(access_token: str) -> dict[str, Any]:
    return _gmail_api_request(access_token, "/profile")


def list_gmail_message_refs(
    access_token: str,
    *,
    history_id: str | None,
    max_results: int = 25,
) -> tuple[list[GmailMessageRef], str | None]:
    if history_id:
        payload = _gmail_api_request(
            access_token,
            "/history",
            params={
                "startHistoryId": history_id,
                "historyTypes": "messageAdded",
                "maxResults": str(max(1, min(max_results, 100))),
            },
        )
        refs: list[GmailMessageRef] = []
        seen: set[str] = set()
        for item in payload.get("history") or []:
            if not isinstance(item, Mapping):
                continue
            for added in item.get("messagesAdded") or []:
                if not isinstance(added, Mapping):
                    continue
                message = added.get("message")
                if not isinstance(message, Mapping):
                    continue
                message_id = _optional_text(message.get("id"))
                if not message_id or message_id in seen:
                    continue
                seen.add(message_id)
                refs.append(GmailMessageRef(message_id=message_id))
        return refs, _optional_text(payload.get("historyId")) or history_id

    listing = _gmail_api_request(
        access_token,
        "/messages",
        params={"maxResults": str(max(1, min(max_results, 100))), "includeSpamTrash": "false"},
    )
    refs = []
    seen: set[str] = set()
    for item in listing.get("messages") or []:
        if not isinstance(item, Mapping):
            continue
        message_id = _optional_text(item.get("id"))
        if not message_id or message_id in seen:
            continue
        seen.add(message_id)
        refs.append(GmailMessageRef(message_id=message_id))
    profile = fetch_gmail_profile(access_token)
    return refs, _optional_text(profile.get("historyId"))


def fetch_gmail_message(access_token: str, *, message_id: str) -> dict[str, Any]:
    return _gmail_api_request(
        access_token,
        f"/messages/{_require_text(message_id, 'message_id')}",
        params={"format": "full"},
    )


def _decode_gmail_body_data(value: Any) -> str:
    data = _optional_text(value)
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="replace")


def _collect_bodies(part: Mapping[str, Any], plain_parts: list[str], html_parts: list[str]) -> None:
    for child in part.get("parts") or []:
        if isinstance(child, Mapping):
            _collect_bodies(child, plain_parts, html_parts)
    mime_type = _optional_text(part.get("mimeType"))
    body = part.get("body")
    if not isinstance(body, Mapping):
        return
    decoded = _decode_gmail_body_data(body.get("data"))
    if not decoded.strip():
        return
    if mime_type == "text/plain":
        plain_parts.append(decoded)
    elif mime_type == "text/html":
        html_parts.append(decoded)


def _headers_by_name(payload: Mapping[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in payload.get("headers") or []:
        if not isinstance(item, Mapping):
            continue
        name = _optional_text(item.get("name"))
        value = _optional_text(item.get("value"))
        if not name or value is None:
            continue
        headers[name.lower()] = value
    return headers


def _parse_address_values(raw_value: str | None) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for name, address in getaddresses([raw_value or ""]):
        address_n = _optional_text(address)
        if not address_n:
            continue
        value: dict[str, Any] = {"email": address_n}
        name_n = _optional_text(name)
        if name_n:
            value["name"] = name_n
        values.append(value)
    return values


def normalize_gmail_message(
    message: Mapping[str, Any],
    *,
    agent_id: str,
    space_id: str,
    integration_account_id: str,
    user_email: str,
) -> GmailPollNormalized:
    if not isinstance(message, Mapping):
        raise ValueError("gmail message must be an object")

    message_id = _require_text(message.get("id"), "id")
    payload = message.get("payload")
    if not isinstance(payload, Mapping):
        payload = {}
    headers = _headers_by_name(payload)
    sender_candidates = _parse_address_values(headers.get("from"))
    sender = sender_candidates[0] if sender_candidates else {"email": user_email}

    recipients: list[dict[str, Any]] = []
    for header_name in ("to", "cc", "bcc"):
        recipients.extend(_parse_address_values(headers.get(header_name)))

    plain_parts: list[str] = []
    html_parts: list[str] = []
    _collect_bodies(payload, plain_parts, html_parts)
    body_text = "\n\n".join(part.strip() for part in plain_parts if part.strip()).strip()
    body_html = "\n".join(part for part in html_parts if part.strip()).strip() or None
    snippet = str(message.get("snippet") or "").strip()
    if not body_text:
        body_text = snippet

    subject = headers.get("subject")
    thread_id = _optional_text(message.get("threadId"))
    history_id = _optional_text(message.get("historyId"))

    integration_message = IntegrationMessageCreate(
        agent_id=agent_id,
        space_id=space_id,
        integration_account_id=integration_account_id,
        provider="gmail",
        channel_type="email",
        object_type="message",
        dedupe_key=f"gmail:{user_email}:{message_id}",
        external_thread_id=thread_id,
        external_message_id=message_id,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        payload=dict(message),
    )
    event_payload = {
        "provider": "gmail",
        "integration_account_id": integration_account_id,
        "gmail_message_id": message_id,
        "gmail_thread_id": thread_id,
        "history_id": history_id,
        "subject": subject,
        "text": body_text,
        "sender": sender,
        "recipients": recipients,
    }
    return GmailPollNormalized(
        integration_account_id=integration_account_id,
        history_id=history_id,
        integration_message=integration_message,
        event_payload=event_payload,
    )
