from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlparse

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


def _add_port(uri: Any) -> str:
    if uri.port:
        return uri.geturl()
    port = 443 if uri.scheme == "https" else 80
    return uri._replace(netloc=f"{uri.netloc}:{port}").geturl()


def _remove_port(uri: Any) -> str:
    if not uri.port:
        return uri.geturl()
    return uri._replace(netloc=uri.netloc.split(":", 1)[0]).geturl()


def _signature_values(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def build_twilio_signature(
    auth_token: str,
    *,
    url: str,
    params: Mapping[str, Any] | None = None,
) -> str:
    auth_token_n = _require_text(auth_token, "auth_token")
    url_n = _require_text(url, "url")

    payload = url_n
    if params:
        for param_name in sorted(set(params)):
            for value in sorted(set(_signature_values(params[param_name]))):
                payload += f"{param_name}{value}"

    digest = hmac.new(auth_token_n.encode("utf-8"), payload.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8").strip()


def verify_twilio_request(
    auth_token: str,
    *,
    url: str,
    params: Mapping[str, Any] | None,
    signature: str,
) -> None:
    signature_n = _require_text(signature, "signature")
    parsed_url = urlparse(_require_text(url, "url"))
    expected_without_port = build_twilio_signature(auth_token, url=_remove_port(parsed_url), params=params or {})
    expected_with_port = build_twilio_signature(auth_token, url=_add_port(parsed_url), params=params or {})
    if not (
        hmac.compare_digest(expected_without_port, signature_n)
        or hmac.compare_digest(expected_with_port, signature_n)
    ):
        raise ValueError("invalid Twilio signature")


def parse_twilio_form_body(body: bytes) -> dict[str, list[str]]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid form body encoding") from exc
    return parse_qs(text, keep_blank_values=True)


def _first_value(payload: Mapping[str, Any], field_name: str) -> str | None:
    value = payload.get(field_name)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if not value:
            return None
        return _optional_text(value[0])
    return _optional_text(value)


def _flatten_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            values = [str(item) for item in value]
            flattened[key] = values[0] if len(values) == 1 else values
        else:
            flattened[key] = value
    return flattened


@dataclass(frozen=True)
class TwilioWebhookNormalized:
    ignored_reason: str | None = None
    integration_message: IntegrationMessageCreate | None = None
    event_payload: dict[str, Any] = field(default_factory=dict)


def normalize_twilio_webhook(
    payload: Mapping[str, Any],
    *,
    agent_id: str,
    space_id: str,
) -> TwilioWebhookNormalized:
    if not isinstance(payload, Mapping):
        raise ValueError("Twilio payload must be an object")

    account_sid = _require_text(_first_value(payload, "AccountSid"), "AccountSid")
    from_number = _require_text(_first_value(payload, "From"), "From")
    to_number = _require_text(_first_value(payload, "To"), "To")
    message_sid = _require_text(_first_value(payload, "MessageSid") or _first_value(payload, "SmsSid"), "MessageSid")
    body_text = str(_first_value(payload, "Body") or "")

    num_media_text = _first_value(payload, "NumMedia") or "0"
    try:
        num_media = int(num_media_text)
    except ValueError as exc:
        raise ValueError("invalid NumMedia") from exc
    if num_media > 0:
        return TwilioWebhookNormalized(ignored_reason="ignored_media_message")

    sender = {
        "account_sid": account_sid,
        "phone_number": from_number,
    }
    recipients = [{"phone_number": to_number}]
    external_thread_id = f"{from_number}:{to_number}"
    flattened_payload = _flatten_payload(payload)
    integration_message = IntegrationMessageCreate(
        agent_id=agent_id,
        space_id=space_id,
        provider="twilio",
        channel_type="sms",
        object_type="sms",
        dedupe_key=f"twilio:{account_sid}:{message_sid}",
        external_thread_id=external_thread_id,
        external_message_id=message_sid,
        sender=sender,
        recipients=recipients,
        body_text=body_text,
        payload=flattened_payload,
    )
    event_payload = {
        "provider": "twilio",
        "channel_type": "sms",
        "object_type": "sms",
        "account_sid": account_sid,
        "message_sid": message_sid,
        "from_number": from_number,
        "to_number": to_number,
        "external_thread_id": external_thread_id,
        "external_message_id": message_sid,
        "text": body_text,
        "sender": sender,
        "recipients": recipients,
        "num_media": num_media,
    }
    return TwilioWebhookNormalized(
        integration_message=integration_message,
        event_payload=event_payload,
    )
