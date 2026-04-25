"""twilio_send_sms tool - Send an SMS via Twilio's Messages API."""

from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from agent_hub.integrations import (
    IntegrationMessageCreate,
    finalize_outbound_integration_message,
    insert_integration_message,
)

from ._outbound import load_outbound_integration_account
from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "twilio_send_sms"
REQUIRED_SCOPES = ["twilio:sms:send"]


def _normalized_secret_value(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text == "REPLACE_ME":
        return None
    return text


def _read_json_response(resp: Any) -> dict[str, Any]:
    raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _recipient_key(sender: dict[str, str], account_sid: str) -> str:
    return sender.get("phone_number") or sender.get("messaging_service_sid") or account_sid


def _message_data(message, account_sid: str) -> dict[str, Any]:
    payload = message.payload if isinstance(message.payload, dict) else {}
    response = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    recipients = message.recipients if isinstance(message.recipients, list) else []
    response_to = (
        str(response.get("to") or (recipients[0].get("phone_number") if recipients else "") or "").strip() or None
    )
    response_from = str(response.get("from") or "").strip() or None
    response_messaging_service_sid = str(response.get("messaging_service_sid") or "").strip() or None
    return {
        "sid": str(message.external_message_id or response.get("sid") or "").strip() or None,
        "status": str(message.status or "").strip() or None,
        "to": response_to,
        "from_number": response_from,
        "messaging_service_sid": response_messaging_service_sid,
        "account_sid": account_sid,
    }


def _finalize_failure(
    ctx: ToolContext,
    *,
    pending_message_id: str,
    request_body: dict[str, Any],
    error_message: str,
    response_payload: dict[str, Any] | None = None,
) -> None:
    try:
        finalize_outbound_integration_message(
            ctx.db,
            integration_message_id=pending_message_id,
            status="error",
            payload={
                "request": request_body,
                "error": error_message,
                "response": response_payload or {},
            },
            transaction_id=None,
        )
    except Exception:
        logger.exception("twilio_send_sms failed to finalize error status")


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    integration_account_id = str(payload.get("integration_account_id") or "").strip()
    to = str(payload.get("to") or "").strip()
    body = str(payload.get("body") or "")
    if not integration_account_id:
        return ToolResult(ok=False, error="missing_integration_account_id")
    if not to:
        return ToolResult(ok=False, error="missing_to")
    if not body.strip():
        return ToolResult(ok=False, error="missing_body")

    pending = insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            integration_account_id=integration_account_id,
            provider="twilio",
            direction="outbound",
            channel_type="sms",
            object_type="sms",
            dedupe_key=f"action:{ctx.action_id}",
            action_id=ctx.action_id,
            external_thread_id=None,
            sender={"type": "sms"},
            recipients=[{"phone_number": to}],
            body_text=body,
            payload={"request": {"to": to, "body": body}, "state": "pending"},
            status="pending",
        ),
    )

    if not pending.inserted:
        if pending.message.status == "sent":
            account_sid = str((pending.message.sender or {}).get("account_sid") or "").strip()
            return ToolResult(ok=True, data=_message_data(pending.message, account_sid or ""))
        if pending.message.status == "error":
            payload_data = pending.message.payload if isinstance(pending.message.payload, dict) else {}
            return ToolResult(
                ok=False, error=f"outbound_message_error: {payload_data.get('error') or pending.message.status}"
            )
        return ToolResult(ok=False, error="outbound_message_pending")

    try:
        _, secret_data = load_outbound_integration_account(
            ctx.db,
            integration_account_id=integration_account_id,
            provider="twilio",
        )
        account_sid = _normalized_secret_value(secret_data.get("account_sid"))
        auth_token = _normalized_secret_value(secret_data.get("auth_token"))
        from_number = _normalized_secret_value(secret_data.get("from_number"))
        messaging_service_sid = _normalized_secret_value(secret_data.get("messaging_service_sid"))
        if not account_sid:
            raise RuntimeError("Twilio account SID not configured")
        if not auth_token:
            raise RuntimeError("Twilio auth token not configured")
        if not from_number and not messaging_service_sid:
            raise RuntimeError("Twilio sender not configured")

        request_body = {
            "To": to,
            "Body": body,
        }
        if messaging_service_sid:
            request_body["MessagingServiceSid"] = messaging_service_sid
        else:
            request_body["From"] = from_number
        encoded_body = urllib.parse.urlencode(request_body).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
            data=encoded_body,
            method="POST",
        )
        basic_auth = base64.b64encode(f"{account_sid}:{auth_token}".encode("utf-8")).decode("utf-8")
        req.add_header("Authorization", f"Basic {basic_auth}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", f"marvain-tool/{TOOL_NAME}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_payload = _read_json_response(resp)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        logger.warning("twilio_send_sms http_error_%s: %s", exc.code, error_body[:500])
        _finalize_failure(
            ctx,
            pending_message_id=pending.message.integration_message_id,
            request_body={"To": to, "Body": body},
            error_message=f"http_error_{exc.code}",
        )
        return ToolResult(ok=False, error=f"http_error_{exc.code}")
    except urllib.error.URLError as exc:
        logger.warning("twilio_send_sms url_error: %s", exc.reason)
        _finalize_failure(
            ctx,
            pending_message_id=pending.message.integration_message_id,
            request_body={"To": to, "Body": body},
            error_message=f"url_error: {exc.reason}",
        )
        return ToolResult(ok=False, error=f"url_error: {exc.reason}")
    except Exception as exc:
        logger.exception("twilio_send_sms failed")
        _finalize_failure(
            ctx,
            pending_message_id=pending.message.integration_message_id,
            request_body={"To": to, "Body": body},
            error_message=str(exc),
        )
        return ToolResult(ok=False, error=str(exc))

    sid = str(response_payload.get("sid") or "").strip()
    if not sid:
        error_message = "twilio_api_error: missing_sid"
        _finalize_failure(
            ctx,
            pending_message_id=pending.message.integration_message_id,
            request_body={"To": to, "Body": body},
            error_message=error_message,
            response_payload=response_payload,
        )
        return ToolResult(ok=False, error=error_message)

    response_to = str(response_payload.get("to") or to).strip()
    response_from = str(response_payload.get("from") or request_body.get("From") or "").strip() or None
    response_messaging_service_sid = (
        str(response_payload.get("messaging_service_sid") or request_body.get("MessagingServiceSid") or "").strip()
        or None
    )
    sender: dict[str, str] = {}
    if response_from:
        sender["phone_number"] = response_from
    if response_messaging_service_sid:
        sender["messaging_service_sid"] = response_messaging_service_sid
    if not sender:
        sender["account_sid"] = account_sid

    finalize_outbound_integration_message(
        ctx.db,
        integration_message_id=pending.message.integration_message_id,
        status="sent",
        payload={"request": request_body, "response": response_payload},
        external_thread_id=f"{_recipient_key(sender, account_sid)}:{response_to}",
        external_message_id=sid,
        action_id=ctx.action_id,
        transaction_id=None,
    )

    return ToolResult(
        ok=True,
        data={
            "sid": sid,
            "status": str(response_payload.get("status") or "").strip() or None,
            "to": response_to,
            "from_number": response_from,
            "messaging_service_sid": response_messaging_service_sid,
        },
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Send a text message using the configured Twilio account",
    )
