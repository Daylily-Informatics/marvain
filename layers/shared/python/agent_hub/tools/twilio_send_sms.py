"""twilio_send_sms tool - Send an SMS via Twilio's Messages API."""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from agent_hub.integrations import IntegrationMessageCreate, insert_integration_message
from agent_hub.secrets import get_secret_json

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "twilio_send_sms"
REQUIRED_SCOPES = ["twilio:sms:send"]


def _normalized_secret_value(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text == "REPLACE_ME":
        return None
    return text


def _get_twilio_credentials() -> dict[str, str | None]:
    secret_arn = str(os.getenv("TWILIO_SECRET_ARN") or "").strip()
    if not secret_arn:
        raise RuntimeError("TWILIO_SECRET_ARN not configured")
    data = get_secret_json(secret_arn)
    account_sid = _normalized_secret_value(data.get("account_sid"))
    auth_token = _normalized_secret_value(data.get("auth_token"))
    from_number = _normalized_secret_value(data.get("from_number"))
    messaging_service_sid = _normalized_secret_value(data.get("messaging_service_sid"))
    if not account_sid:
        raise RuntimeError("Twilio account SID not configured")
    if not auth_token:
        raise RuntimeError("Twilio auth token not configured")
    if not from_number and not messaging_service_sid:
        raise RuntimeError("Twilio sender not configured")
    return {
        "account_sid": account_sid,
        "auth_token": auth_token,
        "from_number": from_number,
        "messaging_service_sid": messaging_service_sid,
    }


def _read_json_response(resp: Any) -> dict[str, Any]:
    raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    _ = ctx
    to = str(payload.get("to") or "").strip()
    body = str(payload.get("body") or "")
    if not to:
        return ToolResult(ok=False, error="missing_to")
    if not body.strip():
        return ToolResult(ok=False, error="missing_body")

    try:
        creds = _get_twilio_credentials()
        request_body = {
            "To": to,
            "Body": body,
        }
        messaging_service_sid = creds["messaging_service_sid"]
        if messaging_service_sid:
            request_body["MessagingServiceSid"] = messaging_service_sid
        else:
            request_body["From"] = str(creds["from_number"])
        account_sid = str(creds["account_sid"])
        auth_token = str(creds["auth_token"])
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
        return ToolResult(ok=False, error=f"http_error_{exc.code}")
    except urllib.error.URLError as exc:
        logger.warning("twilio_send_sms url_error: %s", exc.reason)
        return ToolResult(ok=False, error=f"url_error: {exc.reason}")
    except Exception as exc:
        logger.exception("twilio_send_sms failed")
        return ToolResult(ok=False, error=str(exc))

    sid = str(response_payload.get("sid") or "").strip()
    if not sid:
        return ToolResult(ok=False, error="twilio_api_error: missing_sid")

    response_to = str(response_payload.get("to") or to).strip()
    response_from = str(response_payload.get("from") or request_body.get("From") or "").strip() or None
    response_messaging_service_sid = str(
        response_payload.get("messaging_service_sid") or request_body.get("MessagingServiceSid") or ""
    ).strip() or None
    sender: dict[str, str] = {}
    if response_from:
        sender["phone_number"] = response_from
    if response_messaging_service_sid:
        sender["messaging_service_sid"] = response_messaging_service_sid
    if not sender:
        sender["account_sid"] = account_sid

    insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            provider="twilio",
            direction="outbound",
            channel_type="sms",
            object_type="sms",
            dedupe_key=f"action:{ctx.action_id}",
            external_thread_id=f"{sender.get('phone_number') or sender.get('messaging_service_sid') or account_sid}:{response_to}",
            external_message_id=sid,
            sender=sender,
            recipients=[{"phone_number": response_to}],
            body_text=body,
            payload={"request": request_body, "response": response_payload},
            status=str(response_payload.get("status") or "").strip() or "sent",
        ),
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
