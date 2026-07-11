from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from agent_hub.action_service import (
    begin_device_dispatch,
    load_action,
    mark_action_completed,
    mark_action_dispatch_failed,
    record_device_dispatch_receipt,
    reserve_action_for_execution,
)
from agent_hub.broadcast import broadcast_event, broadcast_target
from agent_hub.config import load_config
from agent_hub.device_routing import (
    DeviceDispatchReceipt,
    DeviceRoute,
    DeviceRoutingError,
    dispatch_to_device_route,
    load_device_route,
    require_route_scopes,
)
from agent_hub.metrics import emit_count, emit_ms
from agent_hub.permission_service import get_tool_runner_scopes
from agent_hub.policy import is_agent_disabled
from agent_hub.provider_contracts import ProviderContractError, ProviderDestinationReceipt, require_outbound_destination
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.tools import execute_tool
from agent_hub.tools.registry import ToolContext, ToolResult

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))

# Allowed HTTP hosts for http_request tool (configurable via env)
_ALLOWED_HTTP_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HTTP_HOSTS", "").split(",") if h.strip()]
_DEVICE_RESULT_TIMEOUT_SECONDS = int(os.getenv("DEVICE_RESULT_TIMEOUT_SECONDS", "90"))
_WS_TABLE = str(os.getenv("WS_TABLE") or "").strip()
_WS_API_ENDPOINT = str(os.getenv("WS_API_ENDPOINT") or "").strip()


def _make_broadcast_fn(agent_id: str, space_id: str | None):
    """Return a broadcast callable matching the ToolContext.broadcast_fn signature.

    The callable accepts ``(broadcast_key: str, payload: dict)`` and delegates
    to :func:`broadcast_event`.
    """

    def _broadcast(broadcast_key: str, payload: dict) -> None:
        # Recipient-targeted message from send_message tool.
        if broadcast_key.startswith(("space:", "user:", "connection:")):
            broadcast_target(
                target_key=broadcast_key,
                agent_id=agent_id,
                space_id=space_id,
                payload=payload,
            )
            return
        # System event broadcast (events.new/actions.updated/etc.).
        broadcast_event(
            event_type=broadcast_key,
            agent_id=agent_id,
            space_id=space_id,
            payload=payload,
        )

    return _broadcast


def _load_action(action_id: str) -> dict[str, Any] | None:
    return load_action(_db, action_id)


def _reserve_action(action_id: str) -> dict[str, Any] | None:
    return reserve_action_for_execution(_db, action_id)


def _require_uuid(value: Any, field_name: str) -> str:
    s = str(value).strip()
    if not s:
        raise DeviceRoutingError("device_dispatch_invalid", detail=f"{field_name} is required")
    try:
        return str(uuid.UUID(s))
    except (TypeError, ValueError, AttributeError) as exc:
        raise DeviceRoutingError("device_dispatch_invalid", detail=f"{field_name} must be a UUID") from exc


def _build_device_message(
    *,
    action_id: str,
    kind: str,
    payload: dict[str, Any],
    correlation_id: str,
) -> dict[str, Any]:
    sent_at = int(time.time() * 1000)
    if kind == "shell_command":
        command_text = str(payload.get("command") or "").strip()
        if not command_text:
            raise DeviceRoutingError("device_dispatch_invalid", detail="command is required")
        return {
            "type": "cmd.run_action",
            "action_id": action_id,
            "correlation_id": correlation_id,
            "kind": "shell_command",
            "payload": {"command": command_text},
            "sent_at": sent_at,
        }

    command = str(payload.get("command") or "").strip()
    data = payload.get("data")
    if not isinstance(data, dict):
        raise DeviceRoutingError("device_dispatch_invalid", detail="data must be an object")
    if command == "ping":
        return {
            "type": "cmd.ping",
            "action_id": action_id,
            "correlation_id": correlation_id,
            "sent_at": sent_at,
        }
    if command == "config":
        config = data.get("config", data)
        if not isinstance(config, dict):
            raise DeviceRoutingError("device_dispatch_invalid", detail="config must be an object")
        return {
            "type": "cmd.config",
            "action_id": action_id,
            "correlation_id": correlation_id,
            "config": config,
            "sent_at": sent_at,
        }
    if command != "run_action":
        raise DeviceRoutingError("device_dispatch_invalid", detail="command must be ping, config, or run_action")
    action_kind = str(data.get("kind") or "").strip()
    action_payload = data.get("payload")
    if not action_kind:
        raise DeviceRoutingError("device_dispatch_invalid", detail="data.kind is required")
    if not isinstance(action_payload, dict):
        raise DeviceRoutingError("device_dispatch_invalid", detail="data.payload must be an object")
    return {
        "type": "cmd.run_action",
        "action_id": action_id,
        "correlation_id": correlation_id,
        "kind": action_kind,
        "payload": action_payload,
        "sent_at": sent_at,
    }


def _dispatch_device_message(
    *,
    route: DeviceRoute,
    message: dict[str, Any],
    correlation_id: str,
) -> DeviceDispatchReceipt:
    if not _WS_TABLE:
        raise DeviceRoutingError("ws_table_not_configured")
    if not _WS_API_ENDPOINT:
        raise DeviceRoutingError("ws_endpoint_not_configured")
    import boto3

    table = boto3.resource("dynamodb").Table(_WS_TABLE)
    management_client = boto3.client("apigatewaymanagementapi", endpoint_url=_WS_API_ENDPOINT)
    return dispatch_to_device_route(
        table=table,
        management_client=management_client,
        route=route,
        message=message,
        correlation_id=correlation_id,
    )


def handler(event: dict, context: Any) -> dict[str, Any]:
    records = event.get("Records") or []
    processed = 0

    for rec in records:
        body = rec.get("body") or "{}"
        try:
            msg = json.loads(body)
        except Exception:
            safe_body = str(body).replace("\r", "").replace("\n", "")
            logger.warning("Bad message body: %s", safe_body)
            continue

        action_id = msg.get("action_id")
        if not action_id:
            continue

        action = _load_action(action_id)
        if not action:
            continue

        agent_id = action["agent_id"]
        if is_agent_disabled(_db, agent_id):
            logger.info("Agent disabled; skipping action")
            continue

        if action.get("status") != "approved":
            logger.info("Action not approved; skipping: %s", action.get("status"))
            continue

        reserved = _reserve_action(action_id)
        if not reserved:
            logger.info("Action already reserved or no longer approved: %s", action_id)
            continue
        action = reserved

        # --- Execute tool via registry ---
        kind = action.get("kind")
        payload = dict(action.get("payload") or {})
        space_id = action.get("space_id")
        required_scopes = action.get("required_scopes") or []
        async_device_dispatch = kind in ("device_command", "shell_command")
        dispatch_correlation_id = str(uuid.uuid4()) if async_device_dispatch else None
        dispatch_timeout_seconds = int(payload.get("timeout_seconds") or _DEVICE_RESULT_TIMEOUT_SECONDS)

        # Build tool context
        ctx = ToolContext(
            db=_db,
            agent_id=agent_id,
            space_id=space_id,
            action_id=action_id,
            device_scopes=get_tool_runner_scopes(),
            action_required_scopes=required_scopes,
            broadcast_fn=_make_broadcast_fn(agent_id, space_id),
            allowed_http_hosts=_ALLOWED_HTTP_HOSTS,
        )

        if async_device_dispatch:
            try:
                dispatch_target_device_id = _require_uuid(payload.get("device_id"), "device_id")
                route = load_device_route(
                    _db,
                    device_id=dispatch_target_device_id,
                    expected_agent_id=agent_id,
                )
                require_route_scopes(
                    route,
                    [str(scope) for scope in required_scopes if str(scope) != "devices:write"],
                )
                message = _build_device_message(
                    action_id=action_id,
                    kind=str(kind),
                    payload=payload,
                    correlation_id=str(dispatch_correlation_id),
                )
                begin_device_dispatch(
                    _db,
                    action_id=action_id,
                    target_device_id=dispatch_target_device_id,
                    correlation_id=dispatch_correlation_id,
                    timeout_seconds=dispatch_timeout_seconds,
                    execution_metadata={
                        "dispatch_pending": True,
                        "dispatched_command": payload.get("command"),
                        "route": route.receipt(),
                    },
                    target_location_id=route.location_id,
                    target_space_id=route.space_id,
                    audit_bucket=_cfg.audit_bucket,
                )
                receipt = _dispatch_device_message(
                    route=route,
                    message=message,
                    correlation_id=str(dispatch_correlation_id),
                )
                record_device_dispatch_receipt(
                    _db,
                    action_id=action_id,
                    receipt=receipt.as_dict(),
                    audit_bucket=_cfg.audit_bucket,
                )
            except DeviceRoutingError as exc:
                logger.warning("Device dispatch failed for %s: %s", action_id, exc.detail)
                current = load_action(_db, action_id)
                if current and current.get("status") == "awaiting_device_result":
                    mark_action_dispatch_failed(
                        _db,
                        action_id=action_id,
                        error=exc.code,
                        audit_bucket=_cfg.audit_bucket,
                    )
                else:
                    mark_action_completed(
                        _db,
                        action_id=action_id,
                        ok=False,
                        result=None,
                        error=exc.code,
                        audit_bucket=_cfg.audit_bucket,
                    )
                try:
                    broadcast_event(
                        event_type="actions.updated",
                        agent_id=agent_id,
                        space_id=space_id,
                        payload={
                            "action_id": action_id,
                            "kind": kind,
                            "status": "failed",
                            "error": exc.code,
                        },
                    )
                except Exception as broadcast_exc:
                    logger.warning("Failed to broadcast dispatch failure: %s", broadcast_exc)
                processed += 1
                continue

            try:
                broadcast_event(
                    event_type="actions.updated",
                    agent_id=agent_id,
                    space_id=route.space_id,
                    payload={
                        "action_id": action_id,
                        "kind": kind,
                        "status": "awaiting_device_result",
                        "target_device_id": dispatch_target_device_id,
                        "correlation_id": dispatch_correlation_id,
                        "location_id": route.location_id,
                        "space_id": route.space_id,
                        "dispatch_receipt": receipt.as_dict(),
                    },
                )
            except Exception as e:
                logger.warning("Failed to broadcast action dispatch: %s", e)

            emit_count(
                "ActionExecutionCount",
                dimensions={
                    "ActionKind": str(kind),
                    "Status": "awaiting_device_result",
                },
            )
            emit_ms(
                "CommandDispatchLatencyMs",
                value_ms=0,
                dimensions={"ActionKind": str(kind)},
            )
            processed += 1
            continue

        provider_receipt: ProviderDestinationReceipt | None = None
        try:
            provider_receipt = require_outbound_destination(_db, action=action)
            tool_result = execute_tool(kind, payload, ctx)
        except ProviderContractError as exc:
            tool_result = ToolResult(ok=False, error=exc.code)
        except Exception as exc:
            tool_result = ToolResult(ok=False, error=str(exc))
        if provider_receipt is not None and tool_result.ok:
            tool_result.data = {
                **(tool_result.data or {}),
                "provider_receipt": provider_receipt.as_dict(),
            }
        result: dict[str, Any] = tool_result.to_dict()
        result["kind"] = kind

        # Mark executed or failed based on result, and persist result/error
        new_status = "executed" if tool_result.ok else "failed"
        mark_action_completed(
            _db,
            action_id=action_id,
            ok=tool_result.ok,
            result=tool_result.data or {},
            error=tool_result.error if not tool_result.ok else None,
            audit_bucket=_cfg.audit_bucket,
        )

        emit_count(
            "ActionExecutionCount",
            dimensions={
                "ActionKind": str(kind),
                "Status": str(new_status),
            },
        )

        # Broadcast action completion to subscribed clients
        try:
            broadcast_event(
                event_type="actions.updated",
                agent_id=agent_id,
                space_id=action.get("space_id"),
                payload={
                    "action_id": action_id,
                    "kind": kind,
                    "status": new_status,
                    "has_result": tool_result.ok,
                },
            )
        except Exception as e:
            logger.warning("Failed to broadcast action update: %s", e)

        processed += 1

    return {"processed": processed}
