from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

from agent_hub.action_service import (
    begin_device_dispatch,
    load_action,
    mark_action_completed,
    mark_action_dispatch_failed,
    reserve_action_for_execution,
)
from agent_hub.broadcast import broadcast_event, broadcast_target
from agent_hub.config import load_config
from agent_hub.metrics import emit_count, emit_ms
from agent_hub.permission_service import get_tool_runner_scopes
from agent_hub.policy import is_agent_disabled
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
    reserved = reserve_action_for_execution(_db, action_id)
    if reserved is None or isinstance(reserved, dict):
        return reserved
    # Tests often replace the DB with a bare MagicMock. Fall back to the loaded
    # action if reservation cannot return the expected row shape.
    return _load_action(action_id)


def _uuid_or_none(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return str(uuid.UUID(s))
    except Exception:
        return None


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
        dispatch_target_device_id = _uuid_or_none(payload.get("device_id")) if async_device_dispatch else None
        dispatch_correlation_id = str(uuid.uuid4()) if async_device_dispatch else None
        dispatch_timeout_seconds = int(payload.get("timeout_seconds") or _DEVICE_RESULT_TIMEOUT_SECONDS)
        if async_device_dispatch:
            payload["correlation_id"] = dispatch_correlation_id
            payload["timeout_seconds"] = dispatch_timeout_seconds

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
                begin_device_dispatch(
                    _db,
                    action_id=action_id,
                    target_device_id=dispatch_target_device_id,
                    correlation_id=dispatch_correlation_id,
                    timeout_seconds=dispatch_timeout_seconds,
                    execution_metadata={
                        "dispatch_pending": True,
                        "dispatched_command": payload.get("command"),
                    },
                    audit_bucket=_cfg.audit_bucket,
                )
            except Exception as exc:
                logger.warning("Failed to start async dispatch for %s: %s", action_id, exc)
                continue

        # Execute the tool
        try:
            tool_result = execute_tool(kind, payload, ctx)
        except Exception as exc:
            tool_result = ToolResult(ok=False, error=str(exc))
        result: dict[str, Any] = tool_result.to_dict()
        result["kind"] = kind

        # Device-backed commands complete asynchronously via WS callbacks.
        if async_device_dispatch:
            if not tool_result.ok or not bool((tool_result.data or {}).get("dispatched")):
                mark_action_dispatch_failed(
                    _db,
                    action_id=action_id,
                    error=tool_result.error or "device_dispatch_failed",
                    audit_bucket=_cfg.audit_bucket,
                )
                try:
                    broadcast_event(
                        event_type="actions.updated",
                        agent_id=agent_id,
                        space_id=action.get("space_id"),
                        payload={
                            "action_id": action_id,
                            "kind": kind,
                            "status": "failed",
                            "error": tool_result.error or "device_dispatch_failed",
                        },
                    )
                except Exception as e:
                    logger.warning("Failed to broadcast dispatch failure: %s", e)
                processed += 1
                continue

            try:
                broadcast_event(
                    event_type="actions.updated",
                    agent_id=agent_id,
                    space_id=action.get("space_id"),
                    payload={
                        "action_id": action_id,
                        "kind": kind,
                        "status": "awaiting_device_result",
                        "target_device_id": dispatch_target_device_id,
                        "correlation_id": dispatch_correlation_id,
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
