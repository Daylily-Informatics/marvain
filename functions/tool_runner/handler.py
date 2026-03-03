from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

from agent_hub.audit import append_audit_entry
from agent_hub.broadcast import broadcast_event, broadcast_target
from agent_hub.contracts import validate_tool_payload
from agent_hub.config import load_config
from agent_hub.metrics import emit_count, emit_ms
from agent_hub.policy import is_agent_disabled
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.tools import execute_tool
from agent_hub.tools.registry import ToolContext, ToolResult, get_registry

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
    rows = _db.query(
        """
        SELECT action_id::TEXT as action_id,
               agent_id::TEXT as agent_id,
               space_id::TEXT as space_id,
               kind,
               payload::TEXT as payload_json,
               required_scopes::TEXT as required_scopes_json,
               status
        FROM actions
        WHERE action_id = :action_id::uuid
        LIMIT 1
        """,
        {"action_id": action_id},
    )
    if not rows:
        return None
    row = rows[0]
    try:
        row["payload"] = json.loads(row.get("payload_json") or "{}")
    except Exception:
        row["payload"] = {}
    try:
        row["required_scopes"] = json.loads(row.get("required_scopes_json") or "[]")
    except Exception:
        row["required_scopes"] = []
    return row


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

        if action.get("status") not in ("approved", "executing"):
            logger.info("Action not approved; skipping: %s", action.get("status"))
            continue

        # Mark executing
        _db.execute(
            """
            UPDATE actions
            SET status='executing', updated_at=now()
            WHERE action_id = :action_id::uuid
            """,
            {"action_id": action_id},
        )

        # --- Execute tool via registry ---
        kind = action.get("kind")
        payload = action.get("payload") or {}
        space_id = action.get("space_id")
        required_scopes = action.get("required_scopes") or []

        # Resolve execution scopes: action-level required scopes + intrinsic tool scopes.
        tool_registry = get_registry()
        tool_spec = tool_registry.get(str(kind))
        intrinsic_tool_scopes = tool_spec.required_scopes if tool_spec else []
        execution_scopes = sorted(set(required_scopes) | set(intrinsic_tool_scopes))

        # Build tool context
        ctx = ToolContext(
            db=_db,
            agent_id=agent_id,
            space_id=space_id,
            action_id=action_id,
            device_scopes=execution_scopes,
            action_required_scopes=required_scopes,
            broadcast_fn=_make_broadcast_fn(agent_id, space_id),
            allowed_http_hosts=_ALLOWED_HTTP_HOSTS,
        )

        # Execute the tool
        try:
            payload = validate_tool_payload(str(kind), payload)
            tool_result = execute_tool(kind, payload, ctx)
        except Exception as exc:
            tool_result = ToolResult(ok=False, error=str(exc))
        result: dict[str, Any] = tool_result.to_dict()
        result["kind"] = kind

        # Device-backed commands complete asynchronously via WS callbacks.
        if kind in ("device_command", "shell_command") and tool_result.ok and bool((tool_result.data or {}).get("dispatched")):
            target_device_id = _uuid_or_none((tool_result.data or {}).get("device_id"))
            correlation_id = _uuid_or_none((tool_result.data or {}).get("correlation_id"))
            timeout_seconds = int((tool_result.data or {}).get("timeout_seconds") or _DEVICE_RESULT_TIMEOUT_SECONDS)
            _db.execute(
                """
                UPDATE actions
                SET status = 'awaiting_device_result',
                    updated_at = now(),
                    target_device_id = :target_device_id::uuid,
                    correlation_id = :correlation_id::uuid,
                    awaiting_result_until = now() + (:timeout_seconds || ' seconds')::interval,
                    execution_metadata = COALESCE(execution_metadata, '{}'::jsonb) || :execution_metadata::jsonb,
                    result = NULL,
                    error = NULL
                WHERE action_id = :action_id::uuid
                """,
                {
                    "action_id": action_id,
                    "target_device_id": target_device_id,
                    "correlation_id": correlation_id,
                    "timeout_seconds": timeout_seconds,
                    "execution_metadata": json.dumps(
                        {
                            "dispatched": True,
                            "dispatched_command": (tool_result.data or {}).get("command"),
                            "connections_sent": (tool_result.data or {}).get("connections_sent", 0),
                        }
                    ),
                },
            )

            try:
                broadcast_event(
                    event_type="actions.updated",
                    agent_id=agent_id,
                    space_id=action.get("space_id"),
                    payload={
                        "action_id": action_id,
                        "kind": kind,
                        "status": "awaiting_device_result",
                        "target_device_id": target_device_id,
                        "correlation_id": correlation_id,
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
        _db.execute(
            """
            UPDATE actions
            SET status = :status,
                updated_at = now(),
                executed_at = now(),
                completed_at = now(),
                result = :result::jsonb,
                error = :error
            WHERE action_id = :action_id::uuid
            """,
            {
                "action_id": action_id,
                "status": new_status,
                "result": json.dumps(tool_result.data) if tool_result.ok else None,
                "error": tool_result.error if not tool_result.ok else None,
            },
        )

        if _cfg.audit_bucket:
            append_audit_entry(
                _db,
                bucket=_cfg.audit_bucket,
                agent_id=agent_id,
                entry_type="action_executed",
                entry={"action_id": action_id, "kind": kind, "result": result, "status": new_status},
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
