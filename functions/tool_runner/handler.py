from __future__ import annotations

import json
import logging
import os
from typing import Any

from agent_hub.audit import append_audit_entry
from agent_hub.config import load_config
from agent_hub.policy import is_agent_disabled
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.tools import execute_tool, get_registry
from agent_hub.tools.registry import ToolContext, ToolResult

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))

# Allowed HTTP hosts for http_request tool (configurable via env)
_ALLOWED_HTTP_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HTTP_HOSTS", "").split(",") if h.strip()]


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

        # Build tool context
        ctx = ToolContext(
            db=_db,
            agent_id=agent_id,
            space_id=space_id,
            action_id=action_id,
            device_scopes=required_scopes,  # Action's required scopes are pre-approved
            broadcast_fn=None,  # TODO: wire up WebSocket broadcast when available
            allowed_http_hosts=_ALLOWED_HTTP_HOSTS,
        )

        # Execute the tool
        tool_result = execute_tool(kind, payload, ctx)
        result: dict[str, Any] = tool_result.to_dict()
        result["kind"] = kind

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

        processed += 1

    return {"processed": processed}
