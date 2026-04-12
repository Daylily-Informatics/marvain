from __future__ import annotations

import json
import logging
import os
from typing import Any

from agent_hub.action_service import mark_action_timed_out
from agent_hub.broadcast import broadcast_event
from agent_hub.config import load_config
from agent_hub.metrics import emit_count
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_BATCH_SIZE = int(os.getenv("ACTION_TIMEOUT_SWEEPER_BATCH_SIZE", "200"))


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    overdue = _db.query(
        """
        SELECT action_id::TEXT as action_id,
               agent_id::TEXT as agent_id,
               space_id::TEXT as space_id,
               kind
        FROM actions
        WHERE status IN ('awaiting_device_result', 'device_acknowledged')
          AND awaiting_result_until IS NOT NULL
          AND awaiting_result_until <= now()
        ORDER BY awaiting_result_until ASC
        LIMIT :limit
        """,
        {"limit": _BATCH_SIZE},
    )

    timed_out = 0
    for row in overdue:
        action_id = str(row["action_id"])
        mark_action_timed_out(
            _db,
            action_id=action_id,
            audit_bucket=_cfg.audit_bucket,
        )

        try:
            broadcast_event(
                event_type="actions.updated",
                agent_id=str(row["agent_id"]),
                space_id=row.get("space_id"),
                payload={
                    "action_id": action_id,
                    "kind": row.get("kind"),
                    "status": "device_timeout",
                    "error": "device_timeout",
                },
            )
        except Exception as exc:
            logger.warning("Failed to broadcast timed out action %s: %s", action_id, exc)

        emit_count(
            "DeviceTimeout",
            dimensions={
                "ActionKind": str(row.get("kind") or "unknown"),
                "AgentId": str(row.get("agent_id") or "unknown"),
            },
        )
        timed_out += 1

    logger.info("Action timeout sweeper timed_out=%d", timed_out)
    return {"timed_out": timed_out}
