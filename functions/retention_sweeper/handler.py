from __future__ import annotations

import logging
import os
from typing import Any

from agent_hub.audit import append_audit_entry
from agent_hub.config import load_config
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_BATCH_SIZE = int(os.getenv("RETENTION_SWEEPER_BATCH_SIZE", "200"))


def _redacted_fields_sql() -> str:
    return """
        UPDATE integration_messages
        SET subject = NULL,
            body_text = '',
            body_html = NULL,
            payload = '{}'::jsonb,
            redacted_at = COALESCE(redacted_at, now()),
            updated_at = now()
        WHERE integration_message_id = :integration_message_id::uuid
        RETURNING integration_message_id::TEXT as integration_message_id,
                  agent_id::TEXT as agent_id,
                  integration_account_id::TEXT as integration_account_id,
                  provider,
                  direction,
                  channel_type,
                  object_type,
                  external_thread_id,
                  external_message_id,
                  dedupe_key,
                  retention_until::TEXT as retention_until,
                  redacted_at::TEXT as redacted_at
    """


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    overdue = _db.query(
        """
        SELECT integration_message_id::TEXT as integration_message_id,
               agent_id::TEXT as agent_id,
               integration_account_id::TEXT as integration_account_id,
               provider,
               direction,
               channel_type,
               object_type,
               external_thread_id,
               external_message_id,
               dedupe_key,
               retention_until::TEXT as retention_until
        FROM integration_messages
        WHERE retention_until IS NOT NULL
          AND retention_until <= now()
          AND redacted_at IS NULL
        ORDER BY retention_until ASC, integration_message_id ASC
        LIMIT :limit
        """,
        {"limit": _BATCH_SIZE},
    )

    redacted = 0
    for row in overdue:
        integration_message_id = str(row.get("integration_message_id") or "").strip()
        if not integration_message_id:
            continue

        updated_rows = _db.query(
            _redacted_fields_sql(),
            {"integration_message_id": integration_message_id},
        )
        if not updated_rows:
            logger.warning("Retention sweeper could not redact message %s", integration_message_id)
            continue

        updated = updated_rows[0]
        redacted_at = str(updated.get("redacted_at") or "").strip() or None
        if _cfg.audit_bucket:
            try:
                append_audit_entry(
                    _db,
                    bucket=_cfg.audit_bucket,
                    agent_id=str(updated.get("agent_id") or row.get("agent_id") or "").strip(),
                    entry_type="integration_message_redacted",
                    entry={
                        "integration_message_id": str(updated.get("integration_message_id") or integration_message_id),
                        "integration_account_id": str(updated.get("integration_account_id") or "").strip() or None,
                        "provider": str(updated.get("provider") or row.get("provider") or "").strip() or None,
                        "direction": str(updated.get("direction") or row.get("direction") or "").strip() or None,
                        "channel_type": str(updated.get("channel_type") or row.get("channel_type") or "").strip() or None,
                        "object_type": str(updated.get("object_type") or row.get("object_type") or "").strip() or None,
                        "external_thread_id": str(updated.get("external_thread_id") or row.get("external_thread_id") or "").strip()
                        or None,
                        "external_message_id": str(updated.get("external_message_id") or row.get("external_message_id") or "").strip()
                        or None,
                        "dedupe_key": str(updated.get("dedupe_key") or row.get("dedupe_key") or "").strip() or None,
                        "retention_until": str(updated.get("retention_until") or row.get("retention_until") or "").strip() or None,
                        "redacted_at": redacted_at,
                    },
                )
            except Exception as exc:
                logger.warning("Failed to write redaction audit entry for %s: %s", integration_message_id, exc)

        redacted += 1

    logger.info("Retention sweeper redacted=%d", redacted)
    return {"redacted": redacted}
