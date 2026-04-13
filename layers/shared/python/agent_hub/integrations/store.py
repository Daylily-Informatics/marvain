from __future__ import annotations

import json
from typing import Any

from agent_hub.integrations.models import (
    IntegrationMessageCreate,
    IntegrationMessageRecord,
    IntegrationMessageWriteResult,
)
from agent_hub.rds_data import RdsData


def _json_loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, type(fallback)):
        return value
    try:
        parsed = json.loads(value)
    except Exception:
        return fallback
    return parsed if isinstance(parsed, type(fallback)) else fallback


_ROW_COLUMNS = """
integration_message_id::TEXT as integration_message_id,
agent_id::TEXT as agent_id,
space_id::TEXT as space_id,
event_id::TEXT as event_id,
provider,
direction,
channel_type,
object_type,
external_thread_id,
external_message_id,
dedupe_key,
sender::TEXT as sender_json,
recipients::TEXT as recipients_json,
subject,
body_text,
body_html,
payload::TEXT as payload_json,
status,
created_at::TEXT as created_at,
updated_at::TEXT as updated_at
"""


def _row_to_message(row: dict[str, Any]) -> IntegrationMessageRecord:
    return IntegrationMessageRecord(
        integration_message_id=str(row.get("integration_message_id") or "").strip(),
        agent_id=str(row.get("agent_id") or "").strip(),
        space_id=str(row.get("space_id") or "").strip() or None,
        event_id=str(row.get("event_id") or "").strip() or None,
        provider=str(row.get("provider") or "").strip(),
        direction=str(row.get("direction") or "").strip(),
        channel_type=str(row.get("channel_type") or "").strip(),
        object_type=str(row.get("object_type") or "").strip(),
        external_thread_id=str(row.get("external_thread_id") or "").strip() or None,
        external_message_id=str(row.get("external_message_id") or "").strip() or None,
        dedupe_key=str(row.get("dedupe_key") or "").strip(),
        sender=_json_loads(row.get("sender_json"), {}),
        recipients=_json_loads(row.get("recipients_json"), []),
        subject=str(row.get("subject") or "").strip() or None,
        body_text=str(row.get("body_text") or ""),
        body_html=str(row.get("body_html") or "").strip() or None,
        payload=_json_loads(row.get("payload_json"), {}),
        status=str(row.get("status") or "").strip(),
        created_at=str(row.get("created_at") or "").strip(),
        updated_at=str(row.get("updated_at") or "").strip(),
    )


def insert_integration_message(
    db: RdsData,
    message: IntegrationMessageCreate,
    *,
    transaction_id: str | None = None,
) -> IntegrationMessageWriteResult:
    rows = db.query(
        f"""
        WITH inserted AS (
            INSERT INTO integration_messages(
                agent_id,
                space_id,
                event_id,
                provider,
                direction,
                channel_type,
                object_type,
                external_thread_id,
                external_message_id,
                dedupe_key,
                sender,
                recipients,
                subject,
                body_text,
                body_html,
                payload,
                status
            )
            VALUES(
                :agent_id::uuid,
                CASE WHEN :space_id IS NULL OR :space_id = '' THEN NULL ELSE :space_id::uuid END,
                CASE WHEN :event_id IS NULL OR :event_id = '' THEN NULL ELSE :event_id::uuid END,
                :provider,
                :direction,
                :channel_type,
                :object_type,
                :external_thread_id,
                :external_message_id,
                :dedupe_key,
                :sender::jsonb,
                :recipients::jsonb,
                :subject,
                :body_text,
                :body_html,
                :payload::jsonb,
                :status
            )
            ON CONFLICT (agent_id, dedupe_key) DO NOTHING
            RETURNING {_ROW_COLUMNS}, TRUE as inserted
        )
        SELECT * FROM inserted
        UNION ALL
        SELECT {_ROW_COLUMNS}, FALSE as inserted
        FROM integration_messages
        WHERE agent_id = :agent_id::uuid
          AND dedupe_key = :dedupe_key
          AND NOT EXISTS (SELECT 1 FROM inserted)
        LIMIT 1
        """,
        {
            "agent_id": message.agent_id,
            "space_id": message.space_id,
            "event_id": message.event_id,
            "provider": message.provider,
            "direction": message.direction,
            "channel_type": message.channel_type,
            "object_type": message.object_type,
            "external_thread_id": message.external_thread_id,
            "external_message_id": message.external_message_id,
            "dedupe_key": message.dedupe_key,
            "sender": json.dumps(message.sender),
            "recipients": json.dumps(message.recipients),
            "subject": message.subject,
            "body_text": message.body_text,
            "body_html": message.body_html,
            "payload": json.dumps(message.payload),
            "status": message.status,
        },
        transaction_id=transaction_id,
    )
    if not rows:
        raise RuntimeError("Failed to insert integration message")
    row = rows[0]
    return IntegrationMessageWriteResult(
        message=_row_to_message(row),
        inserted=bool(row.get("inserted")),
    )


def get_integration_message(
    db: RdsData,
    *,
    integration_message_id: str,
    transaction_id: str | None = None,
) -> IntegrationMessageRecord | None:
    rows = db.query(
        f"""
        SELECT {_ROW_COLUMNS}
        FROM integration_messages
        WHERE integration_message_id = :integration_message_id::uuid
        LIMIT 1
        """,
        {"integration_message_id": integration_message_id},
        transaction_id=transaction_id,
    )
    if not rows:
        return None
    return _row_to_message(rows[0])


def link_integration_message_event(
    db: RdsData,
    *,
    integration_message_id: str,
    event_id: str,
    transaction_id: str | None = None,
) -> IntegrationMessageRecord:
    rows = db.query(
        f"""
        UPDATE integration_messages
        SET event_id = CASE WHEN event_id IS NULL THEN :event_id::uuid ELSE event_id END,
            updated_at = CASE WHEN event_id IS NULL THEN now() ELSE updated_at END
        WHERE integration_message_id = :integration_message_id::uuid
          AND (event_id IS NULL OR event_id = :event_id::uuid)
        RETURNING {_ROW_COLUMNS}
        """,
        {
            "integration_message_id": integration_message_id,
            "event_id": event_id,
        },
        transaction_id=transaction_id,
    )
    if rows:
        return _row_to_message(rows[0])

    existing = get_integration_message(
        db,
        integration_message_id=integration_message_id,
        transaction_id=transaction_id,
    )
    if existing is None:
        raise LookupError("integration message not found")
    if existing.event_id and existing.event_id != event_id:
        raise RuntimeError("integration message already linked to a different event")
    return existing
