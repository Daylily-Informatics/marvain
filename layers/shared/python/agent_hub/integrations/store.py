from __future__ import annotations

import json
from typing import Any

from agent_hub.integrations.models import (
    IntegrationAccountCreate,
    IntegrationAccountRecord,
    IntegrationAccountUpdate,
    IntegrationMessageCreate,
    IntegrationMessageRecord,
    IntegrationMessageWriteResult,
    IntegrationSyncStateRecord,
    _UNSET,
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
integration_account_id::TEXT as integration_account_id,
action_id::TEXT as action_id,
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
contains_phi,
retention_until::TEXT as retention_until,
processed_at::TEXT as processed_at,
redacted_at::TEXT as redacted_at,
created_at::TEXT as created_at,
updated_at::TEXT as updated_at
"""

_ACCOUNT_ROW_COLUMNS = """
integration_account_id::TEXT as integration_account_id,
agent_id::TEXT as agent_id,
provider,
display_name,
external_account_id,
default_space_id::TEXT as default_space_id,
credentials_secret_arn,
scopes::TEXT as scopes_json,
config::TEXT as config_json,
status,
created_at::TEXT as created_at,
updated_at::TEXT as updated_at
"""

_SYNC_STATE_ROW_COLUMNS = """
integration_account_id::TEXT as integration_account_id,
sync_key,
cursor,
state::TEXT as state_json,
updated_at::TEXT as updated_at
"""


def _row_to_message(row: dict[str, Any]) -> IntegrationMessageRecord:
    return IntegrationMessageRecord(
        integration_message_id=str(row.get("integration_message_id") or "").strip(),
        agent_id=str(row.get("agent_id") or "").strip(),
        space_id=str(row.get("space_id") or "").strip() or None,
        event_id=str(row.get("event_id") or "").strip() or None,
        integration_account_id=str(row.get("integration_account_id") or "").strip() or None,
        action_id=str(row.get("action_id") or "").strip() or None,
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
        contains_phi=bool(row.get("contains_phi")),
        retention_until=str(row.get("retention_until") or "").strip() or None,
        processed_at=str(row.get("processed_at") or "").strip() or None,
        redacted_at=str(row.get("redacted_at") or "").strip() or None,
        created_at=str(row.get("created_at") or "").strip(),
        updated_at=str(row.get("updated_at") or "").strip(),
    )


def _row_to_account(row: dict[str, Any]) -> IntegrationAccountRecord:
    return IntegrationAccountRecord(
        integration_account_id=str(row.get("integration_account_id") or "").strip(),
        agent_id=str(row.get("agent_id") or "").strip(),
        provider=str(row.get("provider") or "").strip(),
        display_name=str(row.get("display_name") or "").strip(),
        credentials_secret_arn=str(row.get("credentials_secret_arn") or "").strip(),
        external_account_id=str(row.get("external_account_id") or "").strip() or None,
        default_space_id=str(row.get("default_space_id") or "").strip() or None,
        scopes=_json_loads(row.get("scopes_json"), []),
        config=_json_loads(row.get("config_json"), {}),
        status=str(row.get("status") or "").strip(),
        created_at=str(row.get("created_at") or "").strip(),
        updated_at=str(row.get("updated_at") or "").strip(),
    )


def _row_to_sync_state(row: dict[str, Any]) -> IntegrationSyncStateRecord:
    return IntegrationSyncStateRecord(
        integration_account_id=str(row.get("integration_account_id") or "").strip(),
        sync_key=str(row.get("sync_key") or "").strip(),
        cursor=str(row.get("cursor") or "").strip() or None,
        state=_json_loads(row.get("state_json"), {}),
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
                integration_account_id,
                action_id,
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
                status,
                contains_phi,
                retention_until,
                processed_at,
                redacted_at
            )
            VALUES(
                :agent_id::uuid,
                CASE WHEN :space_id IS NULL OR :space_id = '' THEN NULL ELSE :space_id::uuid END,
                CASE WHEN :event_id IS NULL OR :event_id = '' THEN NULL ELSE :event_id::uuid END,
                CASE WHEN :integration_account_id IS NULL OR :integration_account_id = '' THEN NULL ELSE :integration_account_id::uuid END,
                CASE WHEN :action_id IS NULL OR :action_id = '' THEN NULL ELSE :action_id::uuid END,
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
                :status,
                :contains_phi,
                CASE WHEN :retention_until IS NULL OR :retention_until = '' THEN NULL ELSE :retention_until::timestamptz END,
                CASE WHEN :processed_at IS NULL OR :processed_at = '' THEN NULL ELSE :processed_at::timestamptz END,
                CASE WHEN :redacted_at IS NULL OR :redacted_at = '' THEN NULL ELSE :redacted_at::timestamptz END
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
            "integration_account_id": message.integration_account_id,
            "action_id": message.action_id,
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
            "contains_phi": message.contains_phi,
            "retention_until": message.retention_until,
            "processed_at": message.processed_at,
            "redacted_at": message.redacted_at,
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


def create_integration_account(
    db: RdsData,
    account: IntegrationAccountCreate,
    *,
    transaction_id: str | None = None,
) -> IntegrationAccountRecord:
    rows = db.query(
        f"""
        INSERT INTO integration_accounts(
            agent_id,
            provider,
            display_name,
            external_account_id,
            default_space_id,
            credentials_secret_arn,
            scopes,
            config,
            status
        )
        VALUES(
            :agent_id::uuid,
            :provider,
            :display_name,
            :external_account_id,
            CASE WHEN :default_space_id IS NULL OR :default_space_id = '' THEN NULL ELSE :default_space_id::uuid END,
            :credentials_secret_arn,
            :scopes::jsonb,
            :config::jsonb,
            :status
        )
        RETURNING {_ACCOUNT_ROW_COLUMNS}
        """,
        {
            "agent_id": account.agent_id,
            "provider": account.provider,
            "display_name": account.display_name,
            "external_account_id": account.external_account_id,
            "default_space_id": account.default_space_id,
            "credentials_secret_arn": account.credentials_secret_arn,
            "scopes": json.dumps(account.scopes),
            "config": json.dumps(account.config),
            "status": account.status,
        },
        transaction_id=transaction_id,
    )
    if not rows:
        raise RuntimeError("Failed to create integration account")
    return _row_to_account(rows[0])


def get_integration_account(
    db: RdsData,
    *,
    integration_account_id: str,
    transaction_id: str | None = None,
) -> IntegrationAccountRecord | None:
    rows = db.query(
        f"""
        SELECT {_ACCOUNT_ROW_COLUMNS}
        FROM integration_accounts
        WHERE integration_account_id = :integration_account_id::uuid
        LIMIT 1
        """,
        {"integration_account_id": integration_account_id},
        transaction_id=transaction_id,
    )
    if not rows:
        return None
    return _row_to_account(rows[0])


def list_integration_accounts(
    db: RdsData,
    *,
    agent_id: str,
    provider: str | None = None,
    status: str | None = None,
    transaction_id: str | None = None,
) -> list[IntegrationAccountRecord]:
    params: dict[str, object] = {
        "agent_id": agent_id,
        "provider": (provider or "").strip() or None,
        "status": (status or "").strip() or None,
    }
    rows = db.query(
        f"""
        SELECT {_ACCOUNT_ROW_COLUMNS}
        FROM integration_accounts
        WHERE agent_id = :agent_id::uuid
          AND (:provider IS NULL OR provider = :provider)
          AND (:status IS NULL OR status = :status)
        ORDER BY created_at DESC, integration_account_id DESC
        """,
        params,
        transaction_id=transaction_id,
    )
    return [_row_to_account(row) for row in rows]


def update_integration_account(
    db: RdsData,
    *,
    integration_account_id: str,
    update: IntegrationAccountUpdate,
    transaction_id: str | None = None,
) -> IntegrationAccountRecord:
    sets: list[str] = []
    params: dict[str, object] = {"integration_account_id": integration_account_id}
    for field_name in (
        "display_name",
        "credentials_secret_arn",
        "external_account_id",
        "default_space_id",
        "scopes",
        "config",
        "status",
    ):
        value = getattr(update, field_name)
        if value is _UNSET:
            continue
        if field_name == "default_space_id":
            sets.append(
                "default_space_id = CASE WHEN :default_space_id IS NULL OR :default_space_id = '' THEN NULL ELSE :default_space_id::uuid END"
            )
            params[field_name] = value
            continue
        if field_name in {"scopes", "config"}:
            sets.append(f"{field_name} = :{field_name}::jsonb")
            params[field_name] = json.dumps(value)
            continue
        sets.append(f"{field_name} = :{field_name}")
        params[field_name] = value
    if not sets:
        current = get_integration_account(
            db,
            integration_account_id=integration_account_id,
            transaction_id=transaction_id,
        )
        if current is None:
            raise LookupError("integration account not found")
        return current
    sets.append("updated_at = now()")
    rows = db.query(
        f"""
        UPDATE integration_accounts
        SET {", ".join(sets)}
        WHERE integration_account_id = :integration_account_id::uuid
        RETURNING {_ACCOUNT_ROW_COLUMNS}
        """,
        params,
        transaction_id=transaction_id,
    )
    if not rows:
        raise LookupError("integration account not found")
    return _row_to_account(rows[0])


def get_integration_sync_state(
    db: RdsData,
    *,
    integration_account_id: str,
    sync_key: str = "default",
    transaction_id: str | None = None,
) -> IntegrationSyncStateRecord | None:
    rows = db.query(
        f"""
        SELECT {_SYNC_STATE_ROW_COLUMNS}
        FROM integration_sync_state
        WHERE integration_account_id = :integration_account_id::uuid
          AND sync_key = :sync_key
        LIMIT 1
        """,
        {
            "integration_account_id": integration_account_id,
            "sync_key": sync_key,
        },
        transaction_id=transaction_id,
    )
    if not rows:
        return None
    return _row_to_sync_state(rows[0])


def upsert_integration_sync_state(
    db: RdsData,
    *,
    integration_account_id: str,
    sync_key: str = "default",
    cursor: str | None = None,
    state: dict[str, Any] | None = None,
    transaction_id: str | None = None,
) -> IntegrationSyncStateRecord:
    rows = db.query(
        f"""
        INSERT INTO integration_sync_state(
            integration_account_id,
            sync_key,
            cursor,
            state,
            updated_at
        )
        VALUES(
            :integration_account_id::uuid,
            :sync_key,
            :cursor,
            :state::jsonb,
            now()
        )
        ON CONFLICT (integration_account_id, sync_key)
        DO UPDATE SET
            cursor = EXCLUDED.cursor,
            state = EXCLUDED.state,
            updated_at = now()
        RETURNING {_SYNC_STATE_ROW_COLUMNS}
        """,
        {
            "integration_account_id": integration_account_id,
            "sync_key": sync_key,
            "cursor": cursor,
            "state": json.dumps(state or {}),
        },
        transaction_id=transaction_id,
    )
    if not rows:
        raise RuntimeError("Failed to upsert integration sync state")
    return _row_to_sync_state(rows[0])


def list_integration_messages_for_thread(
    db: RdsData,
    *,
    agent_id: str,
    provider: str,
    external_thread_id: str,
    exclude_integration_message_id: str | None = None,
    limit: int = 10,
    transaction_id: str | None = None,
) -> list[IntegrationMessageRecord]:
    rows = db.query(
        f"""
        SELECT {_ROW_COLUMNS}
        FROM integration_messages
        WHERE agent_id = :agent_id::uuid
          AND provider = :provider
          AND external_thread_id = :external_thread_id
          AND (
            :exclude_integration_message_id IS NULL
            OR integration_message_id <> :exclude_integration_message_id::uuid
          )
        ORDER BY created_at DESC
        LIMIT :limit::int
        """,
        {
            "agent_id": agent_id,
            "provider": provider,
            "external_thread_id": external_thread_id,
            "exclude_integration_message_id": exclude_integration_message_id,
            "limit": max(1, min(limit, 200)),
        },
        transaction_id=transaction_id,
    )
    return [_row_to_message(row) for row in rows]


def finalize_outbound_integration_message(
    db: RdsData,
    *,
    integration_message_id: str,
    status: str,
    payload: dict[str, Any] | None = None,
    external_thread_id: str | None = None,
    external_message_id: str | None = None,
    action_id: str | None = None,
    transaction_id: str | None = None,
) -> IntegrationMessageRecord:
    rows = db.query(
        f"""
        UPDATE integration_messages
        SET status = :status,
            payload = COALESCE(payload, '{{}}'::jsonb) || :payload::jsonb,
            external_thread_id = CASE
                WHEN :external_thread_id IS NULL OR :external_thread_id = '' THEN external_thread_id
                ELSE :external_thread_id
            END,
            external_message_id = CASE
                WHEN :external_message_id IS NULL OR :external_message_id = '' THEN external_message_id
                ELSE :external_message_id
            END,
            action_id = CASE
                WHEN :action_id IS NULL OR :action_id = '' THEN action_id
                ELSE :action_id::uuid
            END,
            processed_at = COALESCE(processed_at, now()),
            updated_at = now()
        WHERE integration_message_id = :integration_message_id::uuid
        RETURNING {_ROW_COLUMNS}
        """,
        {
            "integration_message_id": integration_message_id,
            "status": status,
            "payload": json.dumps(payload or {}),
            "external_thread_id": external_thread_id,
            "external_message_id": external_message_id,
            "action_id": action_id,
        },
        transaction_id=transaction_id,
    )
    if not rows:
        raise LookupError("integration message not found")
    return _row_to_message(rows[0])


def set_integration_message_status(
    db: RdsData,
    *,
    integration_message_id: str,
    status: str,
    reason: str | None = None,
    transaction_id: str | None = None,
) -> IntegrationMessageRecord:
    rows = db.query(
        f"""
        UPDATE integration_messages
        SET status = :status,
            payload = COALESCE(payload, '{{}}'::jsonb) || jsonb_build_object(
                'status_update',
                jsonb_strip_nulls(
                    jsonb_build_object(
                        'status', :status,
                        'reason', :reason
                    )
                )
            ),
            processed_at = COALESCE(processed_at, now()),
            updated_at = now()
        WHERE integration_message_id = :integration_message_id::uuid
        RETURNING {_ROW_COLUMNS}
        """,
        {
            "integration_message_id": integration_message_id,
            "status": status,
            "reason": reason,
        },
        transaction_id=transaction_id,
    )
    if not rows:
        raise LookupError("integration message not found")
    return _row_to_message(rows[0])
