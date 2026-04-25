from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

import boto3
from agent_hub.config import load_config
from agent_hub.integrations.gmail import (
    fetch_gmail_message,
    list_gmail_message_refs,
    load_gmail_credentials,
    normalize_gmail_message,
    refresh_gmail_access_token,
)
from agent_hub.integrations.queue import IntegrationQueueMessage, enqueue_integration_event
from agent_hub.integrations.store import (
    get_integration_sync_state,
    insert_integration_message,
    link_integration_message_event,
    upsert_integration_sync_state,
)
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_sqs = boto3.client("sqs")
_POLL_MAX_RESULTS = int(os.getenv("GMAIL_POLL_MAX_RESULTS", "25"))


def _load_active_gmail_accounts() -> list[dict[str, Any]]:
    return _db.query(
        """
        SELECT integration_account_id::TEXT as integration_account_id,
               agent_id::TEXT as agent_id,
               default_space_id::TEXT as default_space_id,
               credentials_secret_arn
        FROM integration_accounts
        WHERE provider = 'gmail'
          AND status = 'active'
        ORDER BY created_at ASC, integration_account_id ASC
        """
    )


def _persist_integration_event(
    *,
    agent_id: str,
    space_id: str,
    normalized: Any,
    transaction_id: str,
) -> tuple[str, str]:
    if normalized.integration_message is None:
        raise RuntimeError("gmail normalized message missing integration payload")

    write_result = insert_integration_message(_db, normalized.integration_message, transaction_id=transaction_id)
    resolved = write_result.message
    if not resolved.event_id:
        event_id = str(uuid.uuid4())
        event_payload = dict(normalized.event_payload)
        event_payload["integration_message_id"] = resolved.integration_message_id
        _db.execute(
            """
            INSERT INTO events(event_id, agent_id, space_id, device_id, type, payload)
            VALUES(
                :event_id::uuid,
                :agent_id::uuid,
                :space_id::uuid,
                NULL,
                :type,
                :payload::jsonb
            )
            """,
            {
                "event_id": event_id,
                "agent_id": agent_id,
                "space_id": space_id,
                "type": "integration.event.received",
                "payload": json.dumps(event_payload),
            },
            transaction_id=transaction_id,
        )
        resolved = link_integration_message_event(
            _db,
            integration_message_id=resolved.integration_message_id,
            event_id=event_id,
            transaction_id=transaction_id,
        )
    if not resolved.event_id:
        raise RuntimeError("gmail integration message missing event_id")
    return resolved.integration_message_id, resolved.event_id


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if not _cfg.integration_queue_url:
        raise RuntimeError("INTEGRATION_QUEUE_URL not configured")

    summary = {
        "accounts_seen": 0,
        "accounts_processed": 0,
        "accounts_skipped": 0,
        "messages_polled": 0,
        "messages_enqueued": 0,
        "cursor_updates": 0,
    }

    for account in _load_active_gmail_accounts():
        summary["accounts_seen"] += 1
        integration_account_id = str(account.get("integration_account_id") or "").strip()
        agent_id = str(account.get("agent_id") or "").strip()
        space_id = str(account.get("default_space_id") or "").strip()
        credentials_secret_arn = str(account.get("credentials_secret_arn") or "").strip()
        if not integration_account_id or not agent_id or not space_id or not credentials_secret_arn:
            logger.warning(
                "Skipping gmail account with incomplete configuration: %s", integration_account_id or "<missing>"
            )
            summary["accounts_skipped"] += 1
            continue

        try:
            credentials = load_gmail_credentials(credentials_secret_arn)
            access_token = refresh_gmail_access_token(credentials)
            sync_state = get_integration_sync_state(
                _db, integration_account_id=integration_account_id, sync_key="gmail"
            )
            current_cursor = sync_state.cursor if sync_state else None
            refs, next_cursor = list_gmail_message_refs(
                access_token,
                history_id=current_cursor,
                max_results=_POLL_MAX_RESULTS,
            )
        except Exception as exc:
            logger.warning("Failed to prepare gmail poll for %s: %s", integration_account_id, exc)
            summary["accounts_skipped"] += 1
            continue

        if not refs:
            if next_cursor and next_cursor != current_cursor:
                upsert_integration_sync_state(
                    _db,
                    integration_account_id=integration_account_id,
                    sync_key="gmail",
                    cursor=next_cursor,
                    state={"user_email": credentials.user_email},
                )
                summary["cursor_updates"] += 1
            summary["accounts_processed"] += 1
            continue

        tx = _db.begin()
        queue_messages: list[IntegrationQueueMessage] = []
        try:
            for ref in refs:
                raw_message = fetch_gmail_message(access_token, message_id=ref.message_id)
                normalized = normalize_gmail_message(
                    raw_message,
                    agent_id=agent_id,
                    space_id=space_id,
                    integration_account_id=integration_account_id,
                    user_email=credentials.user_email,
                )
                integration_message_id, event_id = _persist_integration_event(
                    agent_id=agent_id,
                    space_id=space_id,
                    normalized=normalized,
                    transaction_id=tx,
                )
                queue_messages.append(
                    IntegrationQueueMessage(
                        event_id=event_id,
                        agent_id=agent_id,
                        space_id=space_id,
                        integration_message_id=integration_message_id,
                    )
                )
            _db.commit(tx)
        except Exception as exc:
            _db.rollback(tx)
            logger.warning("Failed to persist gmail poll batch for %s: %s", integration_account_id, exc)
            summary["accounts_skipped"] += 1
            continue

        try:
            for queue_message in queue_messages:
                enqueue_integration_event(
                    _sqs,
                    queue_url=_cfg.integration_queue_url,
                    message=queue_message,
                )
        except Exception as exc:
            logger.warning("Failed to enqueue gmail poll batch for %s: %s", integration_account_id, exc)
            summary["accounts_skipped"] += 1
            continue

        if next_cursor and next_cursor != current_cursor:
            upsert_integration_sync_state(
                _db,
                integration_account_id=integration_account_id,
                sync_key="gmail",
                cursor=next_cursor,
                state={"user_email": credentials.user_email},
            )
            summary["cursor_updates"] += 1

        summary["accounts_processed"] += 1
        summary["messages_polled"] += len(refs)
        summary["messages_enqueued"] += len(queue_messages)

    logger.info("gmail poll summary=%s", summary)
    return summary
