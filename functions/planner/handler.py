from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from typing import Any

import boto3
from agent_hub.action_service import create_action
from agent_hub.auto_approve_policy import evaluate_auto_approve
from agent_hub.audit import append_audit_entry
from agent_hub.broadcast import broadcast_event
from agent_hub.contracts import validate_tool_payload
from agent_hub.config import load_config
from agent_hub.integrations import get_integration_message, parse_integration_queue_message
from agent_hub.openai_http import call_embeddings, call_responses, extract_output_text
from agent_hub.policy import is_agent_disabled, is_privacy_mode
from agent_hub.rate_limit import RateLimitError
from agent_hub.rds_data import RdsData, RdsDataEnv

from .validation import sanitize_planner_output, validate_planner_output

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_sqs = boto3.client("sqs")
_AUTO_APPROVE_POLICY_MODE = str(os.getenv("AUTO_APPROVE_POLICY_MODE", "enforce")).strip().lower()

# Idempotency: track processed event IDs in memory (per Lambda invocation)
# For true cross-invocation idempotency, we use a database check
_PROCESSED_EVENTS: set[str] = set()


def _compute_action_idempotency_key(event_id: str, action_index: int, kind: str) -> str:
    """Compute a deterministic idempotency key for planner-created actions."""
    content = f"{event_id}:{action_index}:{kind}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]


def _planner_request_origin(event_id: str) -> str:
    return f"planner:{event_id}"


def _is_already_processed(event_id: str) -> bool:
    """Check if an event has already been processed.

    Uses both in-memory cache and database check for idempotency.
    """
    if event_id in _PROCESSED_EVENTS:
        return True

    # Check if memories or actions already exist for this event
    rows = _db.query(
        """
        SELECT 1 FROM memories
        WHERE provenance->>'source_event_id' = :event_id
        LIMIT 1
        """,
        {"event_id": event_id},
    )
    if rows:
        _PROCESSED_EVENTS.add(event_id)
        return True

    rows = _db.query(
        """
        SELECT 1 FROM actions
        WHERE request_origin = :request_origin
        LIMIT 1
        """,
        {"request_origin": _planner_request_origin(event_id)},
    )
    if rows:
        _PROCESSED_EVENTS.add(event_id)
        return True

    return False


def _mark_processed(event_id: str) -> None:
    """Mark an event as processed in the in-memory cache."""
    _PROCESSED_EVENTS.add(event_id)
    # Limit cache size to prevent memory issues
    if len(_PROCESSED_EVENTS) > 10000:
        # Remove oldest entries (arbitrary, since set is unordered)
        to_remove = list(_PROCESSED_EVENTS)[:5000]
        for item in to_remove:
            _PROCESSED_EVENTS.discard(item)


def _load_event(event_id: str) -> dict[str, Any] | None:
    rows = _db.query(
        """
        SELECT event_id::TEXT as event_id,
               agent_id::TEXT as agent_id,
               space_id::TEXT as space_id,
               device_id::TEXT as device_id,
               person_id::TEXT as person_id,
               type,
               payload::TEXT as payload_json,
               created_at::TEXT as created_at
        FROM events
        WHERE event_id = :event_id::uuid
        LIMIT 1
        """,
        {"event_id": event_id},
    )
    if not rows:
        return None
    row = rows[0]
    try:
        row["payload"] = json.loads(row.get("payload_json") or "{}")
    except Exception:
        row["payload"] = {}
    return row


def _bounded_optional_text(value: Any, *, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _field_value(message: Any, field_name: str, default: Any = None) -> Any:
    if isinstance(message, dict):
        return message.get(field_name, default)
    return getattr(message, field_name, default)


def _bounded_integration_metadata(message: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {}

    for field_name, limit in (
        ("provider", 32),
        ("channel_type", 32),
        ("object_type", 64),
        ("subject", 256),
        ("external_thread_id", 128),
        ("external_message_id", 128),
    ):
        value = _bounded_optional_text(_field_value(message, field_name), limit=limit)
        if value:
            metadata[field_name] = value

    sender_value = _field_value(message, "sender", None)
    if sender_value is None:
        sender_value = _field_value(message, "sender_json", {})
    if isinstance(sender_value, str):
        try:
            sender_value = json.loads(sender_value)
        except Exception:
            sender_value = {}
    if isinstance(sender_value, dict):
        sender: dict[str, str] = {}
        for key in ("user_id", "bot_id", "team_id", "email", "phone_number"):
            value = _bounded_optional_text(sender_value.get(key), limit=128)
            if value:
                sender[key] = value
        if sender:
            metadata["sender"] = sender

    recipients_value = _field_value(message, "recipients", None)
    if recipients_value is None:
        recipients_value = _field_value(message, "recipients_json", [])
    if isinstance(recipients_value, str):
        try:
            recipients_value = json.loads(recipients_value)
        except Exception:
            recipients_value = []
    if isinstance(recipients_value, list):
        recipients: list[dict[str, str]] = []
        for item in recipients_value[:5]:
            if not isinstance(item, dict):
                continue
            recipient: dict[str, str] = {}
            for key in ("channel_id", "user_id", "email", "phone_number"):
                value = _bounded_optional_text(item.get(key), limit=128)
                if value:
                    recipient[key] = value
            if recipient:
                recipients.append(recipient)
        if recipients:
            metadata["recipients"] = recipients

    return metadata


def _load_integration_thread_context(integration_message: Any) -> list[dict[str, Any]]:
    external_thread_id = _bounded_optional_text(_field_value(integration_message, "external_thread_id"), limit=128)
    if not external_thread_id:
        return []

    agent_id = _bounded_optional_text(_field_value(integration_message, "agent_id"), limit=64)
    provider = _bounded_optional_text(_field_value(integration_message, "provider"), limit=32)
    integration_message_id = _bounded_optional_text(_field_value(integration_message, "integration_message_id"), limit=64)
    created_at = _field_value(integration_message, "created_at")
    if not agent_id or not provider or not integration_message_id or not created_at:
        return []

    rows = _db.query(
        """
        SELECT integration_message_id::TEXT as integration_message_id,
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
        FROM integration_messages
        WHERE agent_id = :agent_id::uuid
          AND provider = :provider
          AND external_thread_id = :external_thread_id
          AND (
            created_at < :created_at::timestamptz
            OR (
              created_at = :created_at::timestamptz
              AND integration_message_id <> :integration_message_id::uuid
            )
          )
        ORDER BY created_at DESC, integration_message_id DESC
        LIMIT 10
        """,
        {
            "agent_id": agent_id,
            "provider": provider,
            "external_thread_id": external_thread_id,
            "integration_message_id": integration_message_id,
            "created_at": str(created_at),
        },
    )
    if not isinstance(rows, list):
        return []
    thread_context: list[dict[str, Any]] = []
    for row in rows or []:
        thread_context.append(
            {
                "integration_message_id": str(row.get("integration_message_id") or "").strip(),
                "agent_id": str(row.get("agent_id") or "").strip(),
                "space_id": str(row.get("space_id") or "").strip() or None,
                "event_id": str(row.get("event_id") or "").strip() or None,
                "provider": str(row.get("provider") or "").strip(),
                "direction": str(row.get("direction") or "").strip(),
                "channel_type": str(row.get("channel_type") or "").strip(),
                "object_type": str(row.get("object_type") or "").strip(),
                "external_thread_id": str(row.get("external_thread_id") or "").strip() or None,
                "external_message_id": str(row.get("external_message_id") or "").strip() or None,
                "dedupe_key": str(row.get("dedupe_key") or "").strip(),
                "status": str(row.get("status") or "").strip(),
                "text": str(row.get("body_text") or "").strip(),
                "integration": _bounded_integration_metadata(row),
            }
        )
    return thread_context


def _build_planner_event_context(
    ev: dict[str, Any],
    *,
    integration_message: Any | None = None,
    thread_context: list[dict[str, Any]] | None = None,
) -> tuple[str, dict[str, Any]]:
    payload = ev.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}

    if integration_message is None:
        text = str(payload.get("text") or payload.get("transcript") or "").strip()
        return text, {
            "event_id": ev["event_id"],
            "space_id": ev["space_id"],
            "person_id": ev.get("person_id"),
            "type": ev["type"],
            "text": text,
        }

    text = str(getattr(integration_message, "body_text", "") or "").strip()
    integration = _bounded_integration_metadata(integration_message)
    if thread_context is not None:
        integration["thread_context"] = thread_context
    event_context = {
        "event_id": ev["event_id"],
        "space_id": ev["space_id"],
        "person_id": ev.get("person_id"),
        "type": ev["type"],
        "text": text,
        "integration": integration,
    }
    return text, event_context


def _vector_recall(agent_id: str, query_text: str) -> list[dict[str, Any]]:
    """Retrieve top memories via pgvector.

    NOTE: This uses Data API, so we must ensure we do not return the vector column.
    """
    if not _cfg.openai_secret_arn:
        return []
    embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
    emb = call_embeddings(openai_secret_arn=_cfg.openai_secret_arn, model=embed_model, text=query_text)
    emb_str = "[" + ",".join(f"{x:.6f}" for x in emb) + "]"

    rows = _db.query(
        """
        SELECT memory_id::TEXT as memory_id,
               tier,
               content,
               created_at::TEXT as created_at,
               (embedding <=> CAST(:q AS vector))::DOUBLE PRECISION as distance
        FROM memories
        WHERE agent_id = :agent_id::uuid
          AND embedding IS NOT NULL
        ORDER BY embedding <=> CAST(:q AS vector)
        LIMIT 8
        """,
        {"agent_id": agent_id, "q": emb_str},
    )
    return rows


def _insert_memory(
    *, agent_id: str, space_id: str | None, tier: str, content: str, participants: list[str], provenance: dict[str, Any]
) -> str:
    memory_id = str(uuid.uuid4())

    embedding = None
    emb_str = None
    if _cfg.openai_secret_arn:
        try:
            embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
            embedding = call_embeddings(openai_secret_arn=_cfg.openai_secret_arn, model=embed_model, text=content)
            emb_str = "[" + ",".join(f"{x:.6f}" for x in embedding) + "]"
        except Exception as e:
            logger.warning("Embedding failed: %s", e)

    _db.execute(
        """
        INSERT INTO memories(memory_id, agent_id, space_id, tier, content, participants, provenance, retention, embedding)
        VALUES(
          :memory_id::uuid,
          :agent_id::uuid,
          CASE WHEN :space_id IS NULL THEN NULL ELSE :space_id::uuid END,
          :tier,
          :content,
          :participants::jsonb,
          :provenance::jsonb,
          :retention::jsonb,
          CASE WHEN :embedding IS NULL THEN NULL ELSE CAST(:embedding AS vector) END
        )
        """,
        {
            "memory_id": memory_id,
            "agent_id": agent_id,
            "space_id": space_id,
            "tier": tier,
            "content": content,
            "participants": json.dumps(participants),
            "provenance": json.dumps(provenance),
            "retention": json.dumps({"policy": "v1"}),
            "embedding": emb_str,
        },
    )
    return memory_id


def handler(event: dict, context: Any) -> dict[str, Any]:
    records = event.get("Records") or []
    processed = 0
    skipped_idempotent = 0
    skipped_privacy = 0
    skipped_rate_limit = 0

    for rec in records:
        body = rec.get("body") or "{}"
        try:
            msg = json.loads(body)
        except Exception:
            safe_body = str(body).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
            logger.warning("Bad message body: %s", safe_body)
            continue

        integration_message_id: str | None = None
        if msg.get("event_type"):
            try:
                integration_queue_message = parse_integration_queue_message(msg)
            except ValueError as exc:
                logger.warning("Bad integration queue message: %s", exc)
                continue
            event_id = integration_queue_message.event_id
            integration_message_id = integration_queue_message.integration_message_id
        else:
            event_id = msg.get("event_id")
        if not event_id:
            continue

        # Idempotency check: skip if already processed
        if _is_already_processed(event_id):
            logger.info("Event already processed (idempotent skip): %s", event_id)
            skipped_idempotent += 1
            continue

        ev = _load_event(event_id)
        if not ev:
            continue

        agent_id = ev["agent_id"]
        space_id = ev.get("space_id")

        if is_agent_disabled(_db, agent_id):
            logger.info("Agent disabled; skipping")
            continue

        # Privacy mode check: skip planning for private spaces
        if space_id and is_privacy_mode(_db, space_id):
            logger.info("Space is in privacy mode; skipping planning for event %s", event_id)
            skipped_privacy += 1
            continue

        integration_message = None
        thread_context: list[dict[str, Any]] | None = None
        if ev.get("type") == "integration.event.received":
            integration_message_id_n = str(integration_message_id or "").strip()
            if not integration_message_id_n:
                logger.warning("Integration event missing integration_message_id: %s", event_id)
                continue
            integration_message = get_integration_message(_db, integration_message_id=integration_message_id_n)
            if integration_message is None:
                logger.warning("Integration message not found: %s", integration_message_id_n)
                continue
            if _field_value(integration_message, "external_thread_id"):
                thread_context = _load_integration_thread_context(integration_message)

        transcript_text, planner_event = _build_planner_event_context(
            ev,
            integration_message=integration_message,
            thread_context=thread_context,
        )
        if not transcript_text:
            # nothing to plan on
            continue

        recalled = []
        try:
            recalled = _vector_recall(agent_id, transcript_text)
        except Exception as e:
            logger.warning("Vector recall failed (continuing): %s", e)

        system = """
You are the deliberative planner for a persistent personal AI agent hub.

Goals:
- Update long-term memory (episodic + semantic) conservatively.
- Propose actions ONLY when they are clearly helpful.
- Never store sensitive biometric data unless explicitly instructed.

Output STRICT JSON with keys:
- episodic: array of {content, participants}
- semantic: array of {content, participants}
- actions: array of {kind, payload, required_scopes, auto_approve}

Rules:
- Keep memory minimal, high-signal.
- If uncertain, do not write semantic facts; write an episodic note instead.
- When event.integration is present, it is bounded metadata for an inbound external message.
""".strip()

        user = {
            "event": planner_event,
            "recalled_memories": recalled,
        }

        if not _cfg.openai_secret_arn:
            logger.warning("OPENAI_SECRET_ARN not configured; skipping planning")
            continue

        # Call LLM with rate limit handling
        try:
            resp = call_responses(
                openai_secret_arn=_cfg.openai_secret_arn,
                model=os.getenv("PLANNER_MODEL", _cfg.planner_model or "gpt-4.1-mini"),
                system=system,
                user=json.dumps(user),
            )
        except RateLimitError as e:
            logger.error("Rate limit exceeded for event %s: %s", event_id, str(e))
            skipped_rate_limit += 1
            # Don't mark as processed - allow retry on next invocation
            continue
        except Exception as e:
            logger.error("LLM call failed for event %s: %s", event_id, str(e))
            continue

        out_text = extract_output_text(resp)

        try:
            plan = json.loads(out_text)
        except Exception:
            logger.warning("Planner returned non-JSON; skipping. output=%s", out_text[:4000])
            continue

        # Validate planner output against schema
        is_valid, validation_error = validate_planner_output(plan)
        if not is_valid:
            logger.warning("Planner output failed schema validation: %s", validation_error)
            # Continue with sanitized output instead of skipping

        # Sanitize and normalize the output
        plan = sanitize_planner_output(plan)

        episodic = plan.get("episodic") or []
        semantic = plan.get("semantic") or []
        actions = plan.get("actions") or []

        created_memory_ids: list[str] = []
        for item in episodic:
            # Already sanitized, so we can use directly
            mid = _insert_memory(
                agent_id=agent_id,
                space_id=ev["space_id"],
                tier="episodic",
                content=item["content"],
                participants=item["participants"],
                provenance={"source_event_id": ev["event_id"]},
            )
            created_memory_ids.append(mid)

        for item in semantic:
            mid = _insert_memory(
                agent_id=agent_id,
                space_id=None,
                tier="semantic",
                content=item["content"],
                participants=item["participants"],
                provenance={"source_event_id": ev["event_id"]},
            )
            created_memory_ids.append(mid)

        created_action_ids: list[str] = []
        for action_index, a in enumerate(actions):
            try:
                created_action = create_action(
                    _db,
                    agent_id=agent_id,
                    space_id=ev["space_id"],
                    kind=str(a["kind"]),
                    payload=a["payload"],
                    required_scopes=[str(s) for s in (a.get("required_scopes") or [])],
                    manual_auto_approve=False,
                    idempotency_key=_compute_action_idempotency_key(ev["event_id"], action_index, str(a["kind"])),
                    request_actor_type="planner",
                    request_actor_id=agent_id,
                    request_origin=_planner_request_origin(ev["event_id"]),
                    policy_mode=_AUTO_APPROVE_POLICY_MODE,
                    audit_bucket=_cfg.audit_bucket,
                    sqs_client=_sqs,
                    action_queue_url=_cfg.action_queue_url,
                )
            except Exception as exc:
                logger.warning("Skipping planner action kind=%s err=%s", a.get("kind"), exc)
                continue

            action_id = created_action["action_id"]
            status = created_action["status"]
            created_action_ids.append(action_id)

            # Broadcast action creation to subscribed clients
            try:
                broadcast_event(
                    event_type="actions.updated",
                    agent_id=agent_id,
                    space_id=ev["space_id"],
                    payload={
                        "action_id": action_id,
                        "kind": a["kind"],
                        "status": status,
                    },
                )
            except Exception as e:
                logger.warning("Failed to broadcast action: %s", e)

        # Broadcast memories creation (if any)
        for mid in created_memory_ids:
            try:
                broadcast_event(
                    event_type="memories.new",
                    agent_id=agent_id,
                    space_id=ev["space_id"],
                    payload={"memory_id": mid},
                )
            except Exception as e:
                logger.warning("Failed to broadcast memory: %s", e)

        if _cfg.audit_bucket:
            append_audit_entry(
                _db,
                bucket=_cfg.audit_bucket,
                agent_id=agent_id,
                entry_type="planner_result",
                entry={
                    "event_id": ev["event_id"],
                    "created_memory_ids": created_memory_ids,
                    "created_action_ids": created_action_ids,
                },
            )

        # Mark event as processed for idempotency
        _mark_processed(event_id)
        processed += 1

    return {
        "processed": processed,
        "skipped_idempotent": skipped_idempotent,
        "skipped_privacy": skipped_privacy,
        "skipped_rate_limit": skipped_rate_limit,
    }
