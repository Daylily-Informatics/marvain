from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from typing import Any

import boto3
from agent_hub.audit import append_audit_entry
from agent_hub.broadcast import broadcast_event
from agent_hub.config import load_config
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

# Idempotency: track processed event IDs in memory (per Lambda invocation)
# For true cross-invocation idempotency, we use a database check
_PROCESSED_EVENTS: set[str] = set()


def _compute_idempotency_key(event_id: str, transcript_text: str) -> str:
    """Compute a deterministic idempotency key for an event.

    This ensures that the same event with the same content produces
    the same key, allowing us to detect duplicate processing.
    """
    content = f"{event_id}:{transcript_text}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]


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

        payload = ev.get("payload") or {}
        transcript_text = str(payload.get("text") or payload.get("transcript") or "").strip()
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
""".strip()

        user = {
            "event": {
                "event_id": ev["event_id"],
                "space_id": ev["space_id"],
                "person_id": ev.get("person_id"),
                "text": transcript_text,
            },
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
        for a in actions:
            # Already sanitized
            action_id = str(uuid.uuid4())
            _db.execute(
                """
                INSERT INTO actions(action_id, agent_id, space_id, kind, payload, required_scopes, status)
                VALUES(
                  :action_id::uuid,
                  :agent_id::uuid,
                  :space_id::uuid,
                  :kind,
                  :payload::jsonb,
                  :required_scopes::jsonb,
                  :status
                )
                """,
                {
                    "action_id": action_id,
                    "agent_id": agent_id,
                    "space_id": ev["space_id"],
                    "kind": a["kind"],
                    "payload": json.dumps(a["payload"]),
                    "required_scopes": json.dumps(a["required_scopes"]),
                    "status": "approved" if a["auto_approve"] else "proposed",
                },
            )
            created_action_ids.append(action_id)

            if a["auto_approve"] and _cfg.action_queue_url:
                _sqs.send_message(
                    QueueUrl=_cfg.action_queue_url,
                    MessageBody=json.dumps({"action_id": action_id, "agent_id": agent_id}),
                )

            # Broadcast action creation to subscribed clients
            try:
                broadcast_event(
                    event_type="actions.updated",
                    agent_id=agent_id,
                    space_id=ev["space_id"],
                    payload={
                        "action_id": action_id,
                        "kind": a["kind"],
                        "status": "approved" if a["auto_approve"] else "proposed",
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
