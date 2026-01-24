from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

import boto3

from agent_hub.audit import append_audit_entry
from agent_hub.config import load_config
from agent_hub.openai_http import call_embeddings, call_responses, extract_output_text
from agent_hub.policy import is_agent_disabled
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_sqs = boto3.client("sqs")


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


def _insert_memory(*, agent_id: str, space_id: str | None, tier: str, content: str, participants: list[str], provenance: dict[str, Any]) -> str:
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

    for rec in records:
        body = rec.get("body") or "{}"
        try:
            msg = json.loads(body)
        except Exception:
            logger.warning("Bad message body: %s", body)
            continue

        event_id = msg.get("event_id")
        if not event_id:
            continue

        ev = _load_event(event_id)
        if not ev:
            continue

        agent_id = ev["agent_id"]
        if is_agent_disabled(_db, agent_id):
            logger.info("Agent disabled; skipping")
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

        resp = call_responses(
            openai_secret_arn=_cfg.openai_secret_arn,
            model=os.getenv("PLANNER_MODEL", _cfg.planner_model or "gpt-4.1-mini"),
            system=system,
            user=json.dumps(user),
        )
        out_text = extract_output_text(resp)

        try:
            plan = json.loads(out_text)
        except Exception:
            logger.warning("Planner returned non-JSON; skipping. output=%s", out_text[:4000])
            continue

        episodic = plan.get("episodic") or []
        semantic = plan.get("semantic") or []
        actions = plan.get("actions") or []

        created_memory_ids: list[str] = []
        for item in episodic:
            if not isinstance(item, dict):
                continue
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            participants = item.get("participants") or []
            mid = _insert_memory(
                agent_id=agent_id,
                space_id=ev["space_id"],
                tier="episodic",
                content=content,
                participants=[str(p) for p in participants],
                provenance={"source_event_id": ev["event_id"]},
            )
            created_memory_ids.append(mid)

        for item in semantic:
            if not isinstance(item, dict):
                continue
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            participants = item.get("participants") or []
            mid = _insert_memory(
                agent_id=agent_id,
                space_id=None,
                tier="semantic",
                content=content,
                participants=[str(p) for p in participants],
                provenance={"source_event_id": ev["event_id"]},
            )
            created_memory_ids.append(mid)

        created_action_ids: list[str] = []
        for a in actions:
            if not isinstance(a, dict):
                continue
            kind = str(a.get("kind") or "").strip()
            if not kind:
                continue
            payload_obj = a.get("payload") or {}
            required_scopes = a.get("required_scopes") or []
            auto = bool(a.get("auto_approve"))

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
                    "kind": kind,
                    "payload": json.dumps(payload_obj),
                    "required_scopes": json.dumps(required_scopes),
                    "status": "approved" if auto else "proposed",
                },
            )
            created_action_ids.append(action_id)

            if auto and _cfg.action_queue_url:
                _sqs.send_message(
                    QueueUrl=_cfg.action_queue_url,
                    MessageBody=json.dumps({"action_id": action_id, "agent_id": agent_id}),
                )

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

        processed += 1

    return {"processed": processed}
