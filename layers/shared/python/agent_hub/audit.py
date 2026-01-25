from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import uuid
from typing import Any, Mapping

import boto3

from agent_hub.rds_data import RdsData

logger = logging.getLogger(__name__)


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def append_audit_entry(db: RdsData, *, bucket: str, agent_id: str, entry_type: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    """Append an audit entry to the WORM bucket.

    We keep a lightweight hash chain in Postgres (`audit_state`) so you can verify
    tamper-evidence offline by walking the chain.

    This is *not* a blockchain; it's a practical integrity chain combined with
    S3 Object Lock immutability.
    """

    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    entry_id = str(uuid.uuid4())

    # Load previous hash
    prev_rows = db.query(
        """
        SELECT last_hash
        FROM audit_state
        WHERE agent_id = :agent_id::uuid
        LIMIT 1
        """,
        {"agent_id": agent_id},
    )
    prev_hash = (prev_rows[0].get("last_hash") if prev_rows else None) or "GENESIS"

    payload = {
        "entry_id": entry_id,
        "agent_id": agent_id,
        "type": entry_type,
        "ts": now.isoformat(),
        "prev_hash": prev_hash,
        "data": entry,
    }
    payload_hash = _sha256_hex(prev_hash + _canon_json(payload))
    payload["hash"] = payload_hash

    key = f"audit/agent_id={agent_id}/year={now.year}/month={now.month:02d}/day={now.day:02d}/{now.isoformat()}_{entry_id}.json"

    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=_canon_json(payload).encode("utf-8"),
        ContentType="application/json",
    )

    # Update audit state (best effort; you can also reconstruct from S3).
    tx = db.begin()
    try:
        db.execute(
            """
            INSERT INTO audit_state(agent_id, last_hash, updated_at)
            VALUES (:agent_id::uuid, :last_hash, now())
            ON CONFLICT (agent_id) DO UPDATE
              SET last_hash = EXCLUDED.last_hash,
                  updated_at = now()
            """,
            {"agent_id": agent_id, "last_hash": payload_hash},
            transaction_id=tx,
        )
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise

    return payload
