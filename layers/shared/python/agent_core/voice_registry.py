from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Optional, Tuple

import boto3


_dynamodb = boto3.resource("dynamodb")
_cached_table = None
_cached_table_name: Optional[str] = None


def _get_table():
    global _cached_table, _cached_table_name
    table_name = os.environ.get("AGENT_STATE_TABLE")
    if not table_name:
        return None
    if _cached_table is None or _cached_table_name != table_name:
        _cached_table_name = table_name
        _cached_table = _dynamodb.Table(table_name)
    return _cached_table


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def resolve_voice(
    agent_id: str,
    voice_id: Optional[str] = None,
    claimed_name: Optional[str] = None,
    embedding: Any = None,
) -> Tuple[Optional[str], bool]:
    """Resolve or register speaker identity.

    Returns: (speaker_name_or_None, is_new_voice)

    Behavior:
    - If voice_id is known and has a stored name -> (name, False)
    - If voice_id is known but unnamed -> (None, False)
    - If voice_id is new:
        - if claimed_name provided -> store name and return (claimed_name, True)
        - else -> store placeholder and return (None, True)
    - If no voice_id but claimed_name exists -> (claimed_name, False)

    The embedding is accepted but not persisted in this skeleton.
    """
    table = _get_table()
    if table is None:
        logging.error("resolve_voice: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return claimed_name, False

    if not voice_id:
        return (claimed_name, False) if claimed_name else (None, False)

    vid = str(voice_id)
    pk = f"VOICE#{agent_id}"
    sk = vid

    try:
        resp = table.get_item(Key={"pk": pk, "sk": sk})
        item = resp.get("Item")
    except Exception as e:
        logging.error("resolve_voice: get_item failed: %s", e)
        return claimed_name, False

    if item:
        name = item.get("speaker_name")
        return (name, False) if name else (None, False)

    # new voice
    is_new = True
    record = {
        "pk": pk,
        "sk": sk,
        "first_seen_ts": _now_iso(),
        "gsi1pk": f"VOICE#{agent_id}",
        "gsi1sk": sk,
    }
    if claimed_name:
        record["speaker_name"] = claimed_name

    try:
        table.put_item(Item=record)
    except Exception as e:
        logging.error("resolve_voice: put_item failed: %s", e)
        return claimed_name, False

    return (claimed_name, is_new) if claimed_name else (None, is_new)
