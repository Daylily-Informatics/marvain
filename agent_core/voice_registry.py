from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

from . import memory_store

logger = logging.getLogger(__name__)


def resolve_voice(
    *,
    agent_id: str,
    voice_id: Optional[str],
    claimed_name: Optional[str],
    embedding: Any = None,
) -> Tuple[Optional[str], bool]:
    """Resolve a voice identity to a stable speaker_name.

    Returns: (speaker_name, is_new_voice)

    Behavior:
    - If voice_id exists:
      - If record exists and has speaker_name, return it.
      - If record exists and claimed_name provided, update speaker_name.
      - If no record, create it (speaker_name may be None if unknown).
    - If no voice_id:
      - Fall back to claimed_name (if any).
    """
    if not voice_id:
        if claimed_name:
            return claimed_name, False
        return None, True

    voice_id = str(voice_id)

    rec = memory_store.get_voice_record(agent_id, voice_id)
    if rec:
        known = rec.get("speaker_name")
        if claimed_name and (not known or known != claimed_name):
            logger.info("Updating voice registry name voice_id=%s speaker_name=%s", voice_id, claimed_name)
            memory_store.put_voice_record(agent_id, voice_id, {"speaker_name": claimed_name, "had_embedding": bool(embedding)})
            return claimed_name, False
        return known or claimed_name, False

    # New voice
    logger.info("New voice detected voice_id=%s claimed_name=%s", voice_id, claimed_name)
    memory_store.put_voice_record(
        agent_id,
        voice_id,
        {
            "speaker_name": claimed_name,
            "had_embedding": bool(embedding),
        },
    )
    return claimed_name, True
