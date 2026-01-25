from __future__ import annotations

from agent_hub.rds_data import RdsData


def is_agent_disabled(db: RdsData, agent_id: str) -> bool:
    rows = db.query(
        """
        SELECT disabled
        FROM agents
        WHERE agent_id = :agent_id::uuid
        LIMIT 1
        """,
        {"agent_id": agent_id},
    )
    if not rows:
        return False
    return bool(rows[0].get("disabled"))


def is_privacy_mode(db: RdsData, space_id: str) -> bool:
    rows = db.query(
        """
        SELECT privacy_mode
        FROM spaces
        WHERE space_id = :space_id::uuid
        LIMIT 1
        """,
        {"space_id": space_id},
    )
    if not rows:
        return False
    return bool(rows[0].get("privacy_mode"))
