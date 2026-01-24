from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from agent_hub.rds_data import RdsData


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_device_token() -> str:
    # URL-safe, high entropy; treat as bearer secret
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class AuthenticatedDevice:
    device_id: str
    agent_id: str
    scopes: list[str]


def authenticate_device(db: RdsData, bearer_token: str) -> AuthenticatedDevice | None:
    thash = hash_token(bearer_token)
    rows = db.query(
        """
        SELECT device_id::TEXT as device_id,
               agent_id::TEXT as agent_id,
               COALESCE(scopes, '[]'::jsonb)::TEXT as scopes_json
        FROM devices
        WHERE token_hash = :token_hash
          AND revoked_at IS NULL
        LIMIT 1
        """,
        {"token_hash": thash},
    )
    if not rows:
        return None
    row = rows[0]
    try:
        scopes = __import__("json").loads(row.get("scopes_json") or "[]")
    except Exception:
        scopes = []
    return AuthenticatedDevice(
        device_id=row["device_id"],
        agent_id=row["agent_id"],
        scopes=[str(s) for s in scopes],
    )


def require_scopes(device: AuthenticatedDevice, required: list[str]) -> None:
    missing = [s for s in required if s not in device.scopes]
    if missing:
        raise PermissionError(f"Missing required scopes: {missing}")
