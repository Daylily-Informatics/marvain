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


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    cognito_sub: str
    email: str | None


def _boto3_client(service_name: str):
    # Lazy import so local unit tests don't require boto3 installed.
    import boto3  # type: ignore

    return boto3.client(service_name)


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


def _cognito_sub_and_email_from_access_token(access_token: str) -> tuple[str, str | None]:
    """Resolve Cognito user identity from an access token.

    V1 strategy (per plan): call cognito-idp:GetUser server-side.
    """

    client = _boto3_client("cognito-idp")
    resp: Any = client.get_user(AccessToken=access_token)
    attrs = {a.get("Name"): a.get("Value") for a in (resp.get("UserAttributes") or []) if isinstance(a, dict)}

    cognito_sub = str(attrs.get("sub") or resp.get("Username") or "").strip()
    if not cognito_sub:
        raise PermissionError("Missing cognito sub")

    email = attrs.get("email")
    return cognito_sub, (str(email).strip() if email else None)


def _ensure_user_row(db: RdsData, *, cognito_sub: str, email: str | None) -> str:
    rows = db.query(
        """
        INSERT INTO users (cognito_sub, email)
        VALUES (:sub, :email)
        ON CONFLICT (cognito_sub)
        DO UPDATE SET email = COALESCE(EXCLUDED.email, users.email)
        RETURNING user_id::TEXT as user_id
        """,
        {"sub": cognito_sub, "email": email},
    )
    if not rows:
        raise RuntimeError("Failed to ensure users row")
    return str(rows[0].get("user_id") or "").strip()


def ensure_user_row(db: RdsData, *, cognito_sub: str, email: str | None) -> str:
    """Public wrapper used by other modules to upsert a Cognito-backed user."""
    return _ensure_user_row(db, cognito_sub=cognito_sub, email=email)


def lookup_cognito_user_by_email(*, user_pool_id: str, email: str) -> tuple[str, str | None]:
    """Resolve (sub, email) for a Cognito User Pool user by email.

    Uses cognito-idp:ListUsers with an email filter.
    """

    email = str(email).strip()
    if not email:
        raise LookupError("email is required")

    # Escape double-quotes for the Cognito filter string.
    safe_email = email.replace('"', "\\\"")
    client = _boto3_client("cognito-idp")
    resp = client.list_users(
        UserPoolId=user_pool_id,
        Filter=f'email = "{safe_email}"',
        Limit=2,
    )
    users = resp.get("Users") or []
    if not users:
        raise LookupError("user not found")
    if len(users) > 1:
        raise LookupError("multiple users matched")

    attrs = {a.get("Name"): a.get("Value") for a in (users[0].get("Attributes") or [])}
    sub = attrs.get("sub")
    if not sub:
        raise LookupError("missing sub attribute")
    em = attrs.get("email")
    return str(sub), (str(em).strip() if em else None)


def authenticate_user_access_token(db: RdsData, access_token: str) -> AuthenticatedUser:
    cognito_sub, email = _cognito_sub_and_email_from_access_token(access_token)
    user_id = _ensure_user_row(db, cognito_sub=cognito_sub, email=email)
    if not user_id:
        raise RuntimeError("Failed to resolve user_id")
    return AuthenticatedUser(user_id=user_id, cognito_sub=cognito_sub, email=email)
