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
    """Represents an authenticated user.

    NOTE: The cognito_sub field is being retained for database compatibility
    during the authentication rebuild. It will be populated from the new
    session-based auth implementation.
    """

    user_id: str
    cognito_sub: str  # Keep for DB schema compatibility
    email: str | None


def authenticate_user_access_token(db: RdsData, access_token: str) -> AuthenticatedUser:
    """Authenticate a human user via a Cognito access token.

    This calls Cognito `GetUser` to retrieve `sub` and `email`, ensures a users
    row exists, then returns the AuthenticatedUser.

    Kept as a thin, testable boundary for API routes that accept
    `Authorization: Bearer <access_token>`.
    """

    if not access_token:
        raise PermissionError("Missing access token")

    try:
        client = _boto3_client("cognito-idp")
        resp = client.get_user(AccessToken=access_token)
    except Exception as e:  # boto3 raises various ClientError subclasses
        raise PermissionError(f"Invalid access token: {e}")

    sub: str | None = None
    email: str | None = None
    for attr in resp.get("UserAttributes", []) or []:
        name = attr.get("Name")
        val = attr.get("Value")
        if name == "sub" and val:
            sub = str(val)
        elif name == "email" and val:
            email = str(val)

    if not sub:
        sub = str(resp.get("Username") or "").strip() or None
    if not sub:
        raise PermissionError("Cognito response missing sub")

    user_id = ensure_user_row(db, cognito_sub=sub, email=email)
    return AuthenticatedUser(user_id=user_id, cognito_sub=sub, email=email)


def _boto3_client(service_name: str):
    # Lazy import so local unit tests don't require boto3 installed.
    import boto3  # type: ignore

    return boto3.client(service_name)


def lookup_cognito_user_by_email(*, user_pool_id: str, email: str) -> tuple[str, str | None]:
    """Resolve (sub, email) for a Cognito User Pool user by email.

    Uses cognito-idp:ListUsers with an email filter.
    """

    email = str(email).strip()
    if not email:
        raise LookupError("email is required")
    user_pool_id = str(user_pool_id).strip()
    if not user_pool_id:
        raise LookupError("user_pool_id is required")

    # Escape double-quotes for the Cognito filter string.
    safe_email = email.replace('"', "\\\"")
    client = _boto3_client("cognito-idp")
    resp: Any = client.list_users(
        UserPoolId=user_pool_id,
        Filter=f'email = "{safe_email}"',
        Limit=2,
    )
    users = resp.get("Users") or []
    if not users:
        raise LookupError("user not found")
    if len(users) > 1:
        raise LookupError("multiple users matched")

    attrs = {a.get("Name"): a.get("Value") for a in (users[0].get("Attributes") or []) if isinstance(a, dict)}
    sub = attrs.get("sub") or users[0].get("Username")
    if not sub:
        raise LookupError("missing sub attribute")
    em = attrs.get("email")
    return str(sub), (str(em).strip() if em else None)


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


def _ensure_user_row(db: RdsData, *, cognito_sub: str, email: str | None) -> str:
    """Insert or update a user row in the database.

    NOTE: cognito_sub is used as the unique identifier for now.
    This will be refactored once the new auth system is in place.
    """
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
    """Public wrapper used by other modules to upsert a user.

    NOTE: cognito_sub parameter name retained for compatibility.
    Will be refactored with new auth implementation.
    """
    return _ensure_user_row(db, cognito_sub=cognito_sub, email=email)
