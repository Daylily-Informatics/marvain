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


# -----------------------------------------------------------------------------
# Agent-to-Agent Authentication
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthenticatedAgent:
    """Represents an authenticated agent (via agent token).

    Used for agent-to-agent communication where one agent authenticates
    to another agent's resources using a delegated token.
    """

    token_id: str
    issuer_agent_id: str  # The agent that issued the token
    target_agent_id: str | None  # The agent allowed to use it (None = any)
    scopes: list[str]
    allowed_spaces: list[str] | None  # None = all spaces


def generate_agent_token() -> str:
    """Generate a high-entropy agent-to-agent bearer token.

    Uses the same format as device tokens for consistency.
    """
    return secrets.token_urlsafe(32)


def create_agent_token(
    db: RdsData,
    *,
    issuer_agent_id: str,
    target_agent_id: str | None = None,
    name: str = "agent-token",
    scopes: list[str] | None = None,
    allowed_spaces: list[str] | None = None,
    expires_at: str | None = None,
    created_by_user_id: str | None = None,
) -> tuple[str, str]:
    """Create a new agent token for agent-to-agent authentication.

    Args:
        db: Database connection
        issuer_agent_id: The agent issuing/owning this token
        target_agent_id: If set, only this agent can use the token
        name: Human-readable name for the token
        scopes: List of permission scopes (e.g., ["read_memories", "write_events"])
        allowed_spaces: If set, token only valid for these space IDs
        expires_at: ISO timestamp when token expires (None = never)
        created_by_user_id: User who created the token (for audit)

    Returns:
        Tuple of (token_id, plaintext_token) - plaintext is only returned once!
    """
    import json

    token = generate_agent_token()
    token_hash_val = hash_token(token)

    rows = db.query(
        """
        INSERT INTO agent_tokens (
            issuer_agent_id, target_agent_id, name, token_hash,
            scopes, allowed_spaces, expires_at, created_by_user_id
        )
        VALUES (
            :issuer_agent_id::uuid,
            CASE WHEN :target_agent_id IS NULL THEN NULL ELSE :target_agent_id::uuid END,
            :name,
            :token_hash,
            :scopes::jsonb,
            CASE WHEN :allowed_spaces IS NULL THEN NULL ELSE :allowed_spaces::jsonb END,
            CASE WHEN :expires_at IS NULL THEN NULL ELSE :expires_at::timestamptz END,
            CASE WHEN :created_by_user_id IS NULL THEN NULL ELSE :created_by_user_id::uuid END
        )
        RETURNING token_id::TEXT as token_id
        """,
        {
            "issuer_agent_id": issuer_agent_id,
            "target_agent_id": target_agent_id,
            "name": name,
            "token_hash": token_hash_val,
            "scopes": json.dumps(scopes or []),
            "allowed_spaces": json.dumps(allowed_spaces) if allowed_spaces else None,
            "expires_at": expires_at,
            "created_by_user_id": created_by_user_id,
        },
    )

    if not rows:
        raise RuntimeError("Failed to create agent token")

    token_id = str(rows[0].get("token_id") or "").strip()
    return token_id, token


def authenticate_agent_token(db: RdsData, bearer_token: str) -> AuthenticatedAgent | None:
    """Authenticate an agent-to-agent bearer token.

    Args:
        db: Database connection
        bearer_token: The plaintext bearer token

    Returns:
        AuthenticatedAgent if valid, None if invalid/expired/revoked
    """
    import json

    token_hash_val = hash_token(bearer_token)

    rows = db.query(
        """
        SELECT
            token_id::TEXT as token_id,
            issuer_agent_id::TEXT as issuer_agent_id,
            target_agent_id::TEXT as target_agent_id,
            COALESCE(scopes, '[]'::jsonb)::TEXT as scopes_json,
            allowed_spaces::TEXT as allowed_spaces_json
        FROM agent_tokens
        WHERE token_hash = :token_hash
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1
        """,
        {"token_hash": token_hash_val},
    )

    if not rows:
        return None

    row = rows[0]

    # Update last_used_at
    db.execute(
        "UPDATE agent_tokens SET last_used_at = NOW() WHERE token_id = :token_id::uuid",
        {"token_id": row["token_id"]},
    )

    try:
        scopes = json.loads(row.get("scopes_json") or "[]")
    except Exception:
        scopes = []

    allowed_spaces = None
    if row.get("allowed_spaces_json"):
        try:
            allowed_spaces = json.loads(row["allowed_spaces_json"])
        except Exception:
            pass

    return AuthenticatedAgent(
        token_id=row["token_id"],
        issuer_agent_id=row["issuer_agent_id"],
        target_agent_id=row.get("target_agent_id"),
        scopes=[str(s) for s in scopes],
        allowed_spaces=allowed_spaces,
    )


def revoke_agent_token(db: RdsData, token_id: str) -> bool:
    """Revoke an agent token.

    Args:
        db: Database connection
        token_id: The token ID to revoke

    Returns:
        True if token was revoked, False if not found
    """
    rows = db.query(
        """
        UPDATE agent_tokens
        SET revoked_at = NOW()
        WHERE token_id = :token_id::uuid
          AND revoked_at IS NULL
        RETURNING token_id::TEXT as token_id
        """,
        {"token_id": token_id},
    )
    return len(rows) > 0


def list_agent_tokens(db: RdsData, issuer_agent_id: str) -> list[dict]:
    """List all tokens issued by an agent.

    Args:
        db: Database connection
        issuer_agent_id: The agent that issued the tokens

    Returns:
        List of token metadata (excludes token_hash for security)
    """
    import json

    rows = db.query(
        """
        SELECT
            token_id::TEXT as token_id,
            target_agent_id::TEXT as target_agent_id,
            name,
            COALESCE(scopes, '[]'::jsonb)::TEXT as scopes_json,
            allowed_spaces::TEXT as allowed_spaces_json,
            expires_at::TEXT as expires_at,
            revoked_at::TEXT as revoked_at,
            last_used_at::TEXT as last_used_at,
            created_at::TEXT as created_at
        FROM agent_tokens
        WHERE issuer_agent_id = :issuer_agent_id::uuid
        ORDER BY created_at DESC
        """,
        {"issuer_agent_id": issuer_agent_id},
    )

    result = []
    for row in rows:
        try:
            scopes = json.loads(row.get("scopes_json") or "[]")
        except Exception:
            scopes = []

        allowed_spaces = None
        if row.get("allowed_spaces_json"):
            try:
                allowed_spaces = json.loads(row["allowed_spaces_json"])
            except Exception:
                pass

        result.append({
            "token_id": row["token_id"],
            "target_agent_id": row.get("target_agent_id"),
            "name": row.get("name"),
            "scopes": scopes,
            "allowed_spaces": allowed_spaces,
            "expires_at": row.get("expires_at"),
            "revoked_at": row.get("revoked_at"),
            "last_used_at": row.get("last_used_at"),
            "created_at": row.get("created_at"),
            "is_active": row.get("revoked_at") is None,
        })

    return result


def require_agent_scopes(agent: AuthenticatedAgent, required: list[str]) -> None:
    """Check that an authenticated agent has the required scopes.

    Args:
        agent: The authenticated agent
        required: List of required scope strings

    Raises:
        PermissionError: If any required scope is missing
    """
    missing = [s for s in required if s not in agent.scopes]
    if missing:
        raise PermissionError(f"Missing required scopes: {missing}")


def check_agent_space_access(agent: AuthenticatedAgent, space_id: str) -> bool:
    """Check if an authenticated agent can access a specific space.

    Args:
        agent: The authenticated agent
        space_id: The space ID to check

    Returns:
        True if access is allowed, False otherwise
    """
    if agent.allowed_spaces is None:
        return True  # No restriction = all spaces allowed
    return space_id in agent.allowed_spaces
