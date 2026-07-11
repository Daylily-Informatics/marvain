from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from agent_hub.rds_data import RdsData


class AuthStateError(RuntimeError):
    """Raised when persisted authentication state is malformed."""


def _auth_text(value: Any, *, field_name: str, state_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuthStateError(f"Malformed {state_name}: {field_name} must be a non-empty string")
    return value


def _required_auth_text(row: dict[str, Any], field_name: str, *, state_name: str) -> str:
    return _auth_text(row.get(field_name), field_name=field_name, state_name=state_name)


def _auth_string_list(value: Any, *, field_name: str, state_name: str) -> list[str]:
    if not isinstance(value, list):
        raise AuthStateError(f"Malformed {state_name}: {field_name} must be a JSON array")

    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise AuthStateError(f"Malformed {state_name}: {field_name} entries must be non-empty strings")
        if item == "*":
            raise AuthStateError(f"Malformed {state_name}: {field_name} must contain explicit values")
        if item in seen:
            raise AuthStateError(f"Malformed {state_name}: {field_name} entries must be unique")
        seen.add(item)
        result.append(item)
    return result


def _parse_auth_string_list(value: Any, *, field_name: str, state_name: str) -> list[str]:
    if not isinstance(value, str) or not value:
        raise AuthStateError(f"Malformed {state_name}: {field_name} must contain JSON")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AuthStateError(f"Malformed {state_name}: {field_name} contains invalid JSON") from exc
    return _auth_string_list(parsed, field_name=field_name, state_name=state_name)


def _parse_auth_object(value: Any, *, field_name: str, state_name: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise AuthStateError(f"Malformed {state_name}: {field_name} must contain JSON")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AuthStateError(f"Malformed {state_name}: {field_name} contains invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise AuthStateError(f"Malformed {state_name}: {field_name} must be a JSON object")
    return parsed


def _input_text(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _input_string_list(value: Any, *, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be an explicit list")
    try:
        return _auth_string_list(value, field_name=field_name, state_name="token input")
    except AuthStateError as exc:
        raise ValueError(str(exc).replace("Malformed token input: ", "")) from exc


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
    capabilities: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthenticatedUser:
    """Represents an authenticated user."""

    user_id: str
    cognito_sub: str
    email: str | None


def authenticate_user_access_token(db: RdsData, access_token: str) -> AuthenticatedUser:
    """Authenticate a human user via a Cognito access token.

    Uses the shared daylily-auth-cognito runtime verifier boundary, ensures a
    users row exists, then returns the AuthenticatedUser.
    """

    if not access_token:
        raise PermissionError("Missing access token")

    try:
        claims = _cognito_token_verifier().verify_token(access_token)
    except Exception as e:
        raise PermissionError(f"Invalid access token: {e}")

    if not isinstance(claims, dict):
        raise PermissionError("Cognito verifier returned malformed claims")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or sub != sub.strip():
        raise PermissionError("Cognito token missing sub")
    raw_email = claims.get("email")
    if raw_email is None:
        email = None
    elif not isinstance(raw_email, str) or not raw_email or raw_email != raw_email.strip():
        raise PermissionError("Cognito token contains malformed email")
    else:
        email = raw_email

    user_id = ensure_user_row(db, cognito_sub=sub, email=email)
    return AuthenticatedUser(user_id=user_id, cognito_sub=sub, email=email)


def _cognito_token_verifier():
    from daylily_auth_cognito.runtime.verifier import CognitoTokenVerifier

    from agent_hub.config import load_config

    cfg = load_config()
    region = str(cfg.cognito_region or "us-east-1")
    user_pool_id = str(cfg.cognito_user_pool_id or "").strip()
    app_client_id = str(cfg.cognito_user_pool_client_id or "").strip()
    if not user_pool_id or not app_client_id:
        raise PermissionError("Cognito runtime verifier is not configured")
    return CognitoTokenVerifier(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)


def _cognito_admin_client(*, user_pool_id: str | None = None):
    from daylily_auth_cognito.admin.client import CognitoAdminClient

    from agent_hub.config import load_config

    cfg = load_config()
    return CognitoAdminClient(
        region=str(cfg.cognito_region or "us-east-1"),
        user_pool_id=user_pool_id,
    )


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
    safe_email = email.replace('"', '\\"')
    from daylily_auth_cognito.admin.users import list_users as list_cognito_admin_users

    admin = _cognito_admin_client(user_pool_id=user_pool_id)
    users = list_cognito_admin_users(admin, limit=2, filter_expression=f'email = "{safe_email}"')
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


def list_cognito_users(*, user_pool_id: str, region: str | None = None) -> list[dict[str, Any]]:
    """List Cognito users through the shared daylily-auth-cognito boundary."""
    from daylily_auth_cognito.admin.client import CognitoAdminClient
    from daylily_auth_cognito.admin.users import list_users as list_cognito_admin_users

    from agent_hub.config import load_config

    cfg = load_config()
    admin = CognitoAdminClient(
        region=str(region or cfg.cognito_region or "us-east-1"),
        user_pool_id=user_pool_id,
    )
    return list_cognito_admin_users(admin)


def authenticate_device(db: RdsData, bearer_token: str) -> AuthenticatedDevice | None:
    if not isinstance(bearer_token, str) or not bearer_token or bearer_token != bearer_token.strip():
        return None
    thash = hash_token(bearer_token)
    rows = db.query(
        """
        SELECT device_id::TEXT as device_id,
               agent_id::TEXT as agent_id,
               scopes::TEXT as scopes_json,
               capabilities::TEXT as capabilities_json
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
    state_name = "device auth state"
    scopes = _parse_auth_string_list(row.get("scopes_json"), field_name="scopes", state_name=state_name)
    capabilities = _parse_auth_object(
        row.get("capabilities_json"),
        field_name="capabilities",
        state_name=state_name,
    )
    return AuthenticatedDevice(
        device_id=_required_auth_text(row, "device_id", state_name=state_name),
        agent_id=_required_auth_text(row, "agent_id", state_name=state_name),
        scopes=scopes,
        capabilities=capabilities,
    )


def require_scopes(device: AuthenticatedDevice, required: list[str]) -> None:
    granted = _auth_string_list(device.scopes, field_name="scopes", state_name="authenticated device")
    required_scopes = _input_string_list(required, field_name="required")
    missing = [scope for scope in required_scopes if scope not in granted]
    if missing:
        raise PermissionError(f"Missing required scopes: {missing}")


def has_scope(device: AuthenticatedDevice, scope: str) -> bool:
    """Check if a device has a specific explicitly granted scope."""
    granted = _auth_string_list(device.scopes, field_name="scopes", state_name="authenticated device")
    required_scope = _input_text(scope, field_name="scope")
    return required_scope in granted


def require_scope(device: AuthenticatedDevice, scope: str) -> None:
    """Require that a device has a specific explicitly granted scope."""
    if not has_scope(device, scope):
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail=f"Missing required scope: {scope}")


def ensure_user_row(db: RdsData, *, cognito_sub: str, email: str | None) -> str:
    """Insert or update a user row in the database."""
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
    user_id = rows[0].get("user_id")
    if not isinstance(user_id, str) or not user_id or user_id != user_id.strip():
        raise RuntimeError("Failed to ensure users row: malformed user_id")
    return user_id


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
    target_agent_id: str  # The only agent allowed to use it
    scopes: list[str]
    allowed_spaces: list[str]  # Empty means the token cannot access any space


def generate_agent_token() -> str:
    """Generate a high-entropy agent-to-agent bearer token.

    Uses the same format as device tokens for consistency.
    """
    return secrets.token_urlsafe(32)


def create_agent_token(
    db: RdsData,
    *,
    issuer_agent_id: str,
    target_agent_id: str,
    scopes: list[str],
    allowed_spaces: list[str],
    name: str = "agent-token",
    expires_at: str | None = None,
    created_by_user_id: str | None = None,
) -> tuple[str, str]:
    """Create a new agent token for agent-to-agent authentication.

    Args:
        db: Database connection
        issuer_agent_id: The agent issuing/owning this token
        target_agent_id: The only agent allowed to use the token
        name: Human-readable name for the token
        scopes: List of permission scopes (e.g., ["read_memories", "write_events"])
        allowed_spaces: Explicit space IDs available to the token; an empty list denies all spaces
        expires_at: ISO timestamp when token expires (None = never)
        created_by_user_id: User who created the token (for audit)

    Returns:
        Tuple of (token_id, plaintext_token) - plaintext is only returned once!
    """
    issuer_agent_id = _input_text(issuer_agent_id, field_name="issuer_agent_id")
    target_agent_id = _input_text(target_agent_id, field_name="target_agent_id")
    scopes = _input_string_list(scopes, field_name="scopes")
    allowed_spaces = _input_string_list(allowed_spaces, field_name="allowed_spaces")
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
            :target_agent_id::uuid,
            :name,
            :token_hash,
            :scopes::jsonb,
            :allowed_spaces::jsonb,
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
            "scopes": json.dumps(scopes),
            "allowed_spaces": json.dumps(allowed_spaces),
            "expires_at": expires_at,
            "created_by_user_id": created_by_user_id,
        },
    )

    if not rows:
        raise RuntimeError("Failed to create agent token")

    token_id = _required_auth_text(rows[0], "token_id", state_name="created agent token")
    return token_id, token


def authenticate_agent_token(
    db: RdsData,
    bearer_token: str,
    *,
    target_agent_id: str,
) -> AuthenticatedAgent | None:
    """Authenticate an agent-to-agent bearer token.

    Args:
        db: Database connection
        bearer_token: The plaintext bearer token
        target_agent_id: Authenticated identity of the agent presenting the token

    Returns:
        AuthenticatedAgent if valid, None if invalid/expired/revoked
    """
    target_agent_id = _input_text(target_agent_id, field_name="target_agent_id")
    if not isinstance(bearer_token, str) or not bearer_token or bearer_token != bearer_token.strip():
        return None
    token_hash_val = hash_token(bearer_token)

    rows = db.query(
        """
        SELECT
            token_id::TEXT as token_id,
            issuer_agent_id::TEXT as issuer_agent_id,
            target_agent_id::TEXT as target_agent_id,
            scopes::TEXT as scopes_json,
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
    state_name = "agent token auth state"
    token_id = _required_auth_text(row, "token_id", state_name=state_name)
    issuer_agent_id = _required_auth_text(row, "issuer_agent_id", state_name=state_name)
    persisted_target_agent_id = _required_auth_text(row, "target_agent_id", state_name=state_name)
    scopes = _parse_auth_string_list(row.get("scopes_json"), field_name="scopes", state_name=state_name)
    allowed_spaces = _parse_auth_string_list(
        row.get("allowed_spaces_json"),
        field_name="allowed_spaces",
        state_name=state_name,
    )

    if persisted_target_agent_id != target_agent_id:
        return None

    db.execute(
        "UPDATE agent_tokens SET last_used_at = NOW() WHERE token_id = :token_id::uuid",
        {"token_id": token_id},
    )

    return AuthenticatedAgent(
        token_id=token_id,
        issuer_agent_id=issuer_agent_id,
        target_agent_id=persisted_target_agent_id,
        scopes=scopes,
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
    issuer_agent_id = _input_text(issuer_agent_id, field_name="issuer_agent_id")
    rows = db.query(
        """
        SELECT
            token_id::TEXT as token_id,
            target_agent_id::TEXT as target_agent_id,
            name,
            scopes::TEXT as scopes_json,
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
        state_name = "agent token metadata"
        scopes = _parse_auth_string_list(row.get("scopes_json"), field_name="scopes", state_name=state_name)
        allowed_spaces = _parse_auth_string_list(
            row.get("allowed_spaces_json"),
            field_name="allowed_spaces",
            state_name=state_name,
        )

        result.append(
            {
                "token_id": _required_auth_text(row, "token_id", state_name=state_name),
                "target_agent_id": _required_auth_text(row, "target_agent_id", state_name=state_name),
                "name": row.get("name"),
                "scopes": scopes,
                "allowed_spaces": allowed_spaces,
                "expires_at": row.get("expires_at"),
                "revoked_at": row.get("revoked_at"),
                "last_used_at": row.get("last_used_at"),
                "created_at": row.get("created_at"),
                "is_active": row.get("revoked_at") is None,
            }
        )

    return result


def require_agent_scopes(agent: AuthenticatedAgent, required: list[str]) -> None:
    """Check that an authenticated agent has the required scopes.

    Args:
        agent: The authenticated agent
        required: List of required scope strings

    Raises:
        PermissionError: If any required scope is missing
    """
    granted = _auth_string_list(agent.scopes, field_name="scopes", state_name="authenticated agent")
    required_scopes = _input_string_list(required, field_name="required")
    missing = [scope for scope in required_scopes if scope not in granted]
    if missing:
        raise PermissionError(f"Missing required scopes: {missing}")


def check_agent_target_access(agent: AuthenticatedAgent, target_agent_id: str) -> bool:
    """Return whether a token is bound to the agent presenting it."""

    persisted_target = _auth_text(
        agent.target_agent_id,
        field_name="target_agent_id",
        state_name="authenticated agent",
    )
    requested_target = _input_text(target_agent_id, field_name="target_agent_id")
    return persisted_target == requested_target


def check_agent_space_access(agent: AuthenticatedAgent, space_id: str) -> bool:
    """Check if an authenticated agent can access a specific space.

    Args:
        agent: The authenticated agent
        space_id: The space ID to check

    Returns:
        True if access is allowed, False otherwise
    """
    allowed_spaces = _auth_string_list(
        agent.allowed_spaces,
        field_name="allowed_spaces",
        state_name="authenticated agent",
    )
    requested_space = _input_text(space_id, field_name="space_id")
    return requested_space in allowed_spaces
