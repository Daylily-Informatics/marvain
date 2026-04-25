"""API-only FastAPI application for Lambda deployment.

This module contains ONLY the programmatic API routes (health, bootstrap, agents,
spaces, devices, memberships, LiveKit tokens). GUI routes are in app.py which
extends this for local development.

Architecture:
- api_app.py (this file): API routes only -> deployed to Lambda
- app.py: API + GUI routes -> local development only
- lambda_handler.py: imports from api_app.py
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from dataclasses import asdict
from typing import Any, Optional

import boto3
from agent_hub.audit import append_audit_entry
from agent_hub.auth import (
    AuthenticatedAgent,
    AuthenticatedDevice,
    AuthenticatedUser,
    authenticate_agent_token,
    authenticate_device,
    authenticate_user_access_token,
    create_agent_token,
    ensure_user_row,
    generate_device_token,
    hash_token,
    list_agent_tokens,
    lookup_cognito_user_by_email,
    require_scope,
    revoke_agent_token,
)
from agent_hub.broadcast import broadcast_event
from agent_hub.config import load_config
from agent_hub.integrations import (
    IntegrationAccountCreate,
    IntegrationAccountUpdate,
    IntegrationQueueMessage,
    create_integration_account,
    enqueue_integration_event,
    get_integration_account,
    get_integration_message,
    insert_integration_message,
    link_integration_message_event,
    list_integration_accounts,
    normalize_github_webhook,
    normalize_slack_webhook,
    normalize_twilio_webhook,
    parse_twilio_form_body,
    update_integration_account,
    verify_github_request,
    verify_slack_request,
    verify_twilio_request,
)
from agent_hub.integrations.models import _UNSET
from agent_hub.livekit_tokens import mint_livekit_join_token
from agent_hub.memberships import (
    check_agent_permission,
    claim_first_owner,
    grant_membership,
    list_agents_for_user,
    list_members_for_agent,
    revoke_membership,
    update_membership,
)
from agent_hub.metrics import emit_count, emit_ms
from agent_hub.openai_http import call_embeddings
from agent_hub.policy import is_agent_disabled, is_privacy_mode
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.secrets import get_secret_json
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import PlainTextResponse

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
# Avoid leaking AWS response payloads (can include secrets) in local logs.
for _name in ("botocore", "urllib3", "httpcore", "httpx"):
    logging.getLogger(_name).setLevel(logging.WARNING)

api_app = FastAPI(title="AgentHub API")

# Load config
_cfg = load_config()


def _get_session_secret() -> str:
    """Get session secret key, loading from Secrets Manager if needed."""
    if _cfg.session_secret_key:
        return _cfg.session_secret_key
    if _cfg.session_secret_arn:
        try:
            data = get_secret_json(_cfg.session_secret_arn)
            key = data.get("session_secret_key")
            if key:
                return str(key)
        except Exception:
            logger.warning("Failed to load session secret from Secrets Manager")
    logger.warning("SESSION_SECRET_KEY not set - using random key")
    return secrets.token_urlsafe(32)


# Add SessionMiddleware (needed for API routes that use sessions)
_session_secret = _get_session_secret()
# Use SameSite=none for OAuth flows (Cognito redirect requires cross-site cookie)
# This requires https_only=True, which is fine since we default to HTTPS
_is_https = os.getenv("HTTPS_ENABLED", "true").lower() in ("true", "1", "yes")
_is_local = os.getenv("ENVIRONMENT", "").lower() in ("local", "dev", "test")
api_app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    session_cookie="marvain_session",
    max_age=3600 * 8,
    same_site="none" if _is_https else "lax",
    https_only=_is_https or not _is_local,
)

# Lazy-load clients
_db: RdsData | None = None
_sqs: Any = None
_s3: Any = None
_recognition_queue_url: str | None = os.getenv("RECOGNITION_QUEUE_URL")


def _get_db() -> RdsData:
    global _db
    if _db is None:
        _db = RdsData(
            RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name)
        )
    return _db


def _get_sqs() -> Any:
    global _sqs
    if _sqs is None:
        _sqs = boto3.client("sqs")
    return _sqs


def _get_s3() -> Any:
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


def _admin_key() -> str:
    if not _cfg.admin_secret_arn:
        raise RuntimeError("ADMIN_SECRET_ARN not set")
    data = get_secret_json(_cfg.admin_secret_arn)
    k = data.get("admin_api_key")
    if not k:
        raise RuntimeError("Admin API key not present in secret")
    return str(k)


def require_admin(x_admin_key: str = Header(default="", alias="X-Admin-Key")) -> None:
    if not x_admin_key or x_admin_key != _admin_key():
        raise HTTPException(status_code=401, detail="Invalid admin key")


def get_device(request: Request) -> AuthenticatedDevice:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    dev = authenticate_device(_get_db(), token)
    if not dev:
        raise HTTPException(status_code=401, detail="Invalid device token")
    return dev


def get_user(request: Request) -> AuthenticatedUser:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    try:
        return authenticate_user_access_token(_get_db(), token)
    except PermissionError:
        raise HTTPException(status_code=401, detail="Invalid access token")


# Expose shared state for gui routes (app.py) to use
def get_config():
    return _cfg


def _require_agent_space(agent_id: str, space_id: str) -> None:
    rows = _get_db().query(
        """
        SELECT 1
        FROM spaces
        WHERE agent_id = :agent_id::uuid
          AND space_id = :space_id::uuid
        LIMIT 1
        """,
        {"agent_id": agent_id, "space_id": space_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Space not found")


VALID_INTEGRATION_PROVIDERS = {"slack", "gmail", "github", "linear", "twilio"}


def _validate_integration_provider(provider: str) -> str:
    provider_n = str(provider or "").strip().lower()
    if provider_n not in VALID_INTEGRATION_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid integration provider")
    return provider_n


def _integration_account_dict(account: Any) -> dict[str, Any]:
    return asdict(account)


def _integration_message_dict(message: Any) -> dict[str, Any]:
    return asdict(message)


def _require_agent_integration_account(agent_id: str, integration_account_id: str) -> Any:
    account = get_integration_account(_get_db(), integration_account_id=integration_account_id)
    if account is None or account.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Integration account not found")
    return account


def _require_provider_integration_account(agent_id: str, integration_account_id: str, provider: str) -> Any:
    account = _require_agent_integration_account(agent_id, integration_account_id)
    if account.provider != provider:
        raise HTTPException(status_code=400, detail="Integration account provider mismatch")
    return account


def _require_integration_account_secret_data(integration_account: Any) -> dict[str, Any]:
    secret_arn = str(integration_account.credentials_secret_arn or "").strip()
    if not secret_arn:
        raise HTTPException(status_code=500, detail="Integration account secret not configured")
    data = get_secret_json(secret_arn)
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="Integration account secret invalid")
    return data


def _require_webhook_account(integration_account_id: str, provider: str) -> Any:
    account = get_integration_account(_get_db(), integration_account_id=integration_account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Integration account not found")
    if account.provider != provider:
        raise HTTPException(status_code=404, detail="Integration account not found")
    if not account.default_space_id:
        raise HTTPException(status_code=400, detail="Integration account missing default space")
    return account


# -----------------------------
# Pydantic Models
# -----------------------------


class BootstrapIn(BaseModel):
    agent_name: str = Field(default="Forge")
    default_space_name: str = Field(default="home")


class BootstrapOut(BaseModel):
    agent_id: str
    space_id: str
    device_id: str
    device_token: str


class RegisterDeviceIn(BaseModel):
    agent_id: str
    name: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    location_label: Optional[str] = Field(default=None, description="Human-readable location label")
    location_coords: Optional[dict[str, Any]] = Field(
        default=None, description="Optional geographic coordinates: {lat, lng}"
    )


class RegisterDeviceOut(BaseModel):
    device_id: str
    device_token: str


class RotateDeviceTokenOut(BaseModel):
    device_id: str
    device_token: str


class DeviceLocationUpdateIn(BaseModel):
    """Request body for updating device location."""

    location_label: Optional[str] = Field(default=None, description="Human-readable location label")
    location_coords: Optional[dict[str, Any]] = Field(
        default=None, description="Optional geographic coordinates: {lat, lng}"
    )


class SetPrivacyIn(BaseModel):
    privacy_mode: bool


class IngestEventIn(BaseModel):
    space_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    person_id: Optional[str] = None


class IngestEventOut(BaseModel):
    event_id: str
    queued: bool


class MeOut(BaseModel):
    user_id: str
    email: str | None = None


class CreateAgentIn(BaseModel):
    name: str
    relationship_label: str | None = None


class UpdateAgentIn(BaseModel):
    name: str | None = None
    disabled: bool | None = None


class AgentOut(BaseModel):
    agent_id: str
    name: str
    role: str
    relationship_label: str | None = None
    disabled: bool


class AgentMemberOut(BaseModel):
    user_id: str
    cognito_sub: str | None = None
    email: str | None = None
    role: str
    relationship_label: str | None = None


class GrantMemberIn(BaseModel):
    email: str
    role: str
    relationship_label: str | None = None


class UpdateMemberIn(BaseModel):
    role: str
    relationship_label: str | None = None


class LiveKitTokenIn(BaseModel):
    space_id: str
    room_mode: str | None = Field(
        default=None,
        description="Optional room mode override: 'ephemeral' (default) or 'stable'. If omitted, uses spaces.livekit_room_mode.",
    )


class LiveKitDeviceTokenIn(BaseModel):
    space_id: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    room_mode: str | None = Field(default="stable", description="Only 'stable' is supported for device tokens.")


class LiveKitTokenOut(BaseModel):
    url: str
    token: str
    room: str
    identity: str


class PresignIn(BaseModel):
    filename: str
    content_type: str = Field(default="application/octet-stream")
    purpose: str | None = Field(default="general", description="general|recognition")


class IntegrationAccountCreateIn(BaseModel):
    provider: str
    display_name: str
    credentials_secret_arn: str
    external_account_id: str | None = None
    default_space_id: str | None = None
    scopes: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="active")


class IntegrationAccountUpdateIn(BaseModel):
    display_name: str | None = None
    credentials_secret_arn: str | None = None
    external_account_id: str | None = None
    default_space_id: str | None = None
    scopes: list[str] | None = None
    config: dict[str, Any] | None = None
    status: str | None = None


class IntegrationMessageQueryParams(BaseModel):
    provider: str | None = None
    status: str | None = None
    external_thread_id: str | None = None
    limit: int = 50


# -----------------------------
# Helper Functions
# -----------------------------


def _require_agent_role(*, user: AuthenticatedUser, agent_id: str, required_role: str) -> None:
    if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user.user_id, required_role=required_role):
        raise HTTPException(status_code=403, detail="Forbidden")


def _require_livekit_config() -> tuple[str, str, str]:
    url = str(_cfg.livekit_url or "").strip()
    secret_arn = str(_cfg.livekit_secret_arn or "").strip()
    if not url:
        raise HTTPException(status_code=500, detail="LIVEKIT_URL not configured")
    if not secret_arn:
        raise HTTPException(status_code=500, detail="LIVEKIT_SECRET_ARN not configured")
    data = get_secret_json(secret_arn)
    api_key = str(data.get("api_key") or "").strip()
    api_secret = str(data.get("api_secret") or "").strip()
    if not api_key or not api_secret:
        raise HTTPException(status_code=500, detail="LiveKit secret missing api_key/api_secret")
    return url, api_key, api_secret


def _space_agent_id(*, space_id: str) -> str | None:
    try:
        rows = _get_db().query(
            "SELECT agent_id::text AS agent_id FROM spaces WHERE space_id = CAST(:space_id AS uuid)",
            params={"space_id": str(space_id)},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to look up space: {e}")
    if not rows:
        return None
    v = rows[0].get("agent_id")
    return str(v) if v else None


def _space_livekit_room_mode(*, space_id: str) -> str:
    """Return the LiveKit room mode for a space."""
    try:
        rows = _get_db().query(
            "SELECT livekit_room_mode FROM spaces WHERE space_id = CAST(:space_id AS uuid)",
            params={"space_id": str(space_id)},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to look up space room mode: {e}")
    if not rows:
        raise HTTPException(status_code=404, detail="Space not found")
    v = str(rows[0].get("livekit_room_mode") or "").strip().lower()
    if v not in {"ephemeral", "stable"}:
        raise HTTPException(status_code=500, detail=f"Invalid livekit_room_mode for space: {v}")
    return v


def _device_is_admin(device: AuthenticatedDevice) -> bool:
    kind = str((device.capabilities or {}).get("kind") or "").strip().lower()
    # Local agent workers are trusted orchestrators and must access any space
    # selected in LiveKit sessions, even when their bootstrap token is anchored
    # to a different agent.
    return kind in {"admin", "worker"}


def _resolve_space_agent_for_device(
    *,
    device: AuthenticatedDevice,
    space_id: str,
    not_found_detail: str = "Space not found",
    mismatch_status: int = 403,
    mismatch_detail: str = "Forbidden",
) -> str:
    """Resolve a space's owning agent and enforce device access rules."""
    agent_id = _space_agent_id(space_id=space_id)
    if not agent_id:
        raise HTTPException(status_code=404, detail=not_found_detail)
    if agent_id != str(device.agent_id) and not _device_is_admin(device):
        raise HTTPException(status_code=mismatch_status, detail=mismatch_detail)
    return agent_id


async def _mint_livekit_token_for_user(
    *, user: AuthenticatedUser, space_id: str, room_mode: str | None = None
) -> LiveKitTokenOut:
    """Mint a LiveKit token with a unique room name per session.

    Architecture:
    - LiveKit "room" = ephemeral media session (unique per join)
    - Marvain "space" = persistent conversation context (stored in Hub database)
    - One space can have many sequential rooms over time

    Room names are unique per session: "{space_id}:{session_id}". This guarantees
    every join creates a NEW room, triggering reliable agent dispatch. The space_id
    is passed to the agent via metadata so it can persist transcripts correctly.

    Room cleanup: LiveKit Cloud automatically garbage collects empty rooms shortly
    after all participants leave. We don't need to manually delete rooms because
    each join uses a unique room name, avoiding the eventual consistency issues
    that plagued the previous room-deletion approach.
    """
    agent_id = _space_agent_id(space_id=space_id)
    if not agent_id:
        raise HTTPException(status_code=404, detail="Space not found")
    if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user.user_id, required_role="member"):
        raise HTTPException(status_code=403, detail="Forbidden")
    url, api_key, api_secret = _require_livekit_config()

    resolved_mode = str(room_mode or _space_livekit_room_mode(space_id=space_id) or "ephemeral").strip().lower()
    if resolved_mode not in {"ephemeral", "stable"}:
        resolved_mode = "ephemeral"

    # Always generate a session id for metadata/debugging, even in stable mode.
    room_session_id = uuid.uuid4().hex[:12]
    if resolved_mode == "stable":
        room = str(space_id)
    else:
        # Ephemeral mode: guarantees a new room per join for reliable dispatch.
        room = f"{space_id}:{room_session_id}"

    identity = f"user:{user.user_id}"
    token = mint_livekit_join_token(
        api_key=api_key,
        api_secret=api_secret,
        identity=identity,
        room=room,
        name=(user.email or user.user_id),
        ttl_seconds=3600,
        agent_metadata={
            "space_id": str(space_id),
            "agent_id": str(agent_id),
            "room_session_id": room_session_id,
        },
    )
    return LiveKitTokenOut(url=url, token=token, room=room, identity=identity)


# -----------------------------
# API Routes
# -----------------------------


@api_app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "stage": _cfg.stage}


@api_app.get("/v1/tools")
def list_tools(device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    """Return all registered tools with name, description, and required scopes."""
    from agent_hub.tools.registry import get_registry

    registry = get_registry()
    return {"tools": [t.to_dict() for t in registry.list_tools()]}


@api_app.get("/v1/me", response_model=MeOut)
def me(user: AuthenticatedUser = Depends(get_user)) -> MeOut:
    return MeOut(user_id=user.user_id, email=user.email)


@api_app.get("/v1/agents", response_model=dict[str, list[AgentOut]])
def agents(user: AuthenticatedUser = Depends(get_user)) -> dict[str, list[AgentOut]]:
    memberships = list_agents_for_user(_get_db(), user_id=user.user_id)
    return {
        "agents": [
            AgentOut(
                agent_id=m.agent_id,
                name=m.name,
                role=m.role,
                relationship_label=m.relationship_label,
                disabled=m.disabled,
            )
            for m in memberships
        ]
    }


@api_app.post("/v1/agents", response_model=AgentOut)
def create_agent(body: CreateAgentIn, user: AuthenticatedUser = Depends(get_user)) -> AgentOut:
    """Create a new agent and make the creating user the owner."""
    agent_id = str(uuid.uuid4())
    tx = _get_db().begin()
    try:
        _get_db().execute(
            "INSERT INTO agents(agent_id, name, disabled) VALUES (:agent_id::uuid, :name, false)",
            {"agent_id": agent_id, "name": body.name},
            transaction_id=tx,
        )
        _get_db().execute(
            """
            INSERT INTO agent_memberships (agent_id, user_id, role, relationship_label)
            VALUES (:agent_id::uuid, :user_id::uuid, 'owner', :relationship_label)
            """,
            {"agent_id": agent_id, "user_id": user.user_id, "relationship_label": body.relationship_label},
            transaction_id=tx,
        )
        _get_db().commit(tx)
    except Exception:
        _get_db().rollback(tx)
        raise

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="agent_created",
            entry={"user_id": user.user_id, "name": body.name},
        )

    return AgentOut(
        agent_id=agent_id,
        name=body.name,
        role="owner",
        relationship_label=body.relationship_label,
        disabled=False,
    )


@api_app.patch("/v1/agents/{agent_id}", response_model=AgentOut)
def update_agent(agent_id: str, body: UpdateAgentIn, user: AuthenticatedUser = Depends(get_user)) -> AgentOut:
    """Update an agent's name or disabled status. Requires admin role."""
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    updates: list[str] = []
    params: dict[str, Any] = {"agent_id": agent_id}

    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        updates.append("name = :name")
        params["name"] = name

    if body.disabled is not None:
        updates.append("disabled = :disabled")
        params["disabled"] = body.disabled

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    _get_db().execute(
        f"UPDATE agents SET {', '.join(updates)} WHERE agent_id = :agent_id::uuid",
        params,
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="agent_updated",
            entry={"user_id": user.user_id, "name": body.name, "disabled": body.disabled},
        )

    # Fetch current state to return
    rows = _get_db().query(
        """SELECT a.name, a.disabled, am.role, am.relationship_label
           FROM agents a
           JOIN agent_memberships am ON a.agent_id = am.agent_id
           WHERE a.agent_id = :agent_id::uuid AND am.user_id = :user_id::uuid AND am.revoked_at IS NULL""",
        {"agent_id": agent_id, "user_id": user.user_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Agent not found")
    r = rows[0]
    return AgentOut(
        agent_id=agent_id,
        name=r["name"],
        role=r["role"],
        relationship_label=r.get("relationship_label"),
        disabled=r["disabled"],
    )


@api_app.post("/v1/livekit/token", response_model=LiveKitTokenOut)
async def livekit_token(body: LiveKitTokenIn, user: AuthenticatedUser = Depends(get_user)) -> LiveKitTokenOut:
    """Mint a short-lived LiveKit token for a user to join the room for a space."""
    return await _mint_livekit_token_for_user(user=user, space_id=body.space_id, room_mode=body.room_mode)


@api_app.post("/v1/livekit/device-token", response_model=LiveKitTokenOut)
async def livekit_device_token(
    body: LiveKitDeviceTokenIn, device: AuthenticatedDevice = Depends(get_device)
) -> LiveKitTokenOut:
    """Mint a short-lived LiveKit token for a device to join a stable room for a space.

    Intended for always-on Location Nodes that publish/consume AV in LiveKit.
    """
    require_scope(device, "events:write")

    if str(body.room_mode or "stable").strip().lower() != "stable":
        raise HTTPException(status_code=400, detail="Only room_mode='stable' is supported for device tokens")

    agent_id = _resolve_space_agent_for_device(
        device=device,
        space_id=body.space_id,
        not_found_detail="Space not found",
        mismatch_status=404,
        mismatch_detail="Space not found",
    )
    if is_agent_disabled(_get_db(), agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    url, api_key, api_secret = _require_livekit_config()

    room_session_id = uuid.uuid4().hex[:12]
    room = str(body.space_id)
    identity = f"device:{device.device_id}"

    caps = body.capabilities or {}
    publish_audio = bool(caps.get("publish_audio", True))
    publish_video = bool(caps.get("publish_video", True))
    subscribe_audio = bool(caps.get("subscribe_audio", True))

    # LiveKit grants do not separate audio/video publish; treat any publish as can_publish.
    token = mint_livekit_join_token(
        api_key=api_key,
        api_secret=api_secret,
        identity=identity,
        room=room,
        name=(caps.get("name") or device.device_id),
        ttl_seconds=3600,
        can_publish=bool(publish_audio or publish_video),
        can_subscribe=bool(subscribe_audio),
        agent_metadata={
            "space_id": str(body.space_id),
            "agent_id": str(agent_id),
            "room_session_id": room_session_id,
        },
    )
    return LiveKitTokenOut(url=url, token=token, room=room, identity=identity)


@api_app.post("/v1/agents/{agent_id}/claim_owner")
def claim_owner(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    try:
        claim_first_owner(_get_db(), agent_id=agent_id, user_id=user.user_id)
    except PermissionError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="owner_claimed",
            entry={"user_id": user.user_id},
        )
    return {"agent_id": agent_id, "user_id": user.user_id, "role": "owner"}


@api_app.get("/v1/agents/{agent_id}/memberships", response_model=dict[str, list[AgentMemberOut]])
def list_members(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, list[AgentMemberOut]]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="member")
    members = list_members_for_agent(_get_db(), agent_id=agent_id, include_revoked=False)
    return {
        "memberships": [
            AgentMemberOut(user_id=m.user_id, email=m.email, role=m.role, relationship_label=m.relationship_label)
            for m in members
        ]
    }


@api_app.post("/v1/agents/{agent_id}/memberships", response_model=AgentMemberOut)
def add_member(agent_id: str, body: GrantMemberIn, user: AuthenticatedUser = Depends(get_user)) -> AgentMemberOut:
    """Add (or update) a member to an agent."""
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    if not _cfg.cognito_user_pool_id:
        raise HTTPException(status_code=500, detail="COGNITO_USER_POOL_ID not configured")
    try:
        cognito_sub, resolved_email = lookup_cognito_user_by_email(
            user_pool_id=_cfg.cognito_user_pool_id,
            email=body.email,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    user_id = ensure_user_row(_get_db(), cognito_sub=cognito_sub, email=(resolved_email or body.email))
    try:
        grant_membership(
            _get_db(), agent_id=agent_id, user_id=user_id, role=body.role, relationship_label=body.relationship_label
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_granted",
            entry={
                "by_user_id": user.user_id,
                "user_id": user_id,
                "cognito_sub": cognito_sub,
                "email": (resolved_email or body.email),
                "role": body.role,
                "relationship_label": body.relationship_label,
            },
        )
    return AgentMemberOut(
        user_id=user_id,
        cognito_sub=cognito_sub,
        email=(resolved_email or body.email),
        role=body.role,
        relationship_label=body.relationship_label,
    )


@api_app.patch("/v1/agents/{agent_id}/memberships/{member_user_id}")
def patch_member(
    agent_id: str, member_user_id: str, body: UpdateMemberIn, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    try:
        update_membership(
            _get_db(),
            agent_id=agent_id,
            user_id=member_user_id,
            role=body.role,
            relationship_label=body.relationship_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_updated",
            entry={"by_user_id": user.user_id, "user_id": member_user_id, "role": body.role},
        )
    return {"ok": True}


@api_app.delete("/v1/agents/{agent_id}/memberships/{member_user_id}")
def delete_member(agent_id: str, member_user_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    revoke_membership(_get_db(), agent_id=agent_id, user_id=member_user_id)
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_revoked",
            entry={"by_user_id": user.user_id, "user_id": member_user_id},
        )
    return {"ok": True}


class AutoApprovePolicyIn(BaseModel):
    name: str = Field(..., description="Human-readable policy name")
    enabled: bool = Field(default=True)
    priority: int = Field(default=100)
    action_kind: str = Field(default="*")
    required_scopes: list[str] = Field(default_factory=list)
    time_window: dict[str, Any] = Field(default_factory=dict)


def _as_json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return []
    return []


def _as_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


@api_app.get("/v1/agents/{agent_id}/auto-approve-policies", response_model=list[dict[str, Any]])
def list_auto_approve_policies(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> list[dict[str, Any]]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    rows = _get_db().query(
        """
        SELECT policy_id::TEXT as policy_id, name, enabled, priority, action_kind,
               required_scopes::TEXT as required_scopes, time_window::TEXT as time_window,
               created_by::TEXT as created_by, created_at::TEXT as created_at, updated_at::TEXT as updated_at
        FROM action_auto_approve_policies
        WHERE agent_id = :agent_id::uuid
          AND revoked_at IS NULL
        ORDER BY priority ASC, created_at DESC
        """,
        {"agent_id": agent_id},
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "policy_id": row.get("policy_id"),
                "name": row.get("name"),
                "enabled": bool(row.get("enabled")),
                "priority": int(row.get("priority") or 100),
                "action_kind": row.get("action_kind") or "*",
                "required_scopes": _as_json_list(row.get("required_scopes")),
                "time_window": _as_json_dict(row.get("time_window")),
                "created_by": row.get("created_by"),
                "created_at": row.get("created_at"),
                "updated_at": row.get("updated_at"),
            }
        )
    return out


@api_app.post("/v1/agents/{agent_id}/auto-approve-policies")
def create_auto_approve_policy(
    agent_id: str, body: AutoApprovePolicyIn, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    policy_id = str(uuid.uuid4())
    _get_db().execute(
        """
        INSERT INTO action_auto_approve_policies(
          policy_id, agent_id, name, enabled, priority, action_kind, required_scopes, time_window, created_by
        ) VALUES(
          :policy_id::uuid, :agent_id::uuid, :name, :enabled, :priority, :action_kind,
          :required_scopes::jsonb, :time_window::jsonb, :created_by::uuid
        )
        """,
        {
            "policy_id": policy_id,
            "agent_id": agent_id,
            "name": body.name.strip(),
            "enabled": bool(body.enabled),
            "priority": int(body.priority),
            "action_kind": str(body.action_kind or "*").strip(),
            "required_scopes": json.dumps([str(s) for s in (body.required_scopes or [])]),
            "time_window": json.dumps(body.time_window or {}),
            "created_by": str(user.user_id),
        },
    )
    return {"ok": True, "policy_id": policy_id}


@api_app.put("/v1/agents/{agent_id}/auto-approve-policies/{policy_id}")
def update_auto_approve_policy(
    agent_id: str, policy_id: str, body: AutoApprovePolicyIn, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    _get_db().execute(
        """
        UPDATE action_auto_approve_policies
        SET name = :name,
            enabled = :enabled,
            priority = :priority,
            action_kind = :action_kind,
            required_scopes = :required_scopes::jsonb,
            time_window = :time_window::jsonb,
            updated_at = now()
        WHERE policy_id = :policy_id::uuid
          AND agent_id = :agent_id::uuid
          AND revoked_at IS NULL
        """,
        {
            "policy_id": policy_id,
            "agent_id": agent_id,
            "name": body.name.strip(),
            "enabled": bool(body.enabled),
            "priority": int(body.priority),
            "action_kind": str(body.action_kind or "*").strip(),
            "required_scopes": json.dumps([str(s) for s in (body.required_scopes or [])]),
            "time_window": json.dumps(body.time_window or {}),
        },
    )
    return {"ok": True}


@api_app.delete("/v1/agents/{agent_id}/auto-approve-policies/{policy_id}")
def delete_auto_approve_policy(
    agent_id: str, policy_id: str, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    _get_db().execute(
        """
        UPDATE action_auto_approve_policies
        SET revoked_at = now(), updated_at = now()
        WHERE policy_id = :policy_id::uuid
          AND agent_id = :agent_id::uuid
          AND revoked_at IS NULL
        """,
        {"policy_id": policy_id, "agent_id": agent_id},
    )
    return {"ok": True}


@api_app.post("/v1/devices/register", response_model=RegisterDeviceOut)
def register_device(body: RegisterDeviceIn, user: AuthenticatedUser = Depends(get_user)) -> RegisterDeviceOut:
    _require_agent_role(user=user, agent_id=body.agent_id, required_role="admin")
    if is_agent_disabled(_get_db(), body.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")
    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)
    _get_db().execute(
        """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash,
                               location_label, location_coords, provisioned_at, provisioned_by)
           VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash,
                   :location_label, :location_coords::jsonb, NOW(), :provisioned_by)""",
        {
            "device_id": device_id,
            "agent_id": body.agent_id,
            "name": body.name or "device",
            "scopes": json.dumps(body.scopes),
            "capabilities": json.dumps(body.capabilities),
            "token_hash": token_hash,
            "location_label": body.location_label,
            "location_coords": json.dumps(body.location_coords) if body.location_coords else None,
            "provisioned_by": user.user_id,
        },
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=body.agent_id,
            entry_type="device_registered",
            entry={
                "device_id": device_id,
                "name": body.name,
                "scopes": body.scopes,
                "by_user_id": user.user_id,
                "location_label": body.location_label,
            },
        )
    return RegisterDeviceOut(device_id=device_id, device_token=token)


@api_app.post("/v1/devices/{device_id}/rotate-token", response_model=RotateDeviceTokenOut)
def rotate_device_token(device_id: str, user: AuthenticatedUser = Depends(get_user)) -> RotateDeviceTokenOut:
    """Rotate a device token and return the new token once."""
    rows = _get_db().query(
        """
        SELECT d.device_id::TEXT as device_id, d.agent_id::TEXT as agent_id
        FROM devices d
        JOIN agent_memberships m ON d.agent_id = m.agent_id
        WHERE d.device_id = :device_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.role IN ('admin', 'owner')
          AND m.revoked_at IS NULL
        """,
        {"device_id": device_id, "user_id": user.user_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Device not found or permission denied")

    device = rows[0]
    new_token = generate_device_token()
    token_hash = hash_token(new_token)
    _get_db().execute(
        """
        UPDATE devices
        SET token_hash = :token_hash, revoked_at = NULL
        WHERE device_id = :device_id::uuid
        """,
        {"device_id": device_id, "token_hash": token_hash},
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=device["agent_id"],
            entry_type="device_token_rotated",
            entry={"device_id": device_id, "by_user_id": user.user_id},
        )

    return RotateDeviceTokenOut(device_id=device_id, device_token=new_token)


@api_app.post("/v1/admin/bootstrap", response_model=BootstrapOut, dependencies=[Depends(require_admin)])
def admin_bootstrap(body: BootstrapIn) -> BootstrapOut:
    agent_id = str(uuid.uuid4())
    space_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)
    tx = _get_db().begin()
    try:
        _get_db().execute(
            "INSERT INTO agents(agent_id, name, disabled) VALUES (:agent_id::uuid, :name, false)",
            {"agent_id": agent_id, "name": body.agent_name},
            transaction_id=tx,
        )
        _get_db().execute(
            "INSERT INTO spaces(space_id, agent_id, name, privacy_mode) VALUES (:space_id::uuid, :agent_id::uuid, :name, false)",
            {"space_id": space_id, "agent_id": agent_id, "name": body.default_space_name},
            transaction_id=tx,
        )
        _get_db().execute(
            """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
               VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)""",
            {
                "device_id": device_id,
                "agent_id": agent_id,
                "name": "primary",
                "scopes": json.dumps(
                    [
                        "events:read",
                        "events:write",
                        "memories:read",
                        "memories:write",
                        "artifacts:write",
                        "presence:write",
                    ]
                ),
                "capabilities": json.dumps({"kind": "admin"}),
                "token_hash": token_hash,
            },
            transaction_id=tx,
        )
        _get_db().commit(tx)
    except Exception:
        _get_db().rollback(tx)
        raise
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="bootstrap",
            entry={"space_id": space_id, "device_id": device_id},
        )
    return BootstrapOut(agent_id=agent_id, space_id=space_id, device_id=device_id, device_token=token)


@api_app.post("/v1/admin/devices/register", response_model=RegisterDeviceOut, dependencies=[Depends(require_admin)])
def admin_register_device(body: RegisterDeviceIn) -> RegisterDeviceOut:
    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)
    _get_db().execute(
        """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash,
                               location_label, location_coords)
           VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash,
                   :location_label, :location_coords::jsonb)""",
        {
            "device_id": device_id,
            "agent_id": body.agent_id,
            "name": body.name or "device",
            "scopes": json.dumps(body.scopes),
            "capabilities": json.dumps(body.capabilities),
            "token_hash": token_hash,
            "location_label": body.location_label,
            "location_coords": json.dumps(body.location_coords) if body.location_coords else None,
        },
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=body.agent_id,
            entry_type="device_registered",
            entry={
                "device_id": device_id,
                "name": body.name,
                "scopes": body.scopes,
                "location_label": body.location_label,
            },
        )
    return RegisterDeviceOut(device_id=device_id, device_token=token)


@api_app.patch("/v1/devices/{device_id}/location")
def api_update_device_location(
    device_id: str, body: DeviceLocationUpdateIn, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    """Update a device's location information."""
    db = _get_db()
    rows = db.query(
        """SELECT d.agent_id::TEXT as agent_id
           FROM devices d
           JOIN agent_memberships m ON d.agent_id = m.agent_id
           WHERE d.device_id = :device_id::uuid
             AND m.user_id = :user_id::uuid
             AND m.role IN ('admin', 'owner')
             AND m.revoked_at IS NULL""",
        {"device_id": device_id, "user_id": user.user_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Device not found or permission denied")
    db.execute(
        """UPDATE devices
           SET location_label = :location_label,
               location_coords = :location_coords::jsonb
           WHERE device_id = :device_id::uuid""",
        {
            "device_id": device_id,
            "location_label": body.location_label,
            "location_coords": json.dumps(body.location_coords) if body.location_coords else None,
        },
    )
    return {
        "ok": True,
        "device_id": device_id,
        "location_label": body.location_label,
        "location_coords": body.location_coords,
    }


# -----------------------------------------------------------------------------
# People & Consent v1 (machine-usable parity with GUI)
# -----------------------------------------------------------------------------


class PersonCreateV1In(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    aliases: list[str] = Field(default_factory=list)


class PersonPatchV1In(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    aliases: list[str] | None = None


class PersonV1Out(BaseModel):
    person_id: str
    agent_id: str
    display_name: str
    aliases: list[str] = Field(default_factory=list)
    created_at: str | None = None


def _parse_json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return []
    return []


@api_app.get("/v1/agents/{agent_id}/people", response_model=list[PersonV1Out])
def v1_list_people(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> list[PersonV1Out]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="member")
    rows = _get_db().query(
        """
        SELECT person_id::TEXT as person_id,
               agent_id::TEXT as agent_id,
               display_name,
               aliases::TEXT as aliases_json,
               created_at::TEXT as created_at
        FROM people
        WHERE agent_id = :agent_id::uuid
        ORDER BY created_at DESC
        """,
        {"agent_id": agent_id},
    )
    out: list[PersonV1Out] = []
    for r in rows:
        aliases_raw = _parse_json_list(r.get("aliases_json") or "[]")
        aliases = [str(a).strip() for a in aliases_raw if str(a).strip()]
        out.append(
            PersonV1Out(
                person_id=str(r.get("person_id") or ""),
                agent_id=str(r.get("agent_id") or ""),
                display_name=str(r.get("display_name") or ""),
                aliases=aliases,
                created_at=r.get("created_at"),
            )
        )
    return out


@api_app.post("/v1/agents/{agent_id}/people", response_model=PersonV1Out)
def v1_create_person(agent_id: str, body: PersonCreateV1In, user: AuthenticatedUser = Depends(get_user)) -> PersonV1Out:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    person_id = str(uuid.uuid4())
    display_name = str(body.display_name or "").strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="display_name is required")
    aliases = [str(a).strip() for a in (body.aliases or []) if str(a).strip()]
    _get_db().execute(
        """
        INSERT INTO people(person_id, agent_id, display_name, aliases)
        VALUES(:person_id::uuid, :agent_id::uuid, :display_name, :aliases::jsonb)
        """,
        {"person_id": person_id, "agent_id": agent_id, "display_name": display_name, "aliases": json.dumps(aliases)},
    )
    return PersonV1Out(person_id=person_id, agent_id=agent_id, display_name=display_name, aliases=aliases)


def _get_person_agent_id_for_user(*, person_id: str, user: AuthenticatedUser) -> str:
    rows = _get_db().query(
        """
        SELECT p.agent_id::TEXT as agent_id
        FROM people p
        JOIN agent_memberships m ON p.agent_id = m.agent_id
        WHERE p.person_id = :person_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.revoked_at IS NULL
        LIMIT 1
        """,
        {"person_id": person_id, "user_id": user.user_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Person not found")
    return str(rows[0].get("agent_id") or "").strip()


@api_app.get("/v1/people/{person_id}", response_model=PersonV1Out)
def v1_get_person(person_id: str, user: AuthenticatedUser = Depends(get_user)) -> PersonV1Out:
    agent_id = _get_person_agent_id_for_user(person_id=person_id, user=user)
    rows = _get_db().query(
        """
        SELECT person_id::TEXT as person_id,
               agent_id::TEXT as agent_id,
               display_name,
               aliases::TEXT as aliases_json,
               created_at::TEXT as created_at
        FROM people
        WHERE person_id = :person_id::uuid
          AND agent_id = :agent_id::uuid
        LIMIT 1
        """,
        {"person_id": person_id, "agent_id": agent_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Person not found")
    r = rows[0]
    aliases_raw = _parse_json_list(r.get("aliases_json") or "[]")
    aliases = [str(a).strip() for a in aliases_raw if str(a).strip()]
    return PersonV1Out(
        person_id=str(r.get("person_id") or ""),
        agent_id=str(r.get("agent_id") or ""),
        display_name=str(r.get("display_name") or ""),
        aliases=aliases,
        created_at=r.get("created_at"),
    )


@api_app.patch("/v1/people/{person_id}", response_model=PersonV1Out)
def v1_patch_person(person_id: str, body: PersonPatchV1In, user: AuthenticatedUser = Depends(get_user)) -> PersonV1Out:
    agent_id = _get_person_agent_id_for_user(person_id=person_id, user=user)
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    updates: list[str] = []
    params: dict[str, Any] = {"person_id": person_id, "agent_id": agent_id}

    if body.display_name is not None:
        display_name = str(body.display_name or "").strip()
        if not display_name:
            raise HTTPException(status_code=400, detail="display_name cannot be empty")
        updates.append("display_name = :display_name")
        params["display_name"] = display_name

    if body.aliases is not None:
        aliases = [str(a).strip() for a in (body.aliases or []) if str(a).strip()]
        updates.append("aliases = :aliases::jsonb")
        params["aliases"] = json.dumps(aliases)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    _get_db().execute(
        f"UPDATE people SET {', '.join(updates)} WHERE person_id = :person_id::uuid AND agent_id = :agent_id::uuid",
        params,
    )
    return v1_get_person(person_id=person_id, user=user)


class ConsentGrantV1In(BaseModel):
    type: str = Field(..., description="voice|face|recording|global")
    expires_at: str | None = None


class ConsentUpdateV1In(BaseModel):
    consents: list[ConsentGrantV1In] = Field(default_factory=list)


def _parse_consent_expires_at(value: str | None):
    """Parse consent expiry values.

    For <input type="date"> style values ('YYYY-MM-DD'), treat as inclusive and
    expire end-of-day UTC, not midnight.
    """
    if not value:
        return None
    v = str(value).strip()
    if not v:
        return None
    from datetime import date, datetime, timezone
    from datetime import time as dt_time

    try:
        if len(v) == 10 and v[4] == "-" and v[7] == "-":
            d = date.fromisoformat(v)
            return datetime.combine(d, dt_time(23, 59, 59), tzinfo=timezone.utc)
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class ConsentGrantV1Out(BaseModel):
    consent_id: str
    agent_id: str
    person_id: str
    consent_type: str
    granted_at: str
    expires_at: str | None
    revoked_at: str | None


@api_app.get("/v1/people/{person_id}/consent", response_model=list[ConsentGrantV1Out])
def v1_list_consent(person_id: str, user: AuthenticatedUser = Depends(get_user)) -> list[ConsentGrantV1Out]:
    # Requires membership on the owning agent.
    _ = _get_person_agent_id_for_user(person_id=person_id, user=user)
    rows = _get_db().query(
        """
        SELECT cg.consent_id::TEXT as consent_id,
               cg.agent_id::TEXT as agent_id,
               cg.person_id::TEXT as person_id,
               cg.consent_type,
               cg.granted_at::TEXT as granted_at,
               cg.expires_at::TEXT as expires_at,
               cg.revoked_at::TEXT as revoked_at
        FROM consent_grants cg
        WHERE cg.person_id = :person_id::uuid
        ORDER BY cg.granted_at DESC
        """,
        {"person_id": person_id},
    )
    return [
        ConsentGrantV1Out(
            consent_id=str(r.get("consent_id") or ""),
            agent_id=str(r.get("agent_id") or ""),
            person_id=str(r.get("person_id") or ""),
            consent_type=str(r.get("consent_type") or ""),
            granted_at=str(r.get("granted_at") or ""),
            expires_at=r.get("expires_at"),
            revoked_at=r.get("revoked_at"),
        )
        for r in rows
    ]


@api_app.post("/v1/people/{person_id}/consent")
def v1_update_consent(
    person_id: str, body: ConsentUpdateV1In, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    agent_id = _get_person_agent_id_for_user(person_id=person_id, user=user)
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    valid_types = {"voice", "face", "recording", "global"}
    for c in body.consents or []:
        ctype = str(c.type or "").strip().lower()
        if ctype not in valid_types:
            raise HTTPException(status_code=400, detail=f"Invalid consent type: {ctype!r}")

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    tx = _get_db().begin()
    try:
        # Revoke all active grants and replace with the provided set.
        _get_db().execute(
            "UPDATE consent_grants SET revoked_at = :now::timestamptz WHERE person_id = :person_id::uuid AND revoked_at IS NULL",
            {"person_id": person_id, "now": now},
            transaction_id=tx,
        )

        for c in body.consents or []:
            consent_id = str(uuid.uuid4())
            expires_at = _parse_consent_expires_at(c.expires_at)
            _get_db().execute(
                """
                INSERT INTO consent_grants(consent_id, agent_id, person_id, consent_type, expires_at)
                VALUES(
                  :consent_id::uuid,
                  :agent_id::uuid,
                  :person_id::uuid,
                  :consent_type,
                  CASE WHEN :expires_at IS NULL THEN NULL ELSE :expires_at::timestamptz END
                )
                """,
                {
                    "consent_id": consent_id,
                    "agent_id": agent_id,
                    "person_id": person_id,
                    "consent_type": str(c.type).strip().lower(),
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
                transaction_id=tx,
            )
        _get_db().commit(tx)
    except Exception:
        _get_db().rollback(tx)
        raise

    return {"ok": True, "person_id": person_id}


class LinkPersonAccountV1In(BaseModel):
    email: str | None = None
    user_id: str | None = None


@api_app.post("/v1/people/{person_id}/link-account")
def v1_link_person_account(
    person_id: str, body: LinkPersonAccountV1In, user: AuthenticatedUser = Depends(get_user)
) -> dict[str, Any]:
    """Link a Cognito user account (users.user_id) to a Person for an agent."""
    agent_id = _get_person_agent_id_for_user(person_id=person_id, user=user)
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    link_user_id = str(body.user_id or "").strip()
    email = str(body.email or "").strip()
    if not link_user_id and not email:
        raise HTTPException(status_code=400, detail="email or user_id is required")

    if email:
        if not _cfg.cognito_user_pool_id:
            raise HTTPException(status_code=500, detail="COGNITO_USER_POOL_ID not configured")
        try:
            cognito_sub, resolved_email = lookup_cognito_user_by_email(
                user_pool_id=_cfg.cognito_user_pool_id,
                email=email,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        link_user_id = ensure_user_row(_get_db(), cognito_sub=cognito_sub, email=(resolved_email or email))

    if not link_user_id:
        raise HTTPException(status_code=400, detail="Could not resolve user_id")

    # Ensure the user exists.
    urows = _get_db().query(
        "SELECT 1 FROM users WHERE user_id = :user_id::uuid LIMIT 1",
        {"user_id": link_user_id},
    )
    if not urows:
        raise HTTPException(status_code=404, detail="User not found")

    tx = _get_db().begin()
    try:
        # Enforce uniqueness by deleting any prior mappings for this user or person.
        _get_db().execute(
            """
            DELETE FROM person_accounts
            WHERE agent_id = :agent_id::uuid
              AND (user_id = :user_id::uuid OR person_id = :person_id::uuid)
            """,
            {"agent_id": agent_id, "user_id": link_user_id, "person_id": person_id},
            transaction_id=tx,
        )
        _get_db().execute(
            """
            INSERT INTO person_accounts(person_account_id, agent_id, user_id, person_id)
            VALUES(:person_account_id::uuid, :agent_id::uuid, :user_id::uuid, :person_id::uuid)
            """,
            {
                "person_account_id": str(uuid.uuid4()),
                "agent_id": agent_id,
                "user_id": link_user_id,
                "person_id": person_id,
            },
            transaction_id=tx,
        )
        _get_db().commit(tx)
    except Exception:
        _get_db().rollback(tx)
        raise

    return {"ok": True, "agent_id": agent_id, "person_id": person_id, "user_id": link_user_id}


# -----------------------------------------------------------------------------
# Biometrics (voiceprints/faceprints) and identification
# -----------------------------------------------------------------------------


def _vector_literal(values: list[float], expected_dim: int) -> str:
    if len(values) != expected_dim:
        raise HTTPException(
            status_code=400, detail=f"Invalid embedding dim (expected {expected_dim}, got {len(values)})"
        )
    # Limit precision to keep payloads smaller and stable.
    return "[" + ",".join(f"{float(x):.6f}" for x in values) + "]"


def _require_person_consent(*, agent_id: str, person_id: str, consent_type: str) -> None:
    rows = _get_db().query(
        """
        SELECT 1
        FROM consent_grants
        WHERE agent_id = :agent_id::uuid
          AND person_id = :person_id::uuid
          AND consent_type IN (:consent_type, 'global')
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
        LIMIT 1
        """,
        {"agent_id": agent_id, "person_id": person_id, "consent_type": consent_type},
    )
    if not rows:
        raise HTTPException(status_code=403, detail=f"Missing active consent for {consent_type}")


def _require_device_agent_access(*, device: AuthenticatedDevice, agent_id: str) -> None:
    if str(device.agent_id) == str(agent_id):
        return
    if _device_is_admin(device):
        return
    raise HTTPException(status_code=403, detail="Forbidden")


class VoiceprintCreateIn(BaseModel):
    embedding: list[float] = Field(..., min_length=256, max_length=256)
    model: str = Field(default="resemblyzer")
    metadata: dict[str, Any] = Field(default_factory=dict)


class FaceprintCreateIn(BaseModel):
    embedding: list[float] = Field(..., min_length=512, max_length=512)
    model: str = Field(default="insightface-arcface")
    metadata: dict[str, Any] = Field(default_factory=dict)


@api_app.post("/v1/people/{person_id}/voiceprints")
def v1_create_voiceprint(
    person_id: str, body: VoiceprintCreateIn, device: AuthenticatedDevice = Depends(get_device)
) -> dict[str, Any]:
    require_scope(device, "biometrics:write")
    rows = _get_db().query(
        "SELECT agent_id::TEXT as agent_id FROM people WHERE person_id = :person_id::uuid LIMIT 1",
        {"person_id": person_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Person not found")
    agent_id = str(rows[0].get("agent_id") or "")
    _require_device_agent_access(device=device, agent_id=agent_id)
    _require_person_consent(agent_id=agent_id, person_id=person_id, consent_type="voice")

    voiceprint_id = str(uuid.uuid4())
    _get_db().execute(
        """
        INSERT INTO voiceprints(voiceprint_id, agent_id, person_id, embedding, model, metadata)
        VALUES(
          :voiceprint_id::uuid,
          :agent_id::uuid,
          :person_id::uuid,
          CAST(:embedding AS vector),
          :model,
          :metadata::jsonb
        )
        """,
        {
            "voiceprint_id": voiceprint_id,
            "agent_id": agent_id,
            "person_id": person_id,
            "embedding": _vector_literal(body.embedding, 256),
            "model": str(body.model or "resemblyzer").strip(),
            "metadata": json.dumps(body.metadata or {}),
        },
    )
    return {"ok": True, "voiceprint_id": voiceprint_id}


@api_app.post("/v1/people/{person_id}/faceprints")
def v1_create_faceprint(
    person_id: str, body: FaceprintCreateIn, device: AuthenticatedDevice = Depends(get_device)
) -> dict[str, Any]:
    require_scope(device, "biometrics:write")
    rows = _get_db().query(
        "SELECT agent_id::TEXT as agent_id FROM people WHERE person_id = :person_id::uuid LIMIT 1",
        {"person_id": person_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Person not found")
    agent_id = str(rows[0].get("agent_id") or "")
    _require_device_agent_access(device=device, agent_id=agent_id)
    _require_person_consent(agent_id=agent_id, person_id=person_id, consent_type="face")

    faceprint_id = str(uuid.uuid4())
    _get_db().execute(
        """
        INSERT INTO faceprints(faceprint_id, agent_id, person_id, embedding, model, metadata)
        VALUES(
          :faceprint_id::uuid,
          :agent_id::uuid,
          :person_id::uuid,
          CAST(:embedding AS vector),
          :model,
          :metadata::jsonb
        )
        """,
        {
            "faceprint_id": faceprint_id,
            "agent_id": agent_id,
            "person_id": person_id,
            "embedding": _vector_literal(body.embedding, 512),
            "model": str(body.model or "insightface-arcface").strip(),
            "metadata": json.dumps(body.metadata or {}),
        },
    )
    return {"ok": True, "faceprint_id": faceprint_id}


@api_app.delete("/v1/voiceprints/{voiceprint_id}")
def v1_revoke_voiceprint(voiceprint_id: str, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "biometrics:write")
    rows = _get_db().query(
        "SELECT agent_id::TEXT as agent_id FROM voiceprints WHERE voiceprint_id = :id::uuid LIMIT 1",
        {"id": voiceprint_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Voiceprint not found")
    agent_id = str(rows[0].get("agent_id") or "")
    _require_device_agent_access(device=device, agent_id=agent_id)
    _get_db().execute(
        "UPDATE voiceprints SET revoked_at = now() WHERE voiceprint_id = :id::uuid",
        {"id": voiceprint_id},
    )
    return {"ok": True, "voiceprint_id": voiceprint_id, "revoked": True}


@api_app.delete("/v1/faceprints/{faceprint_id}")
def v1_revoke_faceprint(faceprint_id: str, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "biometrics:write")
    rows = _get_db().query(
        "SELECT agent_id::TEXT as agent_id FROM faceprints WHERE faceprint_id = :id::uuid LIMIT 1",
        {"id": faceprint_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Faceprint not found")
    agent_id = str(rows[0].get("agent_id") or "")
    _require_device_agent_access(device=device, agent_id=agent_id)
    _get_db().execute(
        "UPDATE faceprints SET revoked_at = now() WHERE faceprint_id = :id::uuid",
        {"id": faceprint_id},
    )
    return {"ok": True, "faceprint_id": faceprint_id, "revoked": True}


class IdentifyEmbeddingIn(BaseModel):
    agent_id: str
    embedding: list[float]
    k: int = Field(default=1, ge=1, le=10)


@api_app.post("/v1/identify/voice")
def v1_identify_voice(body: IdentifyEmbeddingIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "biometrics:read")
    agent_id = str(body.agent_id or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    _require_device_agent_access(device=device, agent_id=agent_id)

    thr = float(os.getenv("VOICE_MATCH_THRESHOLD", "0.35"))
    q = _vector_literal([float(x) for x in (body.embedding or [])], 256)

    rows = _get_db().query(
        """
        SELECT vp.person_id::TEXT as person_id,
               p.display_name,
               (vp.embedding <=> CAST(:q AS vector))::DOUBLE PRECISION as distance
        FROM voiceprints vp
        JOIN people p ON p.person_id = vp.person_id
        WHERE vp.agent_id = :agent_id::uuid
          AND vp.revoked_at IS NULL
          AND EXISTS (
            SELECT 1 FROM consent_grants cg
            WHERE cg.agent_id = vp.agent_id
              AND cg.person_id = vp.person_id
              AND cg.consent_type IN ('voice', 'global')
              AND cg.revoked_at IS NULL
              AND (cg.expires_at IS NULL OR cg.expires_at > now())
          )
        ORDER BY vp.embedding <=> CAST(:q AS vector)
        LIMIT :limit
        """,
        {"agent_id": agent_id, "q": q, "limit": int(body.k or 1)},
    )
    candidates: list[dict[str, Any]] = []
    for r in rows:
        d = float(r.get("distance") or 0.0)
        candidates.append(
            {
                "person_id": r.get("person_id"),
                "display_name": r.get("display_name"),
                "distance": d,
                "confidence": max(0.0, min(1.0, 1.0 - d)),
            }
        )
    best = candidates[0] if candidates else None
    matched = bool(best) and float(best.get("distance") or 999) <= thr
    return {"matched": matched, "threshold": thr, "best": best, "candidates": candidates}


@api_app.post("/v1/identify/face")
def v1_identify_face(body: IdentifyEmbeddingIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "biometrics:read")
    agent_id = str(body.agent_id or "").strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")
    _require_device_agent_access(device=device, agent_id=agent_id)

    thr = float(os.getenv("FACE_MATCH_THRESHOLD", "0.50"))
    q = _vector_literal([float(x) for x in (body.embedding or [])], 512)

    rows = _get_db().query(
        """
        SELECT fp.person_id::TEXT as person_id,
               p.display_name,
               (fp.embedding <=> CAST(:q AS vector))::DOUBLE PRECISION as distance
        FROM faceprints fp
        JOIN people p ON p.person_id = fp.person_id
        WHERE fp.agent_id = :agent_id::uuid
          AND fp.revoked_at IS NULL
          AND EXISTS (
            SELECT 1 FROM consent_grants cg
            WHERE cg.agent_id = fp.agent_id
              AND cg.person_id = fp.person_id
              AND cg.consent_type IN ('face', 'global')
              AND cg.revoked_at IS NULL
              AND (cg.expires_at IS NULL OR cg.expires_at > now())
          )
        ORDER BY fp.embedding <=> CAST(:q AS vector)
        LIMIT :limit
        """,
        {"agent_id": agent_id, "q": q, "limit": int(body.k or 1)},
    )
    candidates: list[dict[str, Any]] = []
    for r in rows:
        d = float(r.get("distance") or 0.0)
        candidates.append(
            {
                "person_id": r.get("person_id"),
                "display_name": r.get("display_name"),
                "distance": d,
                "confidence": max(0.0, min(1.0, 1.0 - d)),
            }
        )
    best = candidates[0] if candidates else None
    matched = bool(best) and float(best.get("distance") or 999) <= thr
    return {"matched": matched, "threshold": thr, "best": best, "candidates": candidates}


@api_app.post("/v1/admin/spaces/{space_id}/privacy", dependencies=[Depends(require_admin)])
def admin_set_privacy(space_id: str, body: SetPrivacyIn) -> dict[str, Any]:
    rows = _get_db().query(
        "SELECT agent_id::TEXT as agent_id FROM spaces WHERE space_id = :space_id::uuid LIMIT 1", {"space_id": space_id}
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Space not found")
    agent_id = rows[0]["agent_id"]
    _get_db().execute(
        "UPDATE spaces SET privacy_mode = :privacy_mode WHERE space_id = :space_id::uuid",
        {"space_id": space_id, "privacy_mode": body.privacy_mode},
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="privacy_mode_set",
            entry={"space_id": space_id, "privacy_mode": body.privacy_mode},
        )
    return {"space_id": space_id, "privacy_mode": body.privacy_mode}


@api_app.post("/v1/events", response_model=IngestEventOut)
def ingest_event(body: IngestEventIn, device: AuthenticatedDevice = Depends(get_device)) -> IngestEventOut:
    require_scope(device, "events:write")
    space_agent_id = _resolve_space_agent_for_device(
        device=device,
        space_id=body.space_id,
        not_found_detail="Space not found",
        mismatch_status=404,
        mismatch_detail="Space not found",
    )
    if is_agent_disabled(_get_db(), space_agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")
    if is_privacy_mode(_get_db(), body.space_id):
        return IngestEventOut(event_id="privacy_mode", queued=False)
    event_id = str(uuid.uuid4())
    resolved_person_id = str(body.person_id or "").strip()

    # Best-effort: attribute transcript events to a person when we can map a
    # LiveKit participant identity -> user_id -> person_id.
    if not resolved_person_id and body.type == "transcript_chunk":
        participant_identity = body.payload.get("participant_identity")
        if isinstance(participant_identity, str) and participant_identity.startswith("user:"):
            user_id = participant_identity.split(":", 1)[1].strip()
            if user_id:
                rows = _get_db().query(
                    """
                    SELECT person_id::TEXT as person_id
                    FROM person_accounts
                    WHERE agent_id = :agent_id::uuid
                      AND user_id = :user_id::uuid
                    LIMIT 1
                    """,
                    {"agent_id": space_agent_id, "user_id": user_id},
                )
                if rows and rows[0].get("person_id"):
                    resolved_person_id = str(rows[0]["person_id"])
    _get_db().execute(
        """INSERT INTO events(event_id, agent_id, space_id, device_id, person_id, type, payload)
           VALUES (:event_id::uuid, :agent_id::uuid, :space_id::uuid, :device_id::uuid,
                   CASE WHEN :person_id = '' THEN NULL ELSE :person_id::uuid END, :type, :payload::jsonb)""",
        {
            "event_id": event_id,
            "agent_id": space_agent_id,
            "space_id": body.space_id,
            "device_id": device.device_id,
            "person_id": resolved_person_id or "",
            "type": body.type,
            "payload": json.dumps(body.payload),
        },
    )
    queued = False
    if body.type == "transcript_chunk" and _cfg.transcript_queue_url:
        _get_sqs().send_message(
            QueueUrl=_cfg.transcript_queue_url,
            MessageBody=json.dumps(
                {
                    "event_id": event_id,
                    "agent_id": space_agent_id,
                    "space_id": body.space_id,
                    "device_id": device.device_id,
                }
            ),
        )
        queued = True
    if body.type in {"voice.sample", "face.snapshot"} and _recognition_queue_url:
        try:
            _get_sqs().send_message(
                QueueUrl=str(_recognition_queue_url),
                MessageBody=json.dumps(
                    {
                        "event_id": event_id,
                        "agent_id": space_agent_id,
                        "space_id": body.space_id,
                        "device_id": device.device_id,
                        "person_id": resolved_person_id or None,
                        "type": body.type,
                        "payload": body.payload,
                    }
                ),
            )
            queued = True
        except Exception as exc:
            logger.warning("Failed to enqueue recognition event: %s", exc)
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=space_agent_id,
            entry_type="event_ingested",
            entry={"event_id": event_id, "type": body.type, "space_id": body.space_id, "queued": queued},
        )

    # Broadcast to subscribed WebSocket clients
    try:
        broadcast_event(
            event_type="events.new",
            agent_id=space_agent_id,
            space_id=body.space_id,
            payload={
                "event": {
                    "event_id": event_id,
                    "type": body.type,
                    "payload": body.payload,
                    "person_id": resolved_person_id or None,
                }
            },
        )
    except Exception as e:
        logger.warning("Failed to broadcast event: %s", e)

    return IngestEventOut(event_id=event_id, queued=queued)


@api_app.get("/v1/agents/{agent_id}/integration_accounts", response_model=dict[str, list[dict[str, Any]]])
def list_agent_integration_accounts(
    agent_id: str,
    provider: str | None = None,
    status: str | None = None,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, list[dict[str, Any]]]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    provider_n = _validate_integration_provider(provider) if provider else None
    accounts = list_integration_accounts(
        _get_db(),
        agent_id=agent_id,
        provider=provider_n,
        status=(str(status).strip() or None) if status else None,
    )
    return {"integration_accounts": [_integration_account_dict(account) for account in accounts]}


@api_app.post("/v1/agents/{agent_id}/integration_accounts", response_model=dict[str, Any])
def create_agent_integration_account(
    agent_id: str,
    body: IntegrationAccountCreateIn,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    account = create_integration_account(
        _get_db(),
        IntegrationAccountCreate(
            agent_id=agent_id,
            provider=_validate_integration_provider(body.provider),
            display_name=body.display_name,
            credentials_secret_arn=body.credentials_secret_arn,
            external_account_id=body.external_account_id,
            default_space_id=body.default_space_id,
            scopes=body.scopes,
            config=body.config,
            status=body.status,
        ),
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="integration_account_created",
            entry={
                "integration_account_id": account.integration_account_id,
                "provider": account.provider,
                "display_name": account.display_name,
            },
        )
    return {"integration_account": _integration_account_dict(account)}


@api_app.get("/v1/agents/{agent_id}/integration_accounts/{integration_account_id}", response_model=dict[str, Any])
def get_agent_integration_account(
    agent_id: str,
    integration_account_id: str,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    account = _require_agent_integration_account(agent_id, integration_account_id)
    return {"integration_account": _integration_account_dict(account)}


@api_app.patch("/v1/agents/{agent_id}/integration_accounts/{integration_account_id}", response_model=dict[str, Any])
def update_agent_integration_account(
    agent_id: str,
    integration_account_id: str,
    body: IntegrationAccountUpdateIn,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    _require_agent_integration_account(agent_id, integration_account_id)
    account = update_integration_account(
        _get_db(),
        integration_account_id=integration_account_id,
        update=IntegrationAccountUpdate(
            display_name=body.display_name if body.display_name is not None else _UNSET,
            credentials_secret_arn=body.credentials_secret_arn if body.credentials_secret_arn is not None else _UNSET,
            external_account_id=body.external_account_id if body.external_account_id is not None else _UNSET,
            default_space_id=body.default_space_id if body.default_space_id is not None else _UNSET,
            scopes=body.scopes if body.scopes is not None else _UNSET,
            config=body.config if body.config is not None else _UNSET,
            status=body.status if body.status is not None else _UNSET,
        ),
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="integration_account_updated",
            entry={
                "integration_account_id": account.integration_account_id,
                "provider": account.provider,
                "display_name": account.display_name,
            },
        )
    return {"integration_account": _integration_account_dict(account)}


@api_app.delete("/v1/agents/{agent_id}/integration_accounts/{integration_account_id}", response_model=dict[str, Any])
def delete_agent_integration_account(
    agent_id: str,
    integration_account_id: str,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    rows = _get_db().query(
        """
        DELETE FROM integration_accounts
        WHERE integration_account_id = :integration_account_id::uuid
          AND agent_id = :agent_id::uuid
        RETURNING integration_account_id::TEXT as integration_account_id
        """,
        {"integration_account_id": integration_account_id, "agent_id": agent_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Integration account not found")
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="integration_account_deleted",
            entry={"integration_account_id": integration_account_id},
        )
    return {"ok": True}


@api_app.get("/v1/agents/{agent_id}/messages", response_model=dict[str, list[dict[str, Any]]])
def list_agent_messages(
    agent_id: str,
    provider: str | None = None,
    status: str | None = None,
    external_thread_id: str | None = None,
    limit: int = 50,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, list[dict[str, Any]]]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    provider_n = _validate_integration_provider(provider) if provider else None
    limit_n = max(1, min(200, int(limit or 50)))
    rows = _get_db().query(
        """
        SELECT
            integration_message_id::TEXT as integration_message_id,
            agent_id::TEXT as agent_id,
            space_id::TEXT as space_id,
            event_id::TEXT as event_id,
            integration_account_id::TEXT as integration_account_id,
            action_id::TEXT as action_id,
            provider,
            direction,
            channel_type,
            object_type,
            external_thread_id,
            external_message_id,
            dedupe_key,
            sender::TEXT as sender_json,
            recipients::TEXT as recipients_json,
            subject,
            body_text,
            body_html,
            payload::TEXT as payload_json,
            status,
            contains_phi,
            retention_until::TEXT as retention_until,
            processed_at::TEXT as processed_at,
            redacted_at::TEXT as redacted_at,
            created_at::TEXT as created_at,
            updated_at::TEXT as updated_at
        FROM integration_messages
        WHERE agent_id = :agent_id::uuid
          AND (:provider IS NULL OR provider = :provider)
          AND (:status IS NULL OR status = :status)
          AND (:external_thread_id IS NULL OR external_thread_id = :external_thread_id)
        ORDER BY created_at DESC, integration_message_id DESC
        LIMIT :limit::int
        """,
        {
            "agent_id": agent_id,
            "provider": provider_n,
            "status": (str(status).strip() or None) if status else None,
            "external_thread_id": (str(external_thread_id).strip() or None) if external_thread_id else None,
            "limit": limit_n,
        },
    )
    return {"messages": rows}


@api_app.get("/v1/agents/{agent_id}/messages/{integration_message_id}", response_model=dict[str, Any])
def get_agent_message(
    agent_id: str,
    integration_message_id: str,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    message = get_integration_message(_get_db(), integration_message_id=integration_message_id)
    if message is None or message.agent_id != agent_id:
        raise HTTPException(status_code=404, detail="Integration message not found")
    return {"integration_message": _integration_message_dict(message)}


@api_app.post("/v1/integrations/slack/webhook/{integration_account_id}", response_model=None)
async def ingest_slack_webhook(integration_account_id: str, request: Request) -> Any:
    signature = str(request.headers.get("x-slack-signature") or "").strip()
    timestamp = str(request.headers.get("x-slack-request-timestamp") or "").strip()
    if not signature or not timestamp:
        raise HTTPException(status_code=401, detail="Missing Slack signature headers")

    raw_body = await request.body()
    account = _require_webhook_account(integration_account_id, "slack")
    secret_data = _require_integration_account_secret_data(account)
    signing_secret = str(secret_data.get("signing_secret") or "").strip()
    if not signing_secret or signing_secret == "REPLACE_ME":
        raise HTTPException(status_code=500, detail="Slack signing secret not configured")
    try:
        verify_slack_request(
            signing_secret,
            timestamp=timestamp,
            signature=signature,
            body=raw_body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    if is_agent_disabled(_get_db(), account.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    normalized = normalize_slack_webhook(payload, agent_id=account.agent_id, space_id=account.default_space_id)
    if normalized.challenge is not None:
        return PlainTextResponse(normalized.challenge)
    if normalized.ignored_reason is not None:
        return {
            "ok": True,
            "provider": "slack",
            "ignored": True,
            "reason": normalized.ignored_reason,
        }
    if normalized.integration_message is None:
        raise HTTPException(status_code=400, detail="Slack payload did not produce an integration message")

    db = _get_db()
    tx = db.begin()
    write_result = None
    resolved_message = None
    inserted = False
    try:
        write_result = insert_integration_message(db, normalized.integration_message, transaction_id=tx)
        resolved_message = write_result.message
        inserted = write_result.inserted

        if not resolved_message.event_id:
            event_id = str(uuid.uuid4())
            event_payload = dict(normalized.event_payload)
            event_payload["integration_message_id"] = resolved_message.integration_message_id
            db.execute(
                """
                INSERT INTO events(event_id, agent_id, space_id, device_id, type, payload)
                VALUES(
                    :event_id::uuid,
                    :agent_id::uuid,
                    :space_id::uuid,
                    NULL,
                    :type,
                    :payload::jsonb
                )
                """,
                {
                    "event_id": event_id,
                    "agent_id": account.agent_id,
                    "space_id": account.default_space_id,
                    "type": "integration.event.received",
                    "payload": json.dumps(event_payload),
                },
                transaction_id=tx,
            )
            resolved_message = link_integration_message_event(
                db,
                integration_message_id=resolved_message.integration_message_id,
                event_id=event_id,
                transaction_id=tx,
            )

        db.commit(tx)
    except RuntimeError as exc:
        db.rollback(tx)
        if "already linked to a different event" not in str(exc) or write_result is None:
            raise
        resolved_message = get_integration_message(
            db,
            integration_message_id=write_result.message.integration_message_id,
        )
        if resolved_message is None or not resolved_message.event_id:
            raise HTTPException(status_code=409, detail="Slack webhook event conflict") from exc
    except Exception:
        db.rollback(tx)
        raise

    if resolved_message is None or not resolved_message.event_id:
        raise RuntimeError("Slack integration message is missing an event_id")
    if not _cfg.integration_queue_url:
        raise HTTPException(status_code=500, detail="INTEGRATION_QUEUE_URL not configured")

    enqueue_integration_event(
        _get_sqs(),
        queue_url=_cfg.integration_queue_url,
        message=IntegrationQueueMessage(
            event_id=resolved_message.event_id,
            agent_id=account.agent_id,
            space_id=account.default_space_id,
            integration_message_id=resolved_message.integration_message_id,
        ),
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=account.agent_id,
            entry_type="integration_webhook_received",
            entry={
                "provider": "slack",
                "space_id": account.default_space_id,
                "event_id": resolved_message.event_id,
                "integration_message_id": resolved_message.integration_message_id,
                "inserted": inserted,
            },
        )

    return {
        "ok": True,
        "provider": "slack",
        "event_id": resolved_message.event_id,
        "integration_message_id": resolved_message.integration_message_id,
        "inserted": inserted,
    }


@api_app.post("/v1/integrations/twilio/webhook/{integration_account_id}", response_model=None)
async def ingest_twilio_webhook(integration_account_id: str, request: Request) -> Any:
    signature = str(request.headers.get("x-twilio-signature") or "").strip()
    if not signature:
        raise HTTPException(status_code=401, detail="Missing Twilio signature header")

    raw_body = await request.body()
    account = _require_webhook_account(integration_account_id, "twilio")
    secret_data = _require_integration_account_secret_data(account)
    auth_token = str(secret_data.get("auth_token") or "").strip()
    account_sid = str(secret_data.get("account_sid") or "").strip()
    if not auth_token or auth_token == "REPLACE_ME":
        raise HTTPException(status_code=500, detail="Twilio auth token not configured")
    try:
        payload = parse_twilio_form_body(raw_body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload_account_sid = str((payload.get("AccountSid") or [""])[0]).strip()
    if account_sid and payload_account_sid and payload_account_sid != account_sid:
        raise HTTPException(status_code=403, detail="Twilio account SID mismatch")
    try:
        verify_twilio_request(
            auth_token,
            url=str(request.url),
            params=payload,
            signature=signature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    if is_agent_disabled(_get_db(), account.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    normalized = normalize_twilio_webhook(payload, agent_id=account.agent_id, space_id=account.default_space_id)
    if normalized.ignored_reason is not None:
        return PlainTextResponse("")
    if normalized.integration_message is None:
        raise HTTPException(status_code=400, detail="Twilio payload did not produce an integration message")

    db = _get_db()
    tx = db.begin()
    write_result = None
    resolved_message = None
    inserted = False
    try:
        write_result = insert_integration_message(db, normalized.integration_message, transaction_id=tx)
        resolved_message = write_result.message
        inserted = write_result.inserted

        if not resolved_message.event_id:
            event_id = str(uuid.uuid4())
            event_payload = dict(normalized.event_payload)
            event_payload["integration_message_id"] = resolved_message.integration_message_id
            db.execute(
                """
                INSERT INTO events(event_id, agent_id, space_id, device_id, type, payload)
                VALUES(
                    :event_id::uuid,
                    :agent_id::uuid,
                    :space_id::uuid,
                    NULL,
                    :type,
                    :payload::jsonb
                )
                """,
                {
                    "event_id": event_id,
                    "agent_id": account.agent_id,
                    "space_id": account.default_space_id,
                    "type": "integration.event.received",
                    "payload": json.dumps(event_payload),
                },
                transaction_id=tx,
            )
            resolved_message = link_integration_message_event(
                db,
                integration_message_id=resolved_message.integration_message_id,
                event_id=event_id,
                transaction_id=tx,
            )

        db.commit(tx)
    except RuntimeError as exc:
        db.rollback(tx)
        if "already linked to a different event" not in str(exc) or write_result is None:
            raise
        resolved_message = get_integration_message(
            db,
            integration_message_id=write_result.message.integration_message_id,
        )
        if resolved_message is None or not resolved_message.event_id:
            raise HTTPException(status_code=409, detail="Twilio webhook event conflict") from exc
    except Exception:
        db.rollback(tx)
        raise

    if resolved_message is None or not resolved_message.event_id:
        raise RuntimeError("Twilio integration message is missing an event_id")
    if not _cfg.integration_queue_url:
        raise HTTPException(status_code=500, detail="INTEGRATION_QUEUE_URL not configured")

    enqueue_integration_event(
        _get_sqs(),
        queue_url=_cfg.integration_queue_url,
        message=IntegrationQueueMessage(
            event_id=resolved_message.event_id,
            agent_id=account.agent_id,
            space_id=account.default_space_id,
            integration_message_id=resolved_message.integration_message_id,
        ),
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=account.agent_id,
            entry_type="integration_webhook_received",
            entry={
                "provider": "twilio",
                "space_id": account.default_space_id,
                "event_id": resolved_message.event_id,
                "integration_message_id": resolved_message.integration_message_id,
                "inserted": inserted,
            },
        )

    return PlainTextResponse("")


@api_app.post("/v1/integrations/github/webhook/{integration_account_id}", response_model=None)
async def ingest_github_webhook(integration_account_id: str, request: Request) -> Any:
    signature = str(request.headers.get("x-hub-signature-256") or "").strip()
    event_name = str(request.headers.get("x-github-event") or "").strip()
    delivery_id = str(request.headers.get("x-github-delivery") or "").strip()
    if not signature or not event_name or not delivery_id:
        raise HTTPException(status_code=401, detail="Missing GitHub signature headers")

    raw_body = await request.body()
    account = _require_webhook_account(integration_account_id, "github")
    secret_data = _require_integration_account_secret_data(account)
    webhook_secret = str(secret_data.get("webhook_secret") or "").strip()
    if not webhook_secret or webhook_secret == "REPLACE_ME":
        raise HTTPException(status_code=500, detail="GitHub webhook secret not configured")
    try:
        verify_github_request(webhook_secret, signature=signature, body=raw_body)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

    if is_agent_disabled(_get_db(), account.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    normalized = normalize_github_webhook(
        payload,
        event_name=event_name,
        delivery_id=delivery_id,
        agent_id=account.agent_id,
        space_id=account.default_space_id,
    )
    if normalized.ignored_reason is not None:
        return {
            "ok": True,
            "provider": "github",
            "ignored": True,
            "reason": normalized.ignored_reason,
        }
    if normalized.integration_message is None:
        raise HTTPException(status_code=400, detail="GitHub payload did not produce an integration message")

    db = _get_db()
    tx = db.begin()
    write_result = None
    resolved_message = None
    inserted = False
    try:
        write_result = insert_integration_message(db, normalized.integration_message, transaction_id=tx)
        resolved_message = write_result.message
        inserted = write_result.inserted

        if not resolved_message.event_id:
            event_id = str(uuid.uuid4())
            event_payload = dict(normalized.event_payload)
            event_payload["integration_message_id"] = resolved_message.integration_message_id
            db.execute(
                """
                INSERT INTO events(event_id, agent_id, space_id, device_id, type, payload)
                VALUES(
                    :event_id::uuid,
                    :agent_id::uuid,
                    :space_id::uuid,
                    NULL,
                    :type,
                    :payload::jsonb
                )
                """,
                {
                    "event_id": event_id,
                    "agent_id": account.agent_id,
                    "space_id": account.default_space_id,
                    "type": "integration.event.received",
                    "payload": json.dumps(event_payload),
                },
                transaction_id=tx,
            )
            resolved_message = link_integration_message_event(
                db,
                integration_message_id=resolved_message.integration_message_id,
                event_id=event_id,
                transaction_id=tx,
            )

        db.commit(tx)
    except RuntimeError as exc:
        db.rollback(tx)
        if "already linked to a different event" not in str(exc) or write_result is None:
            raise
        resolved_message = get_integration_message(
            db,
            integration_message_id=write_result.message.integration_message_id,
        )
        if resolved_message is None or not resolved_message.event_id:
            raise HTTPException(status_code=409, detail="GitHub webhook event conflict") from exc
    except Exception:
        db.rollback(tx)
        raise

    if resolved_message is None or not resolved_message.event_id:
        raise RuntimeError("GitHub integration message is missing an event_id")
    if not _cfg.integration_queue_url:
        raise HTTPException(status_code=500, detail="INTEGRATION_QUEUE_URL not configured")

    enqueue_integration_event(
        _get_sqs(),
        queue_url=_cfg.integration_queue_url,
        message=IntegrationQueueMessage(
            event_id=resolved_message.event_id,
            agent_id=account.agent_id,
            space_id=account.default_space_id,
            integration_message_id=resolved_message.integration_message_id,
        ),
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=account.agent_id,
            entry_type="integration_webhook_received",
            entry={
                "provider": "github",
                "space_id": account.default_space_id,
                "event_id": resolved_message.event_id,
                "integration_message_id": resolved_message.integration_message_id,
                "inserted": inserted,
            },
        )

    return {
        "ok": True,
        "provider": "github",
        "event_id": resolved_message.event_id,
        "integration_message_id": resolved_message.integration_message_id,
        "inserted": inserted,
    }


@api_app.get("/v1/memories")
def list_memories(limit: int = 50, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "memories:read")
    limit = max(1, min(200, limit))
    rows = _get_db().query(
        """SELECT memory_id::TEXT as memory_id, tier, content, created_at::TEXT as created_at,
                  participants::TEXT as participants, provenance::TEXT as provenance,
                  subject_person_id::TEXT as subject_person_id, tags, scene_context,
                  modality, confidence, related_memory_ids::TEXT[] as related_memory_ids
           FROM memories WHERE agent_id = :agent_id::uuid ORDER BY created_at DESC LIMIT :limit""",
        {"agent_id": device.agent_id, "limit": limit},
    )
    return {"memories": rows}


@api_app.delete("/v1/memories/{memory_id}")
def delete_memory(memory_id: str, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "memories:write")
    _get_db().execute(
        "DELETE FROM memories WHERE memory_id = :memory_id::uuid AND agent_id = :agent_id::uuid",
        {"memory_id": memory_id, "agent_id": device.agent_id},
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=device.agent_id,
            entry_type="memory_deleted",
            entry={"memory_id": memory_id},
        )
    return {"deleted": True, "memory_id": memory_id}


class MemoryCreateIn(BaseModel):
    """Request body for creating a memory from a device."""

    space_id: str | None = None
    tier: str = Field(default="episodic", description="Memory tier: episodic, semantic, or procedural")
    content: str = Field(..., min_length=1, max_length=10000)
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary metadata (input_modality, room_name, etc.)"
    )
    participants: list[str] = Field(default_factory=list)
    subject_person_id: str | None = Field(default=None, description="Person this memory is about")
    tags: list[str] = Field(default_factory=list, description="Freeform tags")
    scene_context: str | None = Field(default=None, description="Where/when context")
    modality: str = Field(default="text", description="text, image, audio, video, sensor")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    related_memory_ids: list[str] = Field(default_factory=list, description="Related memory UUIDs")


@api_app.post("/v1/memories")
def create_memory(body: MemoryCreateIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    """Create a memory for the device's agent (requires memories:write scope)."""
    require_scope(device, "memories:write")

    target_agent_id = str(device.agent_id)
    if body.space_id:
        target_agent_id = _resolve_space_agent_for_device(
            device=device,
            space_id=body.space_id,
            not_found_detail="Space not found",
            mismatch_status=404,
            mismatch_detail="Space not found for this agent",
        )

    memory_id = str(uuid.uuid4())
    provenance = {
        "source": "device",
        "device_id": device.device_id,
        **body.metadata,
    }
    embedding: str | None = None
    if _cfg.openai_secret_arn:
        try:
            embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
            vec = call_embeddings(
                openai_secret_arn=_cfg.openai_secret_arn,
                model=embed_model,
                text=body.content,
            )
            embedding = "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
        except Exception as e:
            logger.warning("Failed to generate memory embedding (continuing without embedding): %s", e)

    _get_db().execute(
        """
        INSERT INTO memories (memory_id, agent_id, space_id, tier, content, participants, provenance, embedding,
                              subject_person_id, tags, scene_context, modality, confidence, related_memory_ids)
        VALUES (
            :memory_id::uuid,
            :agent_id::uuid,
            CASE WHEN :space_id IS NULL THEN NULL ELSE :space_id::uuid END,
            :tier,
            :content,
            :participants::jsonb,
            :provenance::jsonb,
            CASE WHEN :embedding IS NULL THEN NULL ELSE CAST(:embedding AS vector) END,
            CASE WHEN :subject_person_id IS NULL THEN NULL ELSE :subject_person_id::uuid END,
            :tags::text[],
            :scene_context,
            :modality,
            :confidence,
            :related_memory_ids::uuid[]
        )
        """,
        {
            "memory_id": memory_id,
            "agent_id": target_agent_id,
            "space_id": body.space_id,
            "tier": body.tier,
            "content": body.content,
            "participants": json.dumps(body.participants),
            "provenance": json.dumps(provenance),
            "embedding": embedding,
            "subject_person_id": body.subject_person_id,
            "tags": "{" + ",".join(body.tags) + "}" if body.tags else "{}",
            "scene_context": body.scene_context,
            "modality": body.modality,
            "confidence": body.confidence,
            "related_memory_ids": "{" + ",".join(body.related_memory_ids) + "}" if body.related_memory_ids else "{}",
        },
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=target_agent_id,
            entry_type="memory_created",
            entry={"memory_id": memory_id, "tier": body.tier, "source": "device"},
        )

    return {"memory_id": memory_id, "tier": body.tier, "created": True}


# -----------------------------------------------------------------------------
# Memory Recall Endpoint (Semantic Search)
# -----------------------------------------------------------------------------


class RecallIn(BaseModel):
    """Request body for semantic memory recall."""

    agent_id: str
    space_id: str | None = None
    person_id: str | None = Field(
        default=None,
        description="Optional filter: only memories about/including this person (subject_person_id or participants contains person:<id>)",
    )
    query: str = Field(..., min_length=1, max_length=2000)
    k: int = Field(default=8, ge=1, le=50)
    tiers: list[str] | None = None


class RecallMemoryOut(BaseModel):
    """A single recalled memory."""

    memory_id: str
    tier: str
    content: str
    created_at: str
    distance: float


class RecallOut(BaseModel):
    """Response for memory recall."""

    memories: list[RecallMemoryOut]


@api_app.post("/v1/recall", response_model=RecallOut)
def recall_memories(body: RecallIn, device: AuthenticatedDevice = Depends(get_device)) -> RecallOut:
    """Semantic memory search using pgvector embeddings.

    Searches memories for the agent using cosine similarity on embeddings.
    Returns the k most relevant memories ordered by distance.
    """
    require_scope(device, "memories:read")

    target_agent_id = str(body.agent_id)
    if device.agent_id != target_agent_id:
        if not _device_is_admin(device):
            raise HTTPException(status_code=403, detail="Cannot recall memories for a different agent")
        if not body.space_id:
            raise HTTPException(status_code=403, detail="Admin device recall across agents requires space_id")
        space_agent_id = _resolve_space_agent_for_device(
            device=device,
            space_id=body.space_id,
            not_found_detail="Space not found",
            mismatch_status=403,
            mismatch_detail="Cannot recall memories for a different agent",
        )
        target_agent_id = space_agent_id

    if not _cfg.openai_secret_arn:
        raise HTTPException(status_code=503, detail="OPENAI_SECRET_ARN not configured")

    # Generate query embedding
    try:
        embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
        query_embedding = call_embeddings(
            openai_secret_arn=_cfg.openai_secret_arn,
            model=embed_model,
            text=body.query,
        )
        emb_str = "[" + ",".join(f"{x:.6f}" for x in query_embedding) + "]"
    except Exception as e:
        logger.warning("Failed to generate query embedding: %s", e)
        raise HTTPException(status_code=502, detail="Failed to generate query embedding")

    # Build query with optional tier and space filters
    tier_clause = ""
    params: dict[str, Any] = {
        "agent_id": target_agent_id,
        "q": emb_str,
        "limit": body.k,
    }

    if body.tiers:
        tier_clause = "AND tier = ANY(:tiers)"
        params["tiers"] = body.tiers

    space_clause = ""
    if body.space_id:
        space_clause = "AND (space_id = :space_id::uuid OR space_id IS NULL)"
        params["space_id"] = body.space_id

    person_clause = ""
    if body.person_id:
        person_clause = "AND (subject_person_id = :person_id::uuid OR participants @> :person_ref::jsonb)"
        params["person_id"] = body.person_id
        params["person_ref"] = json.dumps([f"person:{body.person_id}"])

    # Query with pgvector cosine distance
    rows = _get_db().query(
        f"""
        SELECT memory_id::TEXT as memory_id,
               tier,
               content,
               created_at::TEXT as created_at,
               (embedding <=> CAST(:q AS vector))::DOUBLE PRECISION as distance
        FROM memories
        WHERE agent_id = :agent_id::uuid
          AND embedding IS NOT NULL
          {tier_clause}
          {space_clause}
          {person_clause}
        ORDER BY embedding <=> CAST(:q AS vector)
        LIMIT :limit
        """,
        params,
    )

    memories = [
        RecallMemoryOut(
            memory_id=r["memory_id"],
            tier=r["tier"],
            content=r["content"],
            created_at=r["created_at"],
            distance=float(r.get("distance", 0.0)),
        )
        for r in rows
    ]

    return RecallOut(memories=memories)


# -----------------------------------------------------------------------------
# Space Events Endpoint
# -----------------------------------------------------------------------------


class SpaceEventOut(BaseModel):
    """A single event in a space."""

    event_id: str
    type: str
    person_id: str | None
    payload: dict[str, Any]
    created_at: str


class SpaceEventsOut(BaseModel):
    """Response for space events."""

    events: list[SpaceEventOut]


@api_app.get("/v1/spaces/{space_id}/events", response_model=SpaceEventsOut)
def get_space_events(
    space_id: str,
    limit: int = 50,
    device: AuthenticatedDevice = Depends(get_device),
) -> SpaceEventsOut:
    """Get recent events for a space.

    Returns events in reverse chronological order (newest first).
    Used for context hydration when an agent joins a space.
    """
    require_scope(device, "events:read")

    _resolve_space_agent_for_device(
        device=device,
        space_id=space_id,
        not_found_detail="Space not found",
        mismatch_status=403,
        mismatch_detail="Space belongs to a different agent",
    )

    # Check privacy mode
    if is_privacy_mode(_get_db(), space_id):
        return SpaceEventsOut(events=[])

    limit = max(1, min(200, limit))

    event_rows = _get_db().query(
        """
        SELECT event_id::TEXT as event_id,
               type,
               person_id::TEXT as person_id,
               payload::TEXT as payload_json,
               created_at::TEXT as created_at
        FROM events
        WHERE space_id = :space_id::uuid
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"space_id": space_id, "limit": limit},
    )

    events = []
    for r in event_rows:
        try:
            payload = json.loads(r.get("payload_json") or "{}")
        except Exception:
            payload = {}
        events.append(
            SpaceEventOut(
                event_id=r["event_id"],
                type=r["type"],
                person_id=r.get("person_id"),
                payload=payload,
                created_at=r["created_at"],
            )
        )

    return SpaceEventsOut(events=events)


@api_app.post("/v1/artifacts/presign")
def presign_upload(body: PresignIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    require_scope(device, "artifacts:write")
    if not _cfg.artifact_bucket:
        raise HTTPException(status_code=500, detail="Artifact bucket not configured")
    purpose = str(body.purpose or "general").strip().lower()
    if purpose not in {"general", "recognition"}:
        purpose = "general"
    prefix = "recognition" if purpose == "recognition" else "artifacts"
    key = f"{prefix}/agent_id={device.agent_id}/{uuid.uuid4()}_{body.filename}"
    url = _get_s3().generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": _cfg.artifact_bucket, "Key": key, "ContentType": body.content_type},
        ExpiresIn=900,
    )
    return {"upload_url": url, "bucket": _cfg.artifact_bucket, "key": key, "purpose": purpose}


# -----------------------------------------------------------------------------
# Device Heartbeat Endpoint
# -----------------------------------------------------------------------------


class HeartbeatIn(BaseModel):
    """Optional metadata to update on heartbeat."""

    metadata: dict[str, Any] | None = Field(default=None, description="Optional device metadata update")


class HeartbeatOut(BaseModel):
    """Response for heartbeat."""

    ok: bool
    device_id: str
    last_heartbeat_at: str


@api_app.post("/v1/devices/heartbeat", response_model=HeartbeatOut)
def device_heartbeat(
    body: HeartbeatIn | None = None, device: AuthenticatedDevice = Depends(get_device)
) -> HeartbeatOut:
    """Update device heartbeat timestamp and optionally metadata.

    This endpoint should be called periodically (every 15-30 seconds) by devices
    to indicate they are still online and reachable.
    """
    require_scope(device, "presence:write")

    db = _get_db()

    prev_rows = db.query(
        """
        SELECT COALESCE(EXTRACT(EPOCH FROM (now() - last_heartbeat_at)) * 1000, 0) as lag_ms
        FROM devices
        WHERE device_id = :device_id::uuid
        LIMIT 1
        """,
        {"device_id": device.device_id},
    )
    prev_lag_ms = float(prev_rows[0].get("lag_ms") or 0) if prev_rows else 0.0

    # Update last_heartbeat_at and optionally metadata
    if body and body.metadata:
        db.execute(
            """UPDATE devices
               SET last_heartbeat_at = now(), last_seen = now(),
                   metadata = COALESCE(metadata, '{}'::jsonb) || :metadata::jsonb
               WHERE device_id = :device_id::uuid""",
            {"device_id": device.device_id, "metadata": json.dumps(body.metadata)},
        )
    else:
        db.execute(
            """UPDATE devices SET last_heartbeat_at = now(), last_seen = now()
               WHERE device_id = :device_id::uuid""",
            {"device_id": device.device_id},
        )

    # Fetch the updated timestamp
    rows = db.query(
        "SELECT last_heartbeat_at::TEXT as last_heartbeat_at FROM devices WHERE device_id = :device_id::uuid",
        {"device_id": device.device_id},
    )
    ts = rows[0]["last_heartbeat_at"] if rows else "unknown"

    # Broadcast presence update to subscribed clients
    try:
        broadcast_event(
            event_type="presence.updated",
            agent_id=device.agent_id,
            payload={
                "device_id": device.device_id,
                "status": "online",
                "last_heartbeat_at": ts,
            },
        )
    except Exception as e:
        logger.warning("Failed to broadcast presence: %s", e)

    emit_count("PresenceHeartbeat", dimensions={"AgentId": str(device.agent_id)})
    emit_ms("DeviceFreshnessLagMs", value_ms=prev_lag_ms, dimensions={"AgentId": str(device.agent_id)})

    return HeartbeatOut(ok=True, device_id=device.device_id, last_heartbeat_at=ts)


# -----------------------------------------------------------------------------
# Human Presence Endpoint (people presence within a space)
# -----------------------------------------------------------------------------


class PresenceUpdateIn(BaseModel):
    person_id: str
    status: str = Field(..., description="present|absent")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    modality: str = Field(default="manual", description="voice|face|manual")
    observed_at: str | None = None
    source_device_id: str | None = None


class PresenceIn(BaseModel):
    updates: list[PresenceUpdateIn] = Field(default_factory=list)


@api_app.post("/v1/spaces/{space_id}/presence")
def update_space_presence(
    space_id: str, body: PresenceIn, device: AuthenticatedDevice = Depends(get_device)
) -> dict[str, Any]:
    """Upsert presence records for people in a space (requires presence:write)."""
    require_scope(device, "presence:write")

    agent_id = _resolve_space_agent_for_device(
        device=device,
        space_id=space_id,
        not_found_detail="Space not found",
        mismatch_status=404,
        mismatch_detail="Space not found",
    )

    db = _get_db()
    applied: list[dict[str, Any]] = []
    for upd in body.updates or []:
        person_id = str(upd.person_id or "").strip()
        if not person_id:
            continue
        status = str(upd.status or "").strip().lower()
        if status not in {"present", "absent"}:
            raise HTTPException(status_code=400, detail="Invalid presence status (expected present|absent)")
        modality = str(upd.modality or "manual").strip().lower()
        if modality not in {"voice", "face", "manual"}:
            modality = "manual"

        # Ensure person belongs to this agent.
        prow = db.query(
            """
            SELECT 1
            FROM people
            WHERE person_id = :person_id::uuid
              AND agent_id = :agent_id::uuid
            LIMIT 1
            """,
            {"person_id": person_id, "agent_id": agent_id},
        )
        if not prow:
            raise HTTPException(status_code=404, detail="Person not found")

        source_device_id = str(upd.source_device_id or device.device_id or "").strip() or device.device_id
        # Upsert (select then update/insert) to avoid requiring a unique constraint.
        existing = db.query(
            """
            SELECT presence_id::TEXT as presence_id
            FROM presence
            WHERE agent_id = :agent_id::uuid
              AND space_id = :space_id::uuid
              AND person_id = :person_id::uuid
            LIMIT 1
            """,
            {"agent_id": agent_id, "space_id": space_id, "person_id": person_id},
        )
        if existing:
            db.execute(
                """
                UPDATE presence
                SET status = :status,
                    confidence = :confidence,
                    device_id = :device_id::uuid,
                    last_update = COALESCE(:observed_at::timestamptz, now())
                WHERE presence_id = :presence_id::uuid
                """,
                {
                    "presence_id": existing[0]["presence_id"],
                    "status": status,
                    "confidence": float(upd.confidence or 0),
                    "device_id": source_device_id,
                    "observed_at": upd.observed_at,
                },
            )
        else:
            presence_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO presence(presence_id, agent_id, space_id, person_id, device_id, status, confidence, last_update)
                VALUES(
                  :presence_id::uuid,
                  :agent_id::uuid,
                  :space_id::uuid,
                  :person_id::uuid,
                  :device_id::uuid,
                  :status,
                  :confidence,
                  COALESCE(:observed_at::timestamptz, now())
                )
                """,
                {
                    "presence_id": presence_id,
                    "agent_id": agent_id,
                    "space_id": space_id,
                    "person_id": person_id,
                    "device_id": source_device_id,
                    "status": status,
                    "confidence": float(upd.confidence or 0),
                    "observed_at": upd.observed_at,
                },
            )

        applied.append(
            {
                "person_id": person_id,
                "status": status,
                "confidence": float(upd.confidence or 0),
                "modality": modality,
                "device_id": source_device_id,
            }
        )

        # Broadcast presence update
        try:
            broadcast_event(
                event_type="presence.updated",
                agent_id=agent_id,
                space_id=space_id,
                payload={
                    "person_id": person_id,
                    "status": status,
                    "confidence": float(upd.confidence or 0),
                    "modality": modality,
                    "device_id": source_device_id,
                },
            )
        except Exception as exc:
            logger.warning("Failed to broadcast human presence: %s", exc)

    return {"ok": True, "space_id": space_id, "updates_applied": applied}


# -----------------------------------------------------------------------------
# Agent-to-Agent Token Management
# -----------------------------------------------------------------------------


class CreateAgentTokenIn(BaseModel):
    """Request body for creating an agent token."""

    name: str = Field(default="agent-token", description="Human-readable name for the token")
    target_agent_id: str | None = Field(default=None, description="If set, only this agent can use the token")
    scopes: list[str] = Field(default_factory=list, description="Permission scopes granted to token holder")
    allowed_spaces: list[str] | None = Field(default=None, description="If set, token only valid for these spaces")
    expires_at: str | None = Field(default=None, description="ISO timestamp when token expires")


class CreateAgentTokenOut(BaseModel):
    """Response for creating an agent token."""

    token_id: str
    token: str  # Plaintext token - only returned once!
    name: str
    scopes: list[str]


class AgentTokenOut(BaseModel):
    """Agent token metadata (excludes plaintext token)."""

    token_id: str
    target_agent_id: str | None
    name: str | None
    scopes: list[str]
    allowed_spaces: list[str] | None
    expires_at: str | None
    revoked_at: str | None
    last_used_at: str | None
    created_at: str | None
    is_active: bool


@api_app.post("/v1/agents/{agent_id}/tokens", response_model=CreateAgentTokenOut)
def create_agent_token_endpoint(
    agent_id: str,
    body: CreateAgentTokenIn,
    user: AuthenticatedUser = Depends(get_user),
) -> CreateAgentTokenOut:
    """Create a new agent-to-agent authentication token.

    Requires admin role on the agent. The plaintext token is only returned once.
    """
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    if is_agent_disabled(_get_db(), agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    token_id, plaintext_token = create_agent_token(
        _get_db(),
        issuer_agent_id=agent_id,
        target_agent_id=body.target_agent_id,
        name=body.name,
        scopes=body.scopes,
        allowed_spaces=body.allowed_spaces,
        expires_at=body.expires_at,
        created_by_user_id=user.user_id,
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="agent_token_created",
            entry={
                "token_id": token_id,
                "name": body.name,
                "scopes": body.scopes,
                "target_agent_id": body.target_agent_id,
                "created_by_user_id": user.user_id,
            },
        )

    return CreateAgentTokenOut(
        token_id=token_id,
        token=plaintext_token,
        name=body.name,
        scopes=body.scopes,
    )


@api_app.get("/v1/agents/{agent_id}/tokens", response_model=list[AgentTokenOut])
def list_agent_tokens_endpoint(
    agent_id: str,
    user: AuthenticatedUser = Depends(get_user),
) -> list[AgentTokenOut]:
    """List all tokens issued by an agent.

    Requires member role or higher on the agent.
    """
    _require_agent_role(user=user, agent_id=agent_id, required_role="member")

    tokens = list_agent_tokens(_get_db(), issuer_agent_id=agent_id)

    return [
        AgentTokenOut(
            token_id=t["token_id"],
            target_agent_id=t.get("target_agent_id"),
            name=t.get("name"),
            scopes=t.get("scopes", []),
            allowed_spaces=t.get("allowed_spaces"),
            expires_at=t.get("expires_at"),
            revoked_at=t.get("revoked_at"),
            last_used_at=t.get("last_used_at"),
            created_at=t.get("created_at"),
            is_active=t.get("is_active", False),
        )
        for t in tokens
    ]


@api_app.delete("/v1/agents/{agent_id}/tokens/{token_id}")
def revoke_agent_token_endpoint(
    agent_id: str,
    token_id: str,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    """Revoke an agent token.

    Requires admin role on the agent.
    """
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")

    success = revoke_agent_token(_get_db(), token_id=token_id)

    if not success:
        raise HTTPException(status_code=404, detail="Token not found or already revoked")

    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="agent_token_revoked",
            entry={
                "token_id": token_id,
                "revoked_by_user_id": user.user_id,
            },
        )

    return {"ok": True, "token_id": token_id, "revoked": True}


def get_agent(request: Request) -> AuthenticatedAgent:
    """Dependency to authenticate agent-to-agent requests.

    Expects Authorization: Bearer <agent_token>
    """
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    agent = authenticate_agent_token(_get_db(), token)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or expired agent token")
    return agent


# -----------------------------------------------------------------------------
# Agent-to-Agent Delegation Endpoints
# These endpoints allow agents to access other agents' resources using tokens.
# -----------------------------------------------------------------------------

# Standard scopes for agent-to-agent delegation
AGENT_SCOPES = {
    "read_memories": "Read memories from the issuing agent",
    "write_memories": "Create memories for the issuing agent",
    "read_events": "Read events from the issuing agent",
    "write_events": "Create events for the issuing agent",
    "read_spaces": "List spaces belonging to the issuing agent",
    "execute_actions": "Execute actions on behalf of the issuing agent",
    "delegate": "Create sub-tokens with subset of own scopes",
}


def _require_agent_scope(agent: AuthenticatedAgent, scope: str) -> None:
    """Check that an authenticated agent has a required scope."""
    if scope not in agent.scopes:
        raise HTTPException(
            status_code=403,
            detail=f"Missing required scope: {scope}",
        )


def _check_agent_space(agent: AuthenticatedAgent, space_id: str) -> None:
    """Check that an authenticated agent can access a space."""
    if agent.allowed_spaces is not None and space_id not in agent.allowed_spaces:
        raise HTTPException(
            status_code=403,
            detail=f"Token not authorized for space: {space_id}",
        )


@api_app.get("/v1/delegate/scopes")
def list_available_scopes() -> dict[str, str]:
    """List all available scopes for agent-to-agent delegation."""
    return AGENT_SCOPES


@api_app.get("/v1/delegate/memories")
def delegate_read_memories(
    space_id: str | None = None,
    limit: int = 100,
    agent: AuthenticatedAgent = Depends(get_agent),
) -> list[dict[str, Any]]:
    """Read memories from the issuing agent (requires read_memories scope)."""
    _require_agent_scope(agent, "read_memories")

    if space_id:
        _check_agent_space(agent, space_id)

    query = """
        SELECT
            memory_id::TEXT as memory_id,
            space_id::TEXT as space_id,
            tier,
            content,
            participants::TEXT as participants,
            created_at::TEXT as created_at,
            subject_person_id::TEXT as subject_person_id,
            tags,
            scene_context,
            modality,
            confidence,
            related_memory_ids::TEXT[] as related_memory_ids
        FROM memories
        WHERE agent_id = :agent_id::uuid
    """
    params: dict[str, Any] = {"agent_id": agent.issuer_agent_id, "limit": limit}

    if space_id:
        query += " AND space_id = :space_id::uuid"
        params["space_id"] = space_id

    query += " ORDER BY created_at DESC LIMIT :limit"

    rows = _get_db().query(query, params)

    return [
        {
            "memory_id": r["memory_id"],
            "space_id": r.get("space_id"),
            "tier": r.get("tier"),
            "content": r.get("content"),
            "participants": json.loads(r.get("participants") or "[]"),
            "created_at": r.get("created_at"),
            "subject_person_id": r.get("subject_person_id"),
            "tags": r.get("tags") or [],
            "scene_context": r.get("scene_context"),
            "modality": r.get("modality", "text"),
            "confidence": r.get("confidence", 1.0),
            "related_memory_ids": r.get("related_memory_ids") or [],
        }
        for r in rows
    ]


@api_app.get("/v1/delegate/events")
def delegate_read_events(
    space_id: str,
    limit: int = 100,
    agent: AuthenticatedAgent = Depends(get_agent),
) -> list[dict[str, Any]]:
    """Read events from the issuing agent (requires read_events scope)."""
    _require_agent_scope(agent, "read_events")
    _check_agent_space(agent, space_id)

    rows = _get_db().query(
        """
        SELECT
            event_id::TEXT as event_id,
            space_id::TEXT as space_id,
            device_id::TEXT as device_id,
            person_id::TEXT as person_id,
            type,
            payload::TEXT as payload,
            created_at::TEXT as created_at
        FROM events
        WHERE agent_id = :agent_id::uuid
          AND space_id = :space_id::uuid
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"agent_id": agent.issuer_agent_id, "space_id": space_id, "limit": limit},
    )

    return [
        {
            "event_id": r["event_id"],
            "space_id": r.get("space_id"),
            "device_id": r.get("device_id"),
            "person_id": r.get("person_id"),
            "type": r.get("type"),
            "payload": json.loads(r.get("payload") or "{}"),
            "created_at": r.get("created_at"),
        }
        for r in rows
    ]


@api_app.get("/v1/delegate/spaces")
def delegate_list_spaces(
    agent: AuthenticatedAgent = Depends(get_agent),
) -> list[dict[str, Any]]:
    """List spaces belonging to the issuing agent (requires read_spaces scope)."""
    _require_agent_scope(agent, "read_spaces")

    rows = _get_db().query(
        """
        SELECT
            space_id::TEXT as space_id,
            name,
            privacy_mode,
            created_at::TEXT as created_at
        FROM spaces
        WHERE agent_id = :agent_id::uuid
        ORDER BY created_at DESC
        """,
        {"agent_id": agent.issuer_agent_id},
    )

    # Filter by allowed_spaces if set
    result = []
    for r in rows:
        if agent.allowed_spaces is None or r["space_id"] in agent.allowed_spaces:
            result.append(
                {
                    "space_id": r["space_id"],
                    "name": r.get("name"),
                    "privacy_mode": r.get("privacy_mode", False),
                    "created_at": r.get("created_at"),
                }
            )

    return result


class DelegateEventIn(BaseModel):
    """Request body for creating an event via delegation."""

    space_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    person_id: str | None = None


@api_app.post("/v1/delegate/events")
def delegate_write_event(
    body: DelegateEventIn,
    agent: AuthenticatedAgent = Depends(get_agent),
) -> dict[str, Any]:
    """Create an event for the issuing agent (requires write_events scope)."""
    _require_agent_scope(agent, "write_events")
    _check_agent_space(agent, body.space_id)

    event_id = str(uuid.uuid4())

    _get_db().execute(
        """
        INSERT INTO events (event_id, agent_id, space_id, person_id, type, payload)
        VALUES (
            :event_id::uuid,
            :agent_id::uuid,
            :space_id::uuid,
            CASE WHEN :person_id IS NULL THEN NULL ELSE :person_id::uuid END,
            :type,
            :payload::jsonb
        )
        """,
        {
            "event_id": event_id,
            "agent_id": agent.issuer_agent_id,
            "space_id": body.space_id,
            "person_id": body.person_id,
            "type": body.type,
            "payload": json.dumps(body.payload),
        },
    )

    return {"event_id": event_id, "created": True}


class DelegateMemoryIn(BaseModel):
    """Request body for creating a memory via delegation."""

    space_id: str | None = None
    tier: str = "short"
    content: str
    participants: list[str] = Field(default_factory=list)
    subject_person_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    scene_context: str | None = None
    modality: str = "text"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    related_memory_ids: list[str] = Field(default_factory=list)


@api_app.post("/v1/delegate/memories")
def delegate_write_memory(
    body: DelegateMemoryIn,
    agent: AuthenticatedAgent = Depends(get_agent),
) -> dict[str, Any]:
    """Create a memory for the issuing agent (requires write_memories scope)."""
    _require_agent_scope(agent, "write_memories")

    if body.space_id:
        _check_agent_space(agent, body.space_id)

    memory_id = str(uuid.uuid4())
    embedding: str | None = None
    if _cfg.openai_secret_arn:
        try:
            embed_model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
            vec = call_embeddings(
                openai_secret_arn=_cfg.openai_secret_arn,
                model=embed_model,
                text=body.content,
            )
            embedding = "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
        except Exception as e:
            logger.warning("Failed to generate delegate memory embedding (continuing): %s", e)

    _get_db().execute(
        """
        INSERT INTO memories (memory_id, agent_id, space_id, tier, content, participants, embedding,
                              subject_person_id, tags, scene_context, modality, confidence, related_memory_ids)
        VALUES (
            :memory_id::uuid,
            :agent_id::uuid,
            CASE WHEN :space_id IS NULL THEN NULL ELSE :space_id::uuid END,
            :tier,
            :content,
            :participants::jsonb,
            CASE WHEN :embedding IS NULL THEN NULL ELSE CAST(:embedding AS vector) END,
            CASE WHEN :subject_person_id IS NULL THEN NULL ELSE :subject_person_id::uuid END,
            :tags::text[],
            :scene_context,
            :modality,
            :confidence,
            :related_memory_ids::uuid[]
        )
        """,
        {
            "memory_id": memory_id,
            "agent_id": agent.issuer_agent_id,
            "space_id": body.space_id,
            "tier": body.tier,
            "content": body.content,
            "participants": json.dumps(body.participants),
            "embedding": embedding,
            "subject_person_id": body.subject_person_id,
            "tags": "{" + ",".join(body.tags) + "}" if body.tags else "{}",
            "scene_context": body.scene_context,
            "modality": body.modality,
            "confidence": body.confidence,
            "related_memory_ids": "{" + ",".join(body.related_memory_ids) + "}" if body.related_memory_ids else "{}",
        },
    )

    return {"memory_id": memory_id, "created": True}
