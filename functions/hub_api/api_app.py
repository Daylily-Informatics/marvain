"""API-only FastAPI application for Lambda deployment.

This module contains ONLY the programmatic API routes (health, bootstrap, agents,
spaces, devices, memberships, LiveKit tokens). GUI routes are in app.py which
extends this for local development.

Architecture:
- api_app.py (this file): API routes only -> deployed to Lambda
- app.py: API + GUI routes -> local development only
- lambda_handler.py: imports from api_app.py
- run_local.py: imports from app.py
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from typing import Any, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

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
    revoke_agent_token,
)
from agent_hub.config import load_config
from agent_hub.memberships import (
    check_agent_permission,
    claim_first_owner,
    grant_membership,
    list_agents_for_user,
    list_members_for_agent,
    revoke_membership,
    update_membership,
)
from agent_hub.livekit_tokens import mint_livekit_join_token
from agent_hub.policy import is_agent_disabled, is_privacy_mode
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.secrets import get_secret_json

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

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


def _get_db() -> RdsData:
    global _db
    if _db is None:
        _db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
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


class RegisterDeviceOut(BaseModel):
    device_id: str
    device_token: str


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


class LiveKitTokenOut(BaseModel):
    url: str
    token: str
    room: str
    identity: str


class PresignIn(BaseModel):
    filename: str
    content_type: str = Field(default="application/octet-stream")


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


async def _mint_livekit_token_for_user(*, user: AuthenticatedUser, space_id: str) -> LiveKitTokenOut:
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

    # Generate a unique room name for this session - guarantees room creation event
    room_session_id = uuid.uuid4().hex[:12]
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
            _get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id,
            entry_type="agent_created", entry={"user_id": user.user_id, "name": body.name},
        )

    return AgentOut(
        agent_id=agent_id,
        name=body.name,
        role="owner",
        relationship_label=body.relationship_label,
        disabled=False,
    )


@api_app.post("/v1/livekit/token", response_model=LiveKitTokenOut)
async def livekit_token(body: LiveKitTokenIn, user: AuthenticatedUser = Depends(get_user)) -> LiveKitTokenOut:
    """Mint a short-lived LiveKit token for a user to join the room for a space."""
    return await _mint_livekit_token_for_user(user=user, space_id=body.space_id)


@api_app.post("/v1/agents/{agent_id}/claim_owner")
def claim_owner(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    try:
        claim_first_owner(_get_db(), agent_id=agent_id, user_id=user.user_id)
    except PermissionError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id,
            entry_type="owner_claimed", entry={"user_id": user.user_id},
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
            user_pool_id=_cfg.cognito_user_pool_id, email=body.email,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    user_id = ensure_user_row(_get_db(), cognito_sub=cognito_sub, email=(resolved_email or body.email))
    try:
        grant_membership(_get_db(), agent_id=agent_id, user_id=user_id, role=body.role, relationship_label=body.relationship_label)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id, entry_type="member_granted",
            entry={"by_user_id": user.user_id, "user_id": user_id, "cognito_sub": cognito_sub,
                   "email": (resolved_email or body.email), "role": body.role, "relationship_label": body.relationship_label},
        )
    return AgentMemberOut(user_id=user_id, cognito_sub=cognito_sub, email=(resolved_email or body.email),
                          role=body.role, relationship_label=body.relationship_label)


@api_app.patch("/v1/agents/{agent_id}/memberships/{member_user_id}")
def patch_member(agent_id: str, member_user_id: str, body: UpdateMemberIn, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    try:
        update_membership(_get_db(), agent_id=agent_id, user_id=member_user_id, role=body.role, relationship_label=body.relationship_label)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id, entry_type="member_updated",
            entry={"by_user_id": user.user_id, "user_id": member_user_id, "role": body.role},
        )
    return {"ok": True}


@api_app.delete("/v1/agents/{agent_id}/memberships/{member_user_id}")
def delete_member(agent_id: str, member_user_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    revoke_membership(_get_db(), agent_id=agent_id, user_id=member_user_id)
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id, entry_type="member_revoked",
            entry={"by_user_id": user.user_id, "user_id": member_user_id},
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
        """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
           VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)""",
        {"device_id": device_id, "agent_id": body.agent_id, "name": body.name or "device",
         "scopes": json.dumps(body.scopes), "capabilities": json.dumps(body.capabilities), "token_hash": token_hash},
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _get_db(), bucket=_cfg.audit_bucket, agent_id=body.agent_id, entry_type="device_registered",
            entry={"device_id": device_id, "name": body.name, "scopes": body.scopes, "by_user_id": user.user_id},
        )
    return RegisterDeviceOut(device_id=device_id, device_token=token)


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
            {"agent_id": agent_id, "name": body.agent_name}, transaction_id=tx,
        )
        _get_db().execute(
            "INSERT INTO spaces(space_id, agent_id, name, privacy_mode) VALUES (:space_id::uuid, :agent_id::uuid, :name, false)",
            {"space_id": space_id, "agent_id": agent_id, "name": body.default_space_name}, transaction_id=tx,
        )
        _get_db().execute(
            """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
               VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)""",
            {"device_id": device_id, "agent_id": agent_id, "name": "primary",
             "scopes": json.dumps(["events:write", "memory:read", "memory:delete", "spaces:write"]),
             "capabilities": json.dumps({"kind": "admin"}), "token_hash": token_hash}, transaction_id=tx,
        )
        _get_db().commit(tx)
    except Exception:
        _get_db().rollback(tx)
        raise
    if _cfg.audit_bucket:
        append_audit_entry(_get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id,
                           entry_type="bootstrap", entry={"space_id": space_id, "device_id": device_id})
    return BootstrapOut(agent_id=agent_id, space_id=space_id, device_id=device_id, device_token=token)


@api_app.post("/v1/admin/devices/register", response_model=RegisterDeviceOut, dependencies=[Depends(require_admin)])
def admin_register_device(body: RegisterDeviceIn) -> RegisterDeviceOut:
    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)
    _get_db().execute(
        """INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
           VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)""",
        {"device_id": device_id, "agent_id": body.agent_id, "name": body.name or "device",
         "scopes": json.dumps(body.scopes), "capabilities": json.dumps(body.capabilities), "token_hash": token_hash},
    )
    if _cfg.audit_bucket:
        append_audit_entry(_get_db(), bucket=_cfg.audit_bucket, agent_id=body.agent_id,
                           entry_type="device_registered", entry={"device_id": device_id, "name": body.name, "scopes": body.scopes})
    return RegisterDeviceOut(device_id=device_id, device_token=token)


@api_app.post("/v1/admin/spaces/{space_id}/privacy", dependencies=[Depends(require_admin)])
def admin_set_privacy(space_id: str, body: SetPrivacyIn) -> dict[str, Any]:
    rows = _get_db().query("SELECT agent_id::TEXT as agent_id FROM spaces WHERE space_id = :space_id::uuid LIMIT 1", {"space_id": space_id})
    if not rows:
        raise HTTPException(status_code=404, detail="Space not found")
    agent_id = rows[0]["agent_id"]
    _get_db().execute("UPDATE spaces SET privacy_mode = :privacy_mode WHERE space_id = :space_id::uuid",
                      {"space_id": space_id, "privacy_mode": body.privacy_mode})
    if _cfg.audit_bucket:
        append_audit_entry(_get_db(), bucket=_cfg.audit_bucket, agent_id=agent_id,
                           entry_type="privacy_mode_set", entry={"space_id": space_id, "privacy_mode": body.privacy_mode})
    return {"space_id": space_id, "privacy_mode": body.privacy_mode}


@api_app.post("/v1/events", response_model=IngestEventOut)
def ingest_event(body: IngestEventIn, device: AuthenticatedDevice = Depends(get_device)) -> IngestEventOut:
    if is_agent_disabled(_get_db(), device.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")
    if is_privacy_mode(_get_db(), body.space_id):
        return IngestEventOut(event_id="privacy_mode", queued=False)
    event_id = str(uuid.uuid4())
    _get_db().execute(
        """INSERT INTO events(event_id, agent_id, space_id, device_id, person_id, type, payload)
           VALUES (:event_id::uuid, :agent_id::uuid, :space_id::uuid, :device_id::uuid,
                   CASE WHEN :person_id IS NULL THEN NULL ELSE :person_id::uuid END, :type, :payload::jsonb)""",
        {"event_id": event_id, "agent_id": device.agent_id, "space_id": body.space_id, "device_id": device.device_id,
         "person_id": body.person_id, "type": body.type, "payload": json.dumps(body.payload)},
    )
    queued = False
    if body.type == "transcript_chunk" and _cfg.transcript_queue_url:
        _get_sqs().send_message(QueueUrl=_cfg.transcript_queue_url, MessageBody=json.dumps({
            "event_id": event_id, "agent_id": device.agent_id, "space_id": body.space_id, "device_id": device.device_id,
        }))
        queued = True
    if _cfg.audit_bucket:
        append_audit_entry(_get_db(), bucket=_cfg.audit_bucket, agent_id=device.agent_id,
                           entry_type="event_ingested", entry={"event_id": event_id, "type": body.type, "space_id": body.space_id, "queued": queued})
    return IngestEventOut(event_id=event_id, queued=queued)


@api_app.get("/v1/memories")
def list_memories(limit: int = 50, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    limit = max(1, min(200, limit))
    rows = _get_db().query(
        """SELECT memory_id::TEXT as memory_id, tier, content, created_at::TEXT as created_at,
                  participants::TEXT as participants, provenance::TEXT as provenance
           FROM memories WHERE agent_id = :agent_id::uuid ORDER BY created_at DESC LIMIT :limit""",
        {"agent_id": device.agent_id, "limit": limit},
    )
    return {"memories": rows}


@api_app.delete("/v1/memories/{memory_id}")
def delete_memory(memory_id: str, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    _get_db().execute("DELETE FROM memories WHERE memory_id = :memory_id::uuid AND agent_id = :agent_id::uuid",
                      {"memory_id": memory_id, "agent_id": device.agent_id})
    if _cfg.audit_bucket:
        append_audit_entry(_get_db(), bucket=_cfg.audit_bucket, agent_id=device.agent_id,
                           entry_type="memory_deleted", entry={"memory_id": memory_id})
    return {"deleted": True, "memory_id": memory_id}


@api_app.post("/v1/artifacts/presign")
def presign_upload(body: PresignIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    if not _cfg.artifact_bucket:
        raise HTTPException(status_code=500, detail="Artifact bucket not configured")
    key = f"artifacts/agent_id={device.agent_id}/{uuid.uuid4()}_{body.filename}"
    url = _get_s3().generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": _cfg.artifact_bucket, "Key": key, "ContentType": body.content_type},
        ExpiresIn=900,
    )
    return {"upload_url": url, "bucket": _cfg.artifact_bucket, "key": key}


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
            created_at::TEXT as created_at
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
            result.append({
                "space_id": r["space_id"],
                "name": r.get("name"),
                "privacy_mode": r.get("privacy_mode", False),
                "created_at": r.get("created_at"),
            })

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

    _get_db().execute(
        """
        INSERT INTO memories (memory_id, agent_id, space_id, tier, content, participants)
        VALUES (
            :memory_id::uuid,
            :agent_id::uuid,
            CASE WHEN :space_id IS NULL THEN NULL ELSE :space_id::uuid END,
            :tier,
            :content,
            :participants::jsonb
        )
        """,
        {
            "memory_id": memory_id,
            "agent_id": agent.issuer_agent_id,
            "space_id": body.space_id,
            "tier": body.tier,
            "content": body.content,
            "participants": json.dumps(body.participants),
        },
    )

    return {"memory_id": memory_id, "created": True}

