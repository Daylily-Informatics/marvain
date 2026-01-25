from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.responses import Response

from agent_hub.audit import append_audit_entry
from agent_hub.auth import (
    AuthenticatedDevice,
    AuthenticatedUser,
    authenticate_device,
    authenticate_user_access_token,
    ensure_user_row,
    generate_device_token,
    hash_token,
    lookup_cognito_user_by_email,
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

app = FastAPI(title="AgentHub")

_cfg = load_config()
_db = RdsData(RdsDataEnv(resource_arn=_cfg.db_resource_arn, secret_arn=_cfg.db_secret_arn, database=_cfg.db_name))
_sqs = boto3.client("sqs")
_s3 = boto3.client("s3")


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
    dev = authenticate_device(_db, token)
    if not dev:
        raise HTTPException(status_code=401, detail="Invalid device token")
    return dev


def get_user(request: Request) -> AuthenticatedUser:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    try:
        return authenticate_user_access_token(_db, token)
    except PermissionError:
        raise HTTPException(status_code=401, detail="Invalid access token")


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
    cognito_sub: str
    email: str | None = None


class AgentOut(BaseModel):
    agent_id: str
    name: str
    role: str
    relationship_label: str | None = None
    disabled: bool


class AgentMemberOut(BaseModel):
    user_id: str
    cognito_sub: str
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


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "stage": _cfg.stage}


@app.get("/v1/me", response_model=MeOut)
def me(user: AuthenticatedUser = Depends(get_user)) -> MeOut:
    return MeOut(user_id=user.user_id, cognito_sub=user.cognito_sub, email=user.email)


@app.get("/v1/agents", response_model=dict[str, list[AgentOut]])
def agents(user: AuthenticatedUser = Depends(get_user)) -> dict[str, list[AgentOut]]:
    memberships = list_agents_for_user(_db, user_id=user.user_id)
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


def _require_agent_role(*, user: AuthenticatedUser, agent_id: str, required_role: str) -> None:
    if not check_agent_permission(_db, agent_id=agent_id, user_id=user.user_id, required_role=required_role):
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
        rows = _db.query(
            "SELECT agent_id::text AS agent_id FROM spaces WHERE space_id = CAST(:space_id AS uuid)",
            params={"space_id": str(space_id)},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to look up space: {e}")

    if not rows:
        return None
    v = rows[0].get("agent_id")
    if not v:
        return None
    return str(v)


def _mint_livekit_token(*, user: AuthenticatedUser, space_id: str) -> LiveKitTokenOut:
    agent_id = _space_agent_id(space_id=space_id)
    if not agent_id:
        raise HTTPException(status_code=404, detail="Space not found")

    if not check_agent_permission(_db, agent_id=agent_id, user_id=user.user_id, required_role="member"):
        raise HTTPException(status_code=403, detail="Forbidden")

    url, api_key, api_secret = _require_livekit_config()

    # Prefix to avoid collisions with device identities.
    identity = f"user:{user.user_id}"
    room = str(space_id)
    token = mint_livekit_join_token(
        api_key=api_key,
        api_secret=api_secret,
        identity=identity,
        room=room,
        name=(user.email or user.user_id),
        ttl_seconds=3600,
    )
    return LiveKitTokenOut(url=url, token=token, room=room, identity=identity)


@app.post("/v1/livekit/token", response_model=LiveKitTokenOut)
def livekit_token(body: LiveKitTokenIn, user: AuthenticatedUser = Depends(get_user)) -> LiveKitTokenOut:
    """Mint a short-lived LiveKit token for a user to join the room for a space."""
    return _mint_livekit_token(user=user, space_id=body.space_id)


@app.post("/v1/agents/{agent_id}/claim_owner")
def claim_owner(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    try:
        claim_first_owner(_db, agent_id=agent_id, user_id=user.user_id)
    except PermissionError as e:
        raise HTTPException(status_code=409, detail=str(e))

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="owner_claimed",
            entry={"user_id": user.user_id},
        )
    return {"agent_id": agent_id, "user_id": user.user_id, "role": "owner"}


@app.get("/v1/agents/{agent_id}/memberships", response_model=dict[str, list[AgentMemberOut]])
def list_members(agent_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, list[AgentMemberOut]]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="member")
    members = list_members_for_agent(_db, agent_id=agent_id, include_revoked=False)
    return {
        "memberships": [
            AgentMemberOut(
                user_id=m.user_id,
                cognito_sub=m.cognito_sub,
                email=m.email,
                role=m.role,
                relationship_label=m.relationship_label,
            )
            for m in members
        ]
    }


@app.post("/v1/agents/{agent_id}/memberships", response_model=AgentMemberOut)
def add_member(agent_id: str, body: GrantMemberIn, user: AuthenticatedUser = Depends(get_user)) -> AgentMemberOut:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    if not _cfg.cognito_user_pool_id:
        raise HTTPException(status_code=500, detail="COGNITO_USER_POOL_ID not configured")
    try:
        cognito_sub, email = lookup_cognito_user_by_email(user_pool_id=_cfg.cognito_user_pool_id, email=body.email)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))

    target_user_id = ensure_user_row(_db, cognito_sub=cognito_sub, email=email)
    try:
        grant_membership(
            _db,
            agent_id=agent_id,
            user_id=target_user_id,
            role=body.role,
            relationship_label=body.relationship_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_granted",
            entry={"by_user_id": user.user_id, "user_id": target_user_id, "email": email, "role": body.role},
        )

    return AgentMemberOut(
        user_id=target_user_id,
        cognito_sub=cognito_sub,
        email=email,
        role=str(body.role),
        relationship_label=body.relationship_label,
    )


@app.patch("/v1/agents/{agent_id}/memberships/{member_user_id}")
def patch_member(
    agent_id: str,
    member_user_id: str,
    body: UpdateMemberIn,
    user: AuthenticatedUser = Depends(get_user),
) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    try:
        update_membership(
            _db,
            agent_id=agent_id,
            user_id=member_user_id,
            role=body.role,
            relationship_label=body.relationship_label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_updated",
            entry={"by_user_id": user.user_id, "user_id": member_user_id, "role": body.role},
        )
    return {"ok": True}


@app.delete("/v1/agents/{agent_id}/memberships/{member_user_id}")
def delete_member(agent_id: str, member_user_id: str, user: AuthenticatedUser = Depends(get_user)) -> dict[str, Any]:
    _require_agent_role(user=user, agent_id=agent_id, required_role="admin")
    revoke_membership(_db, agent_id=agent_id, user_id=member_user_id)
    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_revoked",
            entry={"by_user_id": user.user_id, "user_id": member_user_id},
        )
    return {"ok": True}


@app.post("/v1/devices/register", response_model=RegisterDeviceOut)
def register_device(body: RegisterDeviceIn, user: AuthenticatedUser = Depends(get_user)) -> RegisterDeviceOut:
    # Only admin/owner can mint new device tokens.
    _require_agent_role(user=user, agent_id=body.agent_id, required_role="admin")

    # Global kill switch
    if is_agent_disabled(_db, body.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)

    _db.execute(
        """
        INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
        VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)
        """,
        {
            "device_id": device_id,
            "agent_id": body.agent_id,
            "name": body.name or "device",
            "scopes": json.dumps(body.scopes),
            "capabilities": json.dumps(body.capabilities),
            "token_hash": token_hash,
        },
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=body.agent_id,
            entry_type="device_registered",
            entry={"device_id": device_id, "name": body.name, "scopes": body.scopes, "by_user_id": user.user_id},
        )

    return RegisterDeviceOut(device_id=device_id, device_token=token)


@app.post("/v1/admin/bootstrap", response_model=BootstrapOut, dependencies=[Depends(require_admin)])
def admin_bootstrap(body: BootstrapIn) -> BootstrapOut:
    agent_id = str(uuid.uuid4())
    space_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())

    token = generate_device_token()
    token_hash = hash_token(token)

    tx = _db.begin()
    try:
        _db.execute(
            """
            INSERT INTO agents(agent_id, name, disabled)
            VALUES (:agent_id::uuid, :name, false)
            """,
            {"agent_id": agent_id, "name": body.agent_name},
            transaction_id=tx,
        )
        _db.execute(
            """
            INSERT INTO spaces(space_id, agent_id, name, privacy_mode)
            VALUES (:space_id::uuid, :agent_id::uuid, :name, false)
            """,
            {"space_id": space_id, "agent_id": agent_id, "name": body.default_space_name},
            transaction_id=tx,
        )
        _db.execute(
            """
            INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
            VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)
            """,
            {
                "device_id": device_id,
                "agent_id": agent_id,
                "name": "primary",
                "scopes": json.dumps(["events:write", "memory:read", "memory:delete", "spaces:write"]),
                "capabilities": json.dumps({"kind": "admin"}),
                "token_hash": token_hash,
            },
            transaction_id=tx,
        )
        _db.commit(tx)
    except Exception:
        _db.rollback(tx)
        raise

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="bootstrap",
            entry={"space_id": space_id, "device_id": device_id},
        )

    return BootstrapOut(agent_id=agent_id, space_id=space_id, device_id=device_id, device_token=token)


@app.post("/v1/admin/devices/register", response_model=RegisterDeviceOut, dependencies=[Depends(require_admin)])
def admin_register_device(body: RegisterDeviceIn) -> RegisterDeviceOut:
    device_id = str(uuid.uuid4())
    token = generate_device_token()
    token_hash = hash_token(token)

    _db.execute(
        """
        INSERT INTO devices(device_id, agent_id, name, scopes, capabilities, token_hash)
        VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :capabilities::jsonb, :token_hash)
        """,
        {
            "device_id": device_id,
            "agent_id": body.agent_id,
            "name": body.name or "device",
            "scopes": json.dumps(body.scopes),
            "capabilities": json.dumps(body.capabilities),
            "token_hash": token_hash,
        },
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=body.agent_id,
            entry_type="device_registered",
            entry={"device_id": device_id, "name": body.name, "scopes": body.scopes},
        )

    return RegisterDeviceOut(device_id=device_id, device_token=token)


@app.post("/v1/admin/spaces/{space_id}/privacy", dependencies=[Depends(require_admin)])
def admin_set_privacy(space_id: str, body: SetPrivacyIn) -> dict[str, Any]:
    rows = _db.query(
        """
        SELECT agent_id::TEXT as agent_id
        FROM spaces
        WHERE space_id = :space_id::uuid
        LIMIT 1
        """,
        {"space_id": space_id},
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Space not found")
    agent_id = rows[0]["agent_id"]

    _db.execute(
        """
        UPDATE spaces
        SET privacy_mode = :privacy_mode
        WHERE space_id = :space_id::uuid
        """,
        {"space_id": space_id, "privacy_mode": body.privacy_mode},
    )

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="privacy_mode_set",
            entry={"space_id": space_id, "privacy_mode": body.privacy_mode},
        )

    return {"space_id": space_id, "privacy_mode": body.privacy_mode}


@app.post("/v1/events", response_model=IngestEventOut)
def ingest_event(body: IngestEventIn, device: AuthenticatedDevice = Depends(get_device)) -> IngestEventOut:
    # Global kill switch
    if is_agent_disabled(_db, device.agent_id):
        raise HTTPException(status_code=403, detail="Agent is disabled")

    # Privacy mode gate
    if is_privacy_mode(_db, body.space_id):
        return IngestEventOut(event_id="privacy_mode", queued=False)

    event_id = str(uuid.uuid4())
    _db.execute(
        """
        INSERT INTO events(event_id, agent_id, space_id, device_id, person_id, type, payload)
        VALUES (
          :event_id::uuid,
          :agent_id::uuid,
          :space_id::uuid,
          :device_id::uuid,
          CASE WHEN :person_id IS NULL THEN NULL ELSE :person_id::uuid END,
          :type,
          :payload::jsonb
        )
        """,
        {
            "event_id": event_id,
            "agent_id": device.agent_id,
            "space_id": body.space_id,
            "device_id": device.device_id,
            "person_id": body.person_id,
            "type": body.type,
            "payload": json.dumps(body.payload),
        },
    )

    queued = False
    if body.type == "transcript_chunk" and _cfg.transcript_queue_url:
        _sqs.send_message(
            QueueUrl=_cfg.transcript_queue_url,
            MessageBody=json.dumps(
                {
                    "event_id": event_id,
                    "agent_id": device.agent_id,
                    "space_id": body.space_id,
                    "device_id": device.device_id,
                }
            ),
        )
        queued = True

    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=device.agent_id,
            entry_type="event_ingested",
            entry={"event_id": event_id, "type": body.type, "space_id": body.space_id, "queued": queued},
        )

    return IngestEventOut(event_id=event_id, queued=queued)


@app.get("/v1/memories")
def list_memories(limit: int = 50, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    limit = max(1, min(200, limit))
    rows = _db.query(
        """
        SELECT memory_id::TEXT as memory_id,
               tier,
               content,
               created_at::TEXT as created_at,
               participants::TEXT as participants,
               provenance::TEXT as provenance
        FROM memories
        WHERE agent_id = :agent_id::uuid
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"agent_id": device.agent_id, "limit": limit},
    )
    return {"memories": rows}


@app.delete("/v1/memories/{memory_id}")
def delete_memory(memory_id: str, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    _db.execute(
        """
        DELETE FROM memories
        WHERE memory_id = :memory_id::uuid AND agent_id = :agent_id::uuid
        """,
        {"memory_id": memory_id, "agent_id": device.agent_id},
    )
    if _cfg.audit_bucket:
        append_audit_entry(
            _db,
            bucket=_cfg.audit_bucket,
            agent_id=device.agent_id,
            entry_type="memory_deleted",
            entry={"memory_id": memory_id},
        )
    return {"deleted": True, "memory_id": memory_id}


class PresignIn(BaseModel):
    filename: str
    content_type: str = Field(default="application/octet-stream")


@app.post("/v1/artifacts/presign")
def presign_upload(body: PresignIn, device: AuthenticatedDevice = Depends(get_device)) -> dict[str, Any]:
    if not _cfg.artifact_bucket:
        raise HTTPException(status_code=500, detail="Artifact bucket not configured")
    key = f"artifacts/agent_id={device.agent_id}/{uuid.uuid4()}_{body.filename}"
    url = _s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": _cfg.artifact_bucket, "Key": key, "ContentType": body.content_type},
        ExpiresIn=900,
    )
    return {"upload_url": url, "bucket": _cfg.artifact_bucket, "key": key}


# -----------------------------
# Public GUI (server-rendered)
# -----------------------------

_GUI_ACCESS_TOKEN_COOKIE = "marvain_access_token"
_GUI_OAUTH_STATE_COOKIE = "marvain_oauth_state"
_GUI_OAUTH_VERIFIER_COOKIE = "marvain_oauth_verifier"
_GUI_OAUTH_NEXT_COOKIE = "marvain_oauth_next"


def _cookie_secure(request: Request) -> bool:
    # In Lambda behind API Gateway we expect HTTPS; in local dev/tests use http.
    try:
        return str(request.url.scheme).lower() == "https"
    except Exception:
        return False


def _cognito_hosted_ui_base_url() -> str:
    """Return https://<domain>.auth.<region>.amazoncognito.com (no trailing slash)."""
    dom = str(_cfg.cognito_domain or "").strip()
    if not dom:
        raise RuntimeError("COGNITO_DOMAIN not configured")

    if dom.startswith("https://") or dom.startswith("http://"):
        return dom.rstrip("/")

    # Support passing the full hostname (without scheme) or just the domain prefix.
    if ".auth." in dom and "amazoncognito.com" in dom:
        return f"https://{dom}".rstrip("/")

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-west-2"
    return f"https://{dom}.auth.{region}.amazoncognito.com".rstrip("/")


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256."""
    # RFC 7636: verifier should be 43..128 chars. We use 32 random bytes (~43 chars base64url).
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


def _cognito_exchange_code_for_tokens(*, code: str, redirect_uri: str, code_verifier: str) -> dict[str, Any]:
    base = _cognito_hosted_ui_base_url()
    url = f"{base}/oauth2/token"

    client_id = str(_cfg.cognito_user_pool_client_id or "").strip()
    if not client_id:
        raise RuntimeError("COGNITO_APP_CLIENT_ID/COGNITO_USER_POOL_CLIENT_ID not configured")

    form = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": str(code),
        "redirect_uri": str(redirect_uri),
        "code_verifier": str(code_verifier),
    }
    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")
        except Exception:
            body = ""
        raise RuntimeError(f"token exchange failed: HTTP {e.code} {body}")

    try:
        return json.loads(payload)
    except Exception as e:
        raise RuntimeError(f"token exchange returned invalid json: {e}")


def _safe_next_path(next_path: str | None) -> str:
    """Return a safe relative path to redirect to after login.

    We only allow absolute-path relative URLs like "/profile".
    """
    nxt = str(next_path or "").strip()
    if not nxt:
        return "/"
    if not nxt.startswith("/"):
        return "/"
    if nxt.startswith("//"):
        return "/"
    # Prevent obvious scheme-like or header injection forms.
    if ":" in nxt or "\r" in nxt or "\n" in nxt:
        return "/"
    return nxt


def _gui_path(request: Request, path: str) -> str:
    """Prefix `path` with ASGI root_path (e.g. API Gateway stage).

    Starlette/FastAPI do not automatically apply `root_path` to string URLs like
    "/login". We do it explicitly so redirects/links work behind stage-based
    deployments.
    """

    root = str(request.scope.get("root_path") or "")
    if not root:
        return path
    if root.endswith("/") and path.startswith("/"):
        return root[:-1] + path
    return root + path


def _safe_next_app_path(request: Request, next_path: str | None) -> str:
    """Return a safe app-internal path (no root_path prefix) for the `next` param."""

    nxt = _safe_next_path(next_path)
    root = str(request.scope.get("root_path") or "")
    if root and nxt.startswith(root):
        # Strip root_path if a caller included it.
        nxt = nxt[len(root) :] or "/"
        if not nxt.startswith("/"):
            nxt = "/" + nxt
        nxt = _safe_next_path(nxt)
    return nxt


def _encode_next_cookie(path: str) -> str:
    """Encode a normalized next-path for safe storage in a cookie."""
    # Path is already normalized by _safe_next_app_path; we further make it opaque.
    data = path.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii")


def _decode_next_cookie(value: Optional[str]) -> str:
    """Decode a next-path from cookie storage, falling back to root on error."""
    if not value:
        return "/"
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"), validate=True)
        path = raw.decode("utf-8", errors="strict")
    except Exception:
        return "/"
    # Re-apply safety normalization to be defensive.
    return _safe_next_path(path)


def _gui_get_user(request: Request) -> AuthenticatedUser | None:
    tok = request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or ""
    tok = str(tok).strip()
    if not tok:
        return None
    try:
        return authenticate_user_access_token(_db, tok)
    except PermissionError:
        return None


def _gui_redirect_to_login(*, request: Request, next_path: str | None = None, clear_session: bool = False) -> Response:
    qs = urllib.parse.urlencode({"next": _safe_next_app_path(request, next_path)})
    resp: Response = RedirectResponse(url=f"{_gui_path(request, '/login')}?{qs}", status_code=302)
    if clear_session:
        resp.delete_cookie(_GUI_ACCESS_TOKEN_COOKIE, path="/")
    return resp


def _gui_html_page(*, title: str, body_html: str) -> HTMLResponse:
    # Minimal HTML; no templating dependency in Phase 4.
    t = html.escape(title)
    doc = (
        "<!doctype html>\n"
        "<html><head><meta charset='utf-8'>"
        f"<title>{t}</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "</head><body style='font-family: system-ui, -apple-system, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem;'>"
        f"{body_html}"
        "</body></html>"
    )
    return HTMLResponse(content=doc)


def _gui_error_page(*, request: Request, title: str, message: str, status_code: int = 400) -> HTMLResponse:
    login_href = html.escape(_gui_path(request, "/login"))
    body = (
        f"<h1>{html.escape(title)}</h1>"
        f"<p>{html.escape(message)}</p>"
        f"<p><a href='{login_href}'>Log in</a></p>"
    )
    resp = _gui_html_page(title=title, body_html=body)
    resp.status_code = status_code
    return resp


@app.get("/login", name="login")
def gui_login(request: Request, next: str | None = None) -> RedirectResponse:
    # Redirect to Cognito Hosted UI using OAuth2 code flow + PKCE.
    state = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    redirect_uri = str(request.url_for("auth_callback"))

    base = _cognito_hosted_ui_base_url()
    client_id = str(_cfg.cognito_user_pool_client_id or "").strip()
    if not client_id:
        raise HTTPException(status_code=500, detail="COGNITO client id not configured")

    qs = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
        }
    )
    url = f"{base}/oauth2/authorize?{qs}"

    resp = RedirectResponse(url=url, status_code=302)
    secure = _cookie_secure(request)
    safe_next = _safe_next_app_path(request, next)
    encoded_next = _encode_next_cookie(safe_next)
    resp.set_cookie(
        _GUI_OAUTH_STATE_COOKIE,
        state,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=600,
    )
    resp.set_cookie(
        _GUI_OAUTH_VERIFIER_COOKIE,
        verifier,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=600,
    )
    resp.set_cookie(
        _GUI_OAUTH_NEXT_COOKIE,
        encoded_next,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=600,
    )
    return resp


@app.get("/auth/callback", name="auth_callback")
def gui_auth_callback(request: Request, code: str | None = None, state: str | None = None) -> Response:
    # Always clear transient oauth cookies on the way out.
    def _clear_oauth_cookies(r: Response) -> Response:
        r.delete_cookie(_GUI_OAUTH_STATE_COOKIE, path="/")
        r.delete_cookie(_GUI_OAUTH_VERIFIER_COOKIE, path="/")
        r.delete_cookie(_GUI_OAUTH_NEXT_COOKIE, path="/")
        return r

    if not code:
        return _clear_oauth_cookies(
            _gui_error_page(request=request, title="Login error", message="missing code", status_code=400)
        )
    if not state:
        return _clear_oauth_cookies(
            _gui_error_page(request=request, title="Login error", message="missing state", status_code=400)
        )

    exp_state = str(request.cookies.get(_GUI_OAUTH_STATE_COOKIE) or "")
    verifier = str(request.cookies.get(_GUI_OAUTH_VERIFIER_COOKIE) or "")
    next_path = _safe_next_app_path(request, request.cookies.get(_GUI_OAUTH_NEXT_COOKIE))
    if not exp_state or not verifier or state != exp_state:
        return _clear_oauth_cookies(
            _gui_error_page(request=request, title="Login error", message="invalid state", status_code=400)
        )

    redirect_uri = str(request.url_for("auth_callback"))
    try:
        tok = _cognito_exchange_code_for_tokens(code=code, redirect_uri=redirect_uri, code_verifier=verifier)
    except Exception as e:
        return _clear_oauth_cookies(
            _gui_error_page(request=request, title="Login error", message=f"token exchange failed: {e}", status_code=400)
        )

    access_token = str(tok.get("access_token") or "").strip()
    if not access_token:
        return _clear_oauth_cookies(
            _gui_error_page(request=request, title="Login error", message="missing access_token", status_code=400)
        )

    resp: Response = RedirectResponse(url=_gui_path(request, next_path), status_code=302)
    resp.headers["Cache-Control"] = "no-store"
    secure = _cookie_secure(request)

    max_age: int | None = None
    try:
        exp = int(tok.get("expires_in") or 0)
        if exp > 0:
            max_age = exp
    except Exception:
        max_age = None

    resp.set_cookie(
        _GUI_ACCESS_TOKEN_COOKIE,
        access_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
        max_age=max_age,
    )
    return _clear_oauth_cookies(resp)


@app.get("/logout", name="logout")
def gui_logout(request: Request, cognito: bool = True) -> Response:
    """Clear local session cookie; optionally also sign out of Cognito Hosted UI."""
    if cognito:
        base = _cognito_hosted_ui_base_url()
        client_id = str(_cfg.cognito_user_pool_client_id or "").strip()
        logout_uri = str(request.url_for("logged_out"))
        qs = urllib.parse.urlencode({"client_id": client_id, "logout_uri": logout_uri})
        url = f"{base}/logout?{qs}"
        resp: Response = RedirectResponse(url=url, status_code=302)
    else:
        resp = RedirectResponse(url=_gui_path(request, "/logged-out"), status_code=302)

    # Always clear local cookies.
    resp.delete_cookie(_GUI_ACCESS_TOKEN_COOKIE, path="/")
    resp.delete_cookie(_GUI_OAUTH_STATE_COOKIE, path="/")
    resp.delete_cookie(_GUI_OAUTH_VERIFIER_COOKIE, path="/")
    resp.delete_cookie(_GUI_OAUTH_NEXT_COOKIE, path="/")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/logged-out", name="logged_out")
def gui_logged_out(request: Request) -> HTMLResponse:
    login_href = html.escape(_gui_path(request, "/login"))
    return _gui_html_page(title="Logged out", body_html=f"<h1>Logged out</h1><p><a href='{login_href}'>Log in</a></p>")


@app.get("/", name="home")
def gui_home(request: Request) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    agents = list_agents_for_user(_db, user_id=user.user_id)
    items = []
    for a in agents:
        name = html.escape(a.name)
        agent_href = html.escape(_gui_path(request, f"/agents/{a.agent_id}"))
        items.append(
            "<li>"
            f"<a href='{agent_href}'>{name}</a> "
            f"<small>(role={html.escape(a.role)}{' disabled' if a.disabled else ''})</small>"
            "</li>"
        )

    email = html.escape(user.email or "")
    profile_href = html.escape(_gui_path(request, "/profile"))
    livekit_href = html.escape(_gui_path(request, "/livekit-test"))
    logout_href = html.escape(_gui_path(request, "/logout"))
    body = (
        "<div style='display:flex; justify-content:space-between; align-items:center;'>"
        "<h1>Marvain</h1>"
        f"<div><a href='{profile_href}'>Profile</a> | <a href='{livekit_href}'>LiveKit test</a> | <a href='{logout_href}'>Logout</a></div>"
        "</div>"
        f"<p>Signed in as <code>{email}</code></p>"
        "<h2>Your agents</h2>"
        + ("<ul>" + "".join(items) + "</ul>" if items else "<p>No agents yet.</p>")
    )
    return _gui_html_page(title="Marvain", body_html=body)


@app.get("/profile", name="profile")
def gui_profile(request: Request) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    home_href = html.escape(_gui_path(request, "/"))
    logout_href = html.escape(_gui_path(request, "/logout"))
    body = (
        "<div style='display:flex; justify-content:space-between; align-items:center;'>"
        "<h1>Profile</h1>"
        f"<div><a href='{home_href}'>Home</a> | <a href='{logout_href}'>Logout</a></div>"
        "</div>"
        f"<p>User ID: <code>{html.escape(user.user_id)}</code></p>"
        f"<p>Email: <code>{html.escape(user.email or '')}</code></p>"
        f"<p>Cognito sub: <code>{html.escape(user.cognito_sub)}</code></p>"
    )
    return _gui_html_page(title="Profile", body_html=body)


@app.get("/livekit-test", name="livekit_test")
def gui_livekit_test(request: Request, space_id: str | None = None) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    home_href = html.escape(_gui_path(request, "/"))
    logout_href = html.escape(_gui_path(request, "/logout"))
    token_url = _gui_path(request, "/livekit/token")
    body = (
        "<div style='display:flex; justify-content:space-between; align-items:center;'>"
        "<h1>LiveKit test</h1>"
        f"<div><a href='{home_href}'>Home</a> | <a href='{logout_href}'>Logout</a></div>"
        "</div>"
        "<p>Join a LiveKit room mapped from a Marvain <code>space_id</code>.</p>"
        "<p><label>space_id: <input id='space_id' size='40' /></label> "
        "<button id='join'>Join</button> <button id='leave'>Leave</button></p>"
        "<pre id='status' style='background:#111; color:#eee; padding:12px; border-radius:8px;'>idle</pre>"
        "<script src='https://cdn.jsdelivr.net/npm/livekit-client/dist/livekit-client.umd.min.js'></script>"
        "<script>\n"
        "(function(){\n"
        "  var room = null;\n"
        "  var statusEl = document.getElementById('status');\n"
        "  var inputEl = document.getElementById('space_id');\n"
        f"  inputEl.value = {json.dumps(sid)};\n"
        f"  var tokenUrl = {json.dumps(token_url)};\n"
        "  function setStatus(s){ statusEl.textContent = s; }\n"
        "  async function join(){\n"
        "    var spaceId = (inputEl.value||'').trim();\n"
        "    if(!spaceId){ setStatus('missing space_id'); return; }\n"
        "    setStatus('requesting token...');\n"
        "    var resp = await fetch(tokenUrl, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({space_id: spaceId})});\n"
        "    if(!resp.ok){ setStatus('token request failed: '+resp.status); return; }\n"
        "    var data = await resp.json();\n"
        "    setStatus('connecting to '+data.url+' ...');\n"
        "    var lk = window.livekit || window.LiveKit || window.LivekitClient;\n"
        "    if(!lk || !lk.Room){ setStatus('livekit client not loaded'); return; }\n"
        "    room = new lk.Room();\n"
        "    room.on('disconnected', function(){ setStatus('disconnected'); });\n"
        "    await room.connect(data.url, data.token);\n"
        "    setStatus('connected room='+data.room+' identity='+data.identity);\n"
        "  }\n"
        "  async function leave(){\n"
        "    if(room){ try{ await room.disconnect(); }catch(e){} room = null; }\n"
        "    setStatus('left');\n"
        "  }\n"
        "  document.getElementById('join').addEventListener('click', function(){ join().catch(function(e){ setStatus('join error: '+e); }); });\n"
        "  document.getElementById('leave').addEventListener('click', function(){ leave().catch(function(e){ setStatus('leave error: '+e); }); });\n"
        "})();\n"
        "</script>"
    )
    return _gui_html_page(title="LiveKit test", body_html=body)


@app.post("/livekit/token", response_model=LiveKitTokenOut)
def gui_livekit_token(request: Request, body: LiveKitTokenIn) -> LiveKitTokenOut:
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _mint_livekit_token(user=user, space_id=body.space_id)


@app.get("/agents/{agent_id}", name="agent_detail")
def gui_agent_detail(request: Request, agent_id: str) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    # Ensure the user can see this agent by filtering their memberships.
    agents = list_agents_for_user(_db, user_id=user.user_id)
    match = next((a for a in agents if a.agent_id == agent_id), None)
    if not match:
        return PlainTextResponse("not found", status_code=404)

    role = html.escape(match.role)
    name = html.escape(match.name)
    home_href = html.escape(_gui_path(request, "/"))
    logout_href = html.escape(_gui_path(request, "/logout"))
    body = (
        "<div style='display:flex; justify-content:space-between; align-items:center;'>"
        f"<h1>{name}</h1>"
        f"<div><a href='{home_href}'>Home</a> | <a href='{logout_href}'>Logout</a></div>"
        "</div>"
        f"<p>Agent ID: <code>{html.escape(match.agent_id)}</code></p>"
        f"<p>Your role: <code>{role}</code></p>"
    )
    return _gui_html_page(title=f"Agent {match.name}", body_html=body)
