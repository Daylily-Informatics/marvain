from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Optional

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from agent_hub.audit import append_audit_entry
from agent_hub.auth import AuthenticatedDevice, authenticate_device, generate_device_token, hash_token
from agent_hub.config import load_config
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


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "stage": _cfg.stage}


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
