"""Send selected satellite evidence through the authenticated hub artifact path."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any
from urllib.parse import quote

import aiohttp


async def upload_artifact(
    *, rest_url: str, device_token: str, agent_id: str, space_id: str,
    session_id: str, upload_ttl_seconds: int, filename: str, media_type: str, data: bytes,
) -> dict[str, Any]:
    """Create the owning intent and upload bytes once; return its persisted receipt."""
    if not agent_id or not session_id:
        raise ValueError("bound agent_id and session_id are required for artifact upload")
    if not isinstance(upload_ttl_seconds, int) or isinstance(upload_ttl_seconds, bool):
        raise ValueError("artifact_upload_ttl_seconds must be explicitly configured")
    digest = hashlib.sha256(data).hexdigest()
    base = rest_url.rstrip("/")
    authorization = {"Authorization": f"Bearer {device_token}"}
    intent = {
        "idempotency_key": str(uuid.uuid4()),
        "agent_id": agent_id,
        "purpose": "recognition",
        "filename": filename,
        "media_type": media_type,
        "expected_sha256": digest,
        "expected_byte_count": len(data),
        "upload_ttl_seconds": upload_ttl_seconds,
        "space_id": space_id,
        "session_id": session_id,
        "upload_via_hub": True,
    }
    async with aiohttp.ClientSession() as client:
        async with client.post(f"{base}/v1/artifacts/upload-intents", headers=authorization, json=intent) as response:
            response.raise_for_status()
            created = await response.json()
        artifact_id = str(created.get("artifact_id") or "").strip()
        if not artifact_id:
            raise RuntimeError("artifact upload intent response missing artifact_id")
        headers = {**authorization, "Content-Type": media_type}
        async with client.put(
            f"{base}/v1/artifacts/{quote(artifact_id, safe='')}/upload", headers=headers, data=data
        ) as response:
            response.raise_for_status()
            receipt = await response.json()
    return receipt
