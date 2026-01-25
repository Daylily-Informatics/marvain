from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _jwt_hs256(*, header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    # JWT base64url encoding uses no padding.
    header_b64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    msg = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_b64 = _b64url(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def mint_livekit_join_token(
    *,
    api_key: str,
    api_secret: str,
    identity: str,
    room: str,
    name: str | None = None,
    ttl_seconds: int = 3600,
    can_publish: bool = True,
    can_subscribe: bool = True,
    can_publish_data: bool = True,
) -> str:
    """Mint a LiveKit access token (JWT) for joining a room.

    Ref: LiveKit token structure (HS256), with `video` grants.
    """
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": str(api_key),
        "sub": str(identity),
        # Allow tiny clock skew.
        "nbf": now - 1,
        "exp": now + int(ttl_seconds),
        "video": {
            "room": str(room),
            "roomJoin": True,
            "canPublish": bool(can_publish),
            "canSubscribe": bool(can_subscribe),
            "canPublishData": bool(can_publish_data),
        },
    }
    if name:
        payload["name"] = str(name)

    header = {"alg": "HS256", "typ": "JWT"}
    return _jwt_hs256(header=header, payload=payload, secret=str(api_secret))
