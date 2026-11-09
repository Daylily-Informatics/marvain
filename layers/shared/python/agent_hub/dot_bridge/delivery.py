"""Standard Webhooks signing and HTTPS callback transport for MCP Events."""

from __future__ import annotations

import base64
import binascii
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4


class CallbackError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class EventDeliveryRetry(RuntimeError):
    """Committed canonical work with pending event transport."""

    def __init__(self, *, canonical_result: dict[str, Any]) -> None:
        super().__init__("A committed Marvain handoff has pending webhook delivery")
        self.canonical_result = canonical_result


def signing_key(secret: str) -> bytes:
    if not secret.startswith("whsec_"):
        raise ValueError("The webhook secret must use the whsec_ format")
    encoded = secret.removeprefix("whsec_")
    try:
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("The webhook secret is not valid base64") from exc
    if not 24 <= len(key) <= 64:
        raise ValueError("The webhook signing key must contain 24–64 bytes")
    return key


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, *, timeout: float) -> None:
        super().__init__(host, port=443, timeout=timeout)
        self.address = address
        self.tls = ssl.create_default_context()

    def connect(self) -> None:
        sock = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self.tls.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def callback_url(url: str, allowed_hosts: tuple[str, ...]) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in allowed_hosts or parts.username is not None
            or parts.password is not None or parts.port not in (None, 443) or parts.fragment
            or url != parts.geturl() or any(ord(character) <= 32 or ord(character) >= 127 for character in url)):
        raise ValueError("The callback must be an HTTPS URL on an explicitly configured host")
    return url


def send_webhook(
    *, url: str, allowed_hosts: tuple[str, ...], timeout: float, subscription_id: str,
    event_id: str, payload: dict, keys: tuple[bytes, ...], verification: bool = False,
) -> tuple[int, bytes]:
    parts = urlsplit(callback_url(url, allowed_hosts))
    host = parts.hostname
    if host is None:
        raise ValueError("The callback requires a host")
    timestamp = int(datetime.now(UTC).timestamp())
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    if len(body) > 256 * 1024:
        return 413, b""
    signing_input = f"{event_id}.{timestamp}.".encode() + body
    signatures = " ".join("v1," + base64.b64encode(hmac.digest(key, signing_input, "sha256")).decode() for key in keys)
    headers = {"Content-Type": "application/json", "webhook-id": event_id, "webhook-timestamp": str(timestamp),
               "webhook-signature": signatures, "X-MCP-Subscription-Id": subscription_id}
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = [ipaddress.ip_address(answer[4][0]) for answer in answers]
        if not addresses or any(not address.is_global or address.is_multicast for address in addresses):
            raise CallbackError("unsafe_destination")
        connection = _PinnedHTTPSConnection(host, str(addresses[0]), timeout=timeout)
        try:
            path = parts.path or "/"
            if parts.query:
                path += f"?{parts.query}"
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            if verification and 200 <= response.status < 300:
                return response.status, response.read(256 * 1024 + 1)
            return response.status, b""
        finally:
            connection.close()
    except TimeoutError as exc:
        raise CallbackError("timeout") from exc
    except ssl.SSLError as exc:
        raise CallbackError("tls_error") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise CallbackError("connection_failed") from exc


def verify_callback(*, url: str, hosts: tuple[str, ...], timeout: float, subscription_id: str, key: bytes) -> None:
    challenge = secrets.token_urlsafe()
    status, body = send_webhook(url=url, allowed_hosts=hosts, timeout=timeout, subscription_id=subscription_id,
                                event_id=f"msg_verification_{uuid4()}", payload={"type": "verification",
                                "challenge": challenge}, keys=(key,), verification=True)
    if not 200 <= status < 300:
        raise CallbackError("challenge_failed")
    try:
        response = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise CallbackError("challenge_failed") from exc
    echoed = response.get("challenge") if isinstance(response, dict) else None
    if not isinstance(echoed, str) or not hmac.compare_digest(echoed.encode(), challenge.encode()):
        raise CallbackError("challenge_failed")
