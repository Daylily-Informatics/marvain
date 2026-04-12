from __future__ import annotations

import base64
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_MAX_TEXT_BODY_BYTES = 50000
_MAX_BINARY_BODY_BYTES = 10000


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _host_allowed(hostname: str, allowed_hosts: list[str]) -> bool:
    if not allowed_hosts:
        return True
    host = hostname.lower()
    for allowed in allowed_hosts:
        item = allowed.strip().lower()
        if not item:
            continue
        if host == item or host.endswith(f".{item}"):
            return True
    return False


def _resolve_public_addresses(hostname: str) -> None:
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    if not infos:
        raise ValueError("host_resolution_failed")
    for info in infos:
        raw_ip = info[4][0]
        ip = ipaddress.ip_address(raw_ip)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(f"disallowed_host_ip: {raw_ip}")


def perform_http_request(
    *,
    url: str,
    method: str,
    headers: dict[str, Any],
    body: Any,
    timeout: int,
    allowed_hosts: list[str],
) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("invalid_scheme")
    if not parsed.hostname:
        raise ValueError("missing_hostname")
    if not _host_allowed(parsed.hostname, allowed_hosts):
        raise ValueError("host_not_allowed")
    _resolve_public_addresses(parsed.hostname)

    request_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode("utf-8")

    request = urllib.request.Request(parsed.geturl(), data=data, headers=request_headers, method=str(method or "GET").upper())
    opener = urllib.request.build_opener(NoRedirectHandler)
    start_time = time.time()

    try:
        with opener.open(request, timeout=timeout) as response:
            response_body = response.read()
            execution_time = time.time() - start_time
            try:
                body_text = response_body.decode("utf-8")[:_MAX_TEXT_BODY_BYTES]
                is_binary = False
            except UnicodeDecodeError:
                body_text = base64.b64encode(response_body[:_MAX_BINARY_BODY_BYTES]).decode("ascii")
                is_binary = True

            return {
                "status": "success",
                "status_code": response.status,
                "headers": dict(response.headers),
                "body": body_text,
                "is_binary": is_binary,
                "body_length": len(response_body),
                "truncated": len(response_body) > _MAX_TEXT_BODY_BYTES,
                "execution_time_seconds": round(execution_time, 3),
            }
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        return {
            "status": "http_error",
            "status_code": exc.code,
            "headers": dict(exc.headers),
            "body": body_bytes.decode("utf-8", errors="replace")[:_MAX_TEXT_BODY_BYTES],
            "execution_time_seconds": round(time.time() - start_time, 3),
        }
