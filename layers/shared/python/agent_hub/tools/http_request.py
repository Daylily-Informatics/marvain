"""http_request tool - Makes authenticated HTTP requests.

This tool allows the agent to make HTTP requests to approved hosts,
enabling integrations with external services.
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any
from urllib.parse import urlparse

from .registry import ToolRegistry, ToolResult, ToolContext

logger = logging.getLogger(__name__)

TOOL_NAME = "http_request"
REQUIRED_SCOPES = ["http:request"]

MAX_RESPONSE_SIZE = 32768  # 32KB
DEFAULT_TIMEOUT = 10


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute the http_request tool.
    
    Payload:
        method: HTTP method (GET, POST, PUT, PATCH, DELETE)
        url: The URL to request
        headers: Dict of headers (optional)
        body: Request body for POST/PUT/PATCH (optional)
        timeout: Request timeout in seconds (optional, default 10)
    """
    method = str(payload.get("method", "GET")).strip().upper()
    url = str(payload.get("url", "")).strip()
    headers = payload.get("headers", {})
    body = payload.get("body")
    timeout = int(payload.get("timeout", DEFAULT_TIMEOUT))
    
    # Validate method
    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
    if method not in allowed_methods:
        return ToolResult(ok=False, error=f"invalid_method: {method}")
    
    # Validate URL
    if not url:
        return ToolResult(ok=False, error="missing_url")
    
    try:
        parsed = urlparse(url)
    except Exception:
        return ToolResult(ok=False, error="invalid_url")
    
    if parsed.scheme not in ("http", "https"):
        return ToolResult(ok=False, error=f"invalid_scheme: {parsed.scheme}")
    
    # Check host allowlist
    host = parsed.netloc.split(":")[0].lower()
    if ctx.allowed_http_hosts and host not in ctx.allowed_http_hosts:
        return ToolResult(ok=False, error=f"host_not_allowed: {host}")
    
    # Validate headers
    if not isinstance(headers, dict):
        headers = {}
    
    # Clamp timeout
    timeout = max(1, min(timeout, 60))
    
    try:
        # Prepare request body
        data = None
        if body is not None and method in ("POST", "PUT", "PATCH"):
            if isinstance(body, dict):
                data = json.dumps(body).encode("utf-8")
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = str(body).encode("utf-8")
        
        # Build request
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in headers.items():
            req.add_header(str(key), str(value))
        
        # Add user agent
        req.add_header("User-Agent", f"marvain-tool/{TOOL_NAME}")
        
        # Execute request
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            raw_body = resp.read(MAX_RESPONSE_SIZE)
        
        # Try to decode as text
        try:
            body_text = raw_body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = f"<binary data, {len(raw_body)} bytes>"
        
        return ToolResult(ok=True, data={
            "status": status,
            "headers": resp_headers,
            "body": body_text,
            "body_length": len(raw_body),
        })
        
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read(MAX_RESPONSE_SIZE).decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        return ToolResult(ok=False, error=f"http_error_{e.code}", data={
            "status": e.code,
            "body": error_body[:1000],
        })
    except urllib.error.URLError as e:
        return ToolResult(ok=False, error=f"url_error: {str(e.reason)}")
    except TimeoutError:
        return ToolResult(ok=False, error="timeout")
    except Exception as e:
        logger.exception("http_request failed")
        return ToolResult(ok=False, error=f"request_failed: {str(e)}")


def register(registry: ToolRegistry) -> None:
    """Register the http_request tool with the registry."""
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Make HTTP requests to approved external services",
    )

