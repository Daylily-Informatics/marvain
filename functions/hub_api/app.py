"""Full Hub application with both API and GUI routes.

This module is for LOCAL DEVELOPMENT ONLY. It includes:
- All API routes from api_app.py
- GUI routes (login, callback, logout, home, profile, livekit-test, agent detail)

For Lambda deployment, use api_app.py instead (via lambda_handler.py).
"""
from __future__ import annotations

import base64
import html
import logging
import os
import uuid
from pathlib import Path
import secrets
import urllib.parse
from typing import Optional

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from agent_hub.auth import AuthenticatedUser, ensure_user_row
from agent_hub.cognito import (
    CognitoAuthError,
    CognitoUserInfo,
    build_login_url,
    build_logout_url,
    exchange_code_for_tokens,
    get_user_info_from_tokens,
)
from agent_hub.memberships import check_agent_permission, list_agents_for_user, list_spaces_for_user, SpaceInfo
from agent_hub.livekit_tokens import mint_livekit_join_token
from agent_hub.secrets import get_secret_json

# Import the API app and its shared state
from api_app import (
    api_app,
    _get_db,
    get_config,
    LiveKitTokenIn,
    LiveKitTokenOut,
    _mint_livekit_token_for_user,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# Use the API app as the base - all API routes are already defined
app = api_app

# Get config from api_app
_cfg = get_config()

# Setup Jinja2 templates and static files
_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

# Mount static files
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Setup Jinja2 templates
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# -----------------------------
# GUI Routes (local development only)
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
    """Get the authenticated user from the session."""
    session = request.session
    user_sub = session.get("user_sub")
    if not user_sub:
        return None

    user_id = session.get("user_id")
    email = session.get("email")

    if not user_id:
        # User exists in session but doesn't have a user_id - need to ensure row
        try:
            user_id = ensure_user_row(_get_db(), cognito_sub=user_sub, email=email)
            session["user_id"] = user_id
        except Exception:
            logger.exception("Failed to ensure user row")
            return None

    return AuthenticatedUser(
        user_id=user_id,
        cognito_sub=user_sub,
        email=email,
    )


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


@app.get("/login", name="login", response_model=None)
def gui_login(request: Request, next: str | None = None) -> Response:
    """Initiate Cognito login flow."""
    # Check if Cognito is configured
    if not _cfg.cognito_user_pool_id or not _cfg.cognito_domain:
        return _gui_error_page(
            request=request,
            title="Authentication Not Configured",
            message="Cognito authentication is not configured. Please set COGNITO_USER_POOL_ID and COGNITO_DOMAIN.",
            status_code=503,
        )

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    # Store the next URL if provided
    if next:
        request.session["oauth_next"] = _safe_next_app_path(request, next)

    try:
        login_url = build_login_url(_cfg, state=state)
        return RedirectResponse(url=login_url, status_code=302)
    except CognitoAuthError as e:
        logger.error(f"Failed to build login URL: {e}")
        return _gui_error_page(
            request=request,
            title="Authentication Error",
            message=str(e),
            status_code=500,
        )


@app.get("/auth/callback", name="auth_callback")
async def gui_auth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
    """Handle OAuth callback from Cognito."""
    # Check for OAuth errors from Cognito
    if error:
        logger.warning(f"OAuth error: {error} - {error_description}")
        return _gui_error_page(
            request=request,
            title="Authentication Error",
            message=f"{error}: {error_description or 'Unknown error'}",
            status_code=400,
        )

    if not code:
        return _gui_error_page(
            request=request,
            title="Missing Authorization Code",
            message="No authorization code was provided by the identity provider.",
            status_code=400,
        )

    # Verify state for CSRF protection
    expected_state = request.session.get("oauth_state")
    if not expected_state or state != expected_state:
        logger.warning(f"Invalid OAuth state. Expected: {expected_state}, Got: {state}")
        return _gui_error_page(
            request=request,
            title="Invalid State",
            message="OAuth state mismatch. Please try logging in again.",
            status_code=400,
        )

    # Clear state from session
    request.session.pop("oauth_state", None)

    try:
        # Exchange code for tokens
        tokens = await exchange_code_for_tokens(_cfg, code)
        id_token = tokens.get("id_token")

        if not id_token:
            return _gui_error_page(
                request=request,
                title="Authentication Error",
                message="No ID token in response from identity provider.",
                status_code=400,
            )

        # Get user info from tokens
        cognito_user = await get_user_info_from_tokens(_cfg, id_token)

        # Ensure user exists in database
        user_id = ensure_user_row(
            _get_db(),
            cognito_sub=cognito_user.sub,
            email=cognito_user.email,
        )

        # Create session
        request.session.update({
            "user_sub": cognito_user.sub,
            "user_id": user_id,
            "email": cognito_user.email,
            "name": cognito_user.name,
            "roles": cognito_user.roles,
            "cognito_groups": cognito_user.cognito_groups,
        })

        logger.info(f"User {cognito_user.email} ({cognito_user.sub}) logged in")

        # Redirect to the next URL or home
        next_url = request.session.pop("oauth_next", None) or "/"
        return RedirectResponse(url=_gui_path(request, next_url), status_code=302)

    except CognitoAuthError as e:
        logger.error(f"Cognito auth error: {e}")
        return _gui_error_page(
            request=request,
            title="Authentication Error",
            message=str(e),
            status_code=401,
        )
    except Exception as e:
        logger.exception("Unexpected error during OAuth callback")
        return _gui_error_page(
            request=request,
            title="Authentication Error",
            message="An unexpected error occurred. Please try again.",
            status_code=500,
        )


@app.get("/logout", name="logout")
def gui_logout(request: Request) -> Response:
    """Clear session and redirect to Cognito logout or logged-out page."""
    # Clear session
    request.session.clear()

    # Also clear old cookies for backward compatibility
    resp: Response
    if _cfg.cognito_domain and _cfg.cognito_user_pool_client_id:
        # Redirect to Cognito logout
        try:
            logout_url = build_logout_url(_cfg)
            resp = RedirectResponse(url=logout_url, status_code=302)
        except CognitoAuthError:
            resp = RedirectResponse(url=_gui_path(request, "/logged-out"), status_code=302)
    else:
        resp = RedirectResponse(url=_gui_path(request, "/logged-out"), status_code=302)

    # Clear old cookies
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


@app.get("/", name="gui_home")
def gui_home(request: Request) -> Response:
    """Home dashboard - central hub with status overview and navigation."""
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    db = _get_db()

    # Get agents for user
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Get spaces for user
    spaces = list_spaces_for_user(db, user_id=user.user_id)

    # Get remotes (satellites) - query from database
    remotes = []
    remotes_online = 0
    try:
        rows = db.query("""
            SELECT r.remote_id, r.name, r.address, r.connection_type, r.status, r.last_seen
            FROM remotes r
            INNER JOIN memberships m ON r.agent_id = m.agent_id
            WHERE m.user_id = :user_id
            ORDER BY r.status = 'online' DESC, r.name ASC
            LIMIT 10
        """, {"user_id": str(user.user_id)})
        for row in rows:
            remote = {
                "remote_id": str(row.get("remote_id", "")),
                "name": row.get("name", "Unknown"),
                "address": row.get("address", ""),
                "connection_type": row.get("connection_type", "network"),
                "status": row.get("status", "offline"),
            }
            remotes.append(remote)
            if remote["status"] == "online":
                remotes_online += 1
    except Exception as e:
        logger.warning(f"Failed to fetch remotes: {e}")

    # Get pending actions count
    pending_actions = 0
    try:
        rows = db.query("""
            SELECT COUNT(*) as cnt FROM actions a
            INNER JOIN memberships m ON a.agent_id = m.agent_id
            WHERE m.user_id = :user_id AND a.status = 'proposed'
        """, {"user_id": str(user.user_id)})
        if rows:
            pending_actions = rows[0].get("cnt", 0) or 0
    except Exception as e:
        logger.warning(f"Failed to fetch pending actions: {e}")

    # Convert agents to dicts for template
    agents_data = [
        {
            "agent_id": str(a.agent_id),
            "name": a.name,
            "role": a.role,
            "disabled": a.disabled,
        }
        for a in agents
    ]

    return templates.TemplateResponse(request, "home.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "home",
        "agents": agents_data,
        "agents_count": len(agents_data),
        "spaces_count": len(spaces),
        "remotes": remotes,
        "remotes_online": remotes_online,
        "remotes_total": len(remotes),
        "pending_actions": pending_actions,
    })


# -----------------------------
# GUI Routes - Placeholder stubs for navigation
# These will be fully implemented in subsequent Phase 5 tasks
# -----------------------------

@app.get("/remotes", name="gui_remotes")
def gui_remotes(request: Request) -> Response:
    """Remotes management - view connected satellites."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/remotes")

    db = _get_db()

    # Get all remotes for user's agents
    remotes = []
    try:
        rows = db.query("""
            SELECT r.remote_id, r.name, r.address, r.connection_type, r.capabilities,
                   r.status, r.last_ping, r.last_seen, a.name as agent_name
            FROM remotes r
            INNER JOIN agents a ON r.agent_id = a.agent_id
            INNER JOIN memberships m ON r.agent_id = m.agent_id
            WHERE m.user_id = :user_id
            ORDER BY r.status = 'online' DESC, r.status = 'hibernate' DESC, r.name ASC
        """, {"user_id": str(user.user_id)})
        for row in rows:
            # Parse capabilities JSON if present
            caps = row.get("capabilities") or []
            if isinstance(caps, str):
                try:
                    import json
                    caps = json.loads(caps)
                except Exception:
                    caps = []
            if isinstance(caps, dict):
                caps = list(caps.keys())

            # Calculate relative time for last_seen
            last_seen = row.get("last_seen")
            last_seen_relative = None
            if last_seen:
                try:
                    from datetime import datetime, timezone
                    if isinstance(last_seen, str):
                        last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    delta = now - last_seen
                    if delta.days > 0:
                        last_seen_relative = f"{delta.days}d ago"
                    elif delta.seconds >= 3600:
                        last_seen_relative = f"{delta.seconds // 3600}h ago"
                    elif delta.seconds >= 60:
                        last_seen_relative = f"{delta.seconds // 60}m ago"
                    else:
                        last_seen_relative = "just now"
                except Exception:
                    last_seen_relative = str(last_seen)

            remotes.append({
                "remote_id": str(row.get("remote_id", "")),
                "name": row.get("name", "Unknown"),
                "address": row.get("address", ""),
                "connection_type": row.get("connection_type", "network"),
                "capabilities": caps,
                "status": row.get("status", "offline"),
                "last_seen": str(last_seen) if last_seen else None,
                "last_seen_relative": last_seen_relative,
                "agent_name": row.get("agent_name", ""),
            })
    except Exception as e:
        logger.warning(f"Failed to fetch remotes: {e}")

    # Get agents for the add remote dropdown
    agents = list_agents_for_user(db, user_id=user.user_id)
    agents_data = [{"agent_id": str(a.agent_id), "name": a.name} for a in agents]

    # Count by status
    online_count = sum(1 for r in remotes if r["status"] == "online")
    hibernate_count = sum(1 for r in remotes if r["status"] == "hibernate")
    offline_count = sum(1 for r in remotes if r["status"] == "offline")

    return templates.TemplateResponse(request, "remotes.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "remotes",
        "remotes": remotes,
        "agents": agents_data,
        "online_count": online_count,
        "hibernate_count": hibernate_count,
        "offline_count": offline_count,
        "total_count": len(remotes),
    })


# -----------------------------
# Remotes API Endpoints
# -----------------------------


class RemoteCreate(BaseModel):
    """Request body for creating a remote."""

    name: str = Field(..., min_length=1, max_length=255)
    address: str = Field(..., min_length=1, max_length=512)
    connection_type: str = Field(default="network")
    agent_id: str = Field(...)


class RemoteResponse(BaseModel):
    """Response for a remote."""

    remote_id: str
    name: str
    address: str
    connection_type: str
    status: str
    agent_id: str


@app.post("/api/remotes", name="api_create_remote")
def api_create_remote(request: Request, body: RemoteCreate) -> RemoteResponse:
    """Create a new remote satellite."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has permission on the agent
    if not check_agent_permission(db, user_id=user.user_id, agent_id=body.agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    # Validate connection_type
    if body.connection_type not in ("network", "usb", "direct"):
        raise HTTPException(status_code=400, detail="Invalid connection_type")

    # Create the remote
    remote_id = str(uuid.uuid4())
    try:
        db.execute("""
            INSERT INTO remotes (remote_id, agent_id, name, address, connection_type, status)
            VALUES (:remote_id::uuid, :agent_id::uuid, :name, :address, :connection_type, 'offline')
        """, {
            "remote_id": remote_id,
            "agent_id": body.agent_id,
            "name": body.name,
            "address": body.address,
            "connection_type": body.connection_type,
        })
    except Exception as e:
        logger.error(f"Failed to create remote: {e}")
        raise HTTPException(status_code=500, detail="Failed to create remote")

    return RemoteResponse(
        remote_id=remote_id,
        name=body.name,
        address=body.address,
        connection_type=body.connection_type,
        status="offline",
        agent_id=body.agent_id,
    )


def _ping_remote_address(address: str, connection_type: str, timeout: float = 2.0) -> tuple[bool, str]:
    """Ping a remote to check if it's reachable.

    Returns (is_online, status) where status is 'online', 'offline', or 'hibernate'.
    """
    import socket
    import subprocess

    if connection_type == "network":
        # Try network ping - parse IP/hostname from address
        # Address might be IP, IP:port, hostname, or URL
        host = address.split(":")[0].split("/")[-1]
        if not host:
            return False, "offline"

        # Try socket connection first (faster than ICMP ping)
        try:
            port = 80  # Default HTTP port
            if ":" in address:
                parts = address.split(":")
                if len(parts) >= 2 and parts[-1].isdigit():
                    port = int(parts[-1])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                return True, "online"
        except Exception:
            pass

        # Fall back to ICMP ping
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), host],
                capture_output=True,
                timeout=timeout + 1
            )
            if result.returncode == 0:
                return True, "online"
        except Exception:
            pass

        return False, "offline"

    elif connection_type == "usb":
        # USB devices - check if device path exists
        # Address should be a device path like /dev/video0
        import os
        if address.startswith("/dev/") and os.path.exists(address):
            return True, "online"
        return False, "offline"

    elif connection_type == "direct":
        # Direct attached devices - assume online if registered
        # Could check specific hardware interfaces in the future
        return True, "online"

    # Unknown connection type
    return False, "offline"


@app.post("/api/remotes/{remote_id}/ping", name="api_ping_remote")
def api_ping_remote(request: Request, remote_id: str) -> dict:
    """Ping a remote to check its status."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the remote and check permission
    rows = db.query("""
        SELECT r.remote_id, r.agent_id, r.address, r.connection_type, r.status
        FROM remotes r
        INNER JOIN memberships m ON r.agent_id = m.agent_id
        WHERE r.remote_id = :remote_id::uuid AND m.user_id = :user_id::uuid
    """, {"remote_id": remote_id, "user_id": str(user.user_id)})

    if not rows:
        raise HTTPException(status_code=404, detail="Remote not found")

    remote = rows[0]
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    # Actually ping the remote based on connection_type
    is_online, new_status = _ping_remote_address(
        remote["address"],
        remote["connection_type"]
    )

    # Update status and timestamps
    try:
        update_params = {
            "remote_id": remote_id,
            "now": now.isoformat(),
            "status": new_status,
        }
        if is_online:
            db.execute("""
                UPDATE remotes
                SET last_ping = :now, last_seen = :now, status = :status
                WHERE remote_id = :remote_id::uuid
            """, update_params)
        else:
            db.execute("""
                UPDATE remotes
                SET last_ping = :now, status = :status
                WHERE remote_id = :remote_id::uuid
            """, update_params)
    except Exception as e:
        logger.warning(f"Failed to update remote status: {e}")

    return {
        "remote_id": remote_id,
        "status": new_status,
        "is_online": is_online,
        "last_ping": now.isoformat(),
    }


@app.get("/api/remotes/status", name="api_remotes_status")
def api_remotes_status(request: Request) -> dict:
    """Get status of all remotes for the current user."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get all remotes for user
    rows = db.query("""
        SELECT r.remote_id, r.name, r.status, r.last_ping, r.last_seen
        FROM remotes r
        INNER JOIN memberships m ON r.agent_id = m.agent_id
        WHERE m.user_id = :user_id::uuid
    """, {"user_id": str(user.user_id)})

    remotes = []
    for row in rows:
        remotes.append({
            "remote_id": str(row["remote_id"]),
            "name": row["name"],
            "status": row["status"] or "offline",
            "last_ping": row["last_ping"].isoformat() if row.get("last_ping") else None,
            "last_seen": row["last_seen"].isoformat() if row.get("last_seen") else None,
        })

    return {
        "remotes": remotes,
        "online_count": sum(1 for r in remotes if r["status"] == "online"),
        "hibernate_count": sum(1 for r in remotes if r["status"] == "hibernate"),
        "offline_count": sum(1 for r in remotes if r["status"] == "offline"),
        "total_count": len(remotes),
    }


@app.delete("/api/remotes/{remote_id}", name="api_delete_remote")
def api_delete_remote(request: Request, remote_id: str) -> dict:
    """Delete a remote."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the remote and check permission (require admin)
    rows = db.query("""
        SELECT r.remote_id, r.agent_id
        FROM remotes r
        INNER JOIN memberships m ON r.agent_id = m.agent_id
        WHERE r.remote_id = :remote_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner')
    """, {"remote_id": remote_id, "user_id": str(user.user_id)})

    if not rows:
        raise HTTPException(status_code=404, detail="Remote not found or permission denied")

    try:
        db.execute("""
            DELETE FROM remotes WHERE remote_id = :remote_id::uuid
        """, {"remote_id": remote_id})
    except Exception as e:
        logger.error(f"Failed to delete remote: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete remote")

    return {"message": "Remote deleted", "remote_id": remote_id}


# ---------------------------------------------------------------------------
# Spaces API endpoints
# ---------------------------------------------------------------------------


class SpaceCreate(BaseModel):
    """Request body for creating a space."""
    agent_id: str = Field(..., description="ID of the agent that owns this space")
    name: str = Field(..., description="Name of the space")
    privacy_mode: bool = Field(False, description="Whether privacy mode is enabled")


class SpaceResponse(BaseModel):
    """Response body for space operations."""
    space_id: str
    agent_id: str
    name: str
    privacy_mode: bool


@app.post("/api/spaces", name="api_create_space")
def api_create_space(request: Request, body: SpaceCreate) -> SpaceResponse:
    """Create a new space."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin permission on the agent
    if not check_agent_permission(db, user_id=user.user_id, agent_id=body.agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    # Create the space
    space_id = str(uuid.uuid4())
    try:
        db.execute("""
            INSERT INTO spaces (space_id, agent_id, name, privacy_mode)
            VALUES (:space_id::uuid, :agent_id::uuid, :name, :privacy_mode)
        """, {
            "space_id": space_id,
            "agent_id": body.agent_id,
            "name": body.name,
            "privacy_mode": body.privacy_mode,
        })
    except Exception as e:
        logger.error(f"Failed to create space: {e}")
        raise HTTPException(status_code=500, detail="Failed to create space")

    return SpaceResponse(
        space_id=space_id,
        agent_id=body.agent_id,
        name=body.name,
        privacy_mode=body.privacy_mode,
    )


# ---------------------------------------------------------------------------
# Devices API endpoints
# ---------------------------------------------------------------------------


class DeviceCreate(BaseModel):
    """Request body for registering a device."""
    agent_id: str = Field(..., description="ID of the agent this device belongs to")
    name: str = Field(..., description="Name of the device")
    scopes: list[str] = Field(default_factory=list, description="Scopes assigned to the device")


class DeviceResponse(BaseModel):
    """Response body for device registration."""
    device_id: str
    agent_id: str
    name: str
    scopes: list[str]
    token: str  # Only returned on creation, not stored


@app.post("/api/devices", name="api_create_device")
def api_create_device(request: Request, body: DeviceCreate) -> DeviceResponse:
    """Register a new device."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin permission on the agent
    if not check_agent_permission(db, user_id=user.user_id, agent_id=body.agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    # Generate device token and hash it
    import hashlib
    device_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(device_token.encode()).hexdigest()

    # Create the device
    device_id = str(uuid.uuid4())
    try:
        import json
        db.execute("""
            INSERT INTO devices (device_id, agent_id, name, scopes, token_hash)
            VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :token_hash)
        """, {
            "device_id": device_id,
            "agent_id": body.agent_id,
            "name": body.name,
            "scopes": json.dumps(body.scopes),
            "token_hash": token_hash,
        })
    except Exception as e:
        logger.error(f"Failed to register device: {e}")
        raise HTTPException(status_code=500, detail="Failed to register device")

    return DeviceResponse(
        device_id=device_id,
        agent_id=body.agent_id,
        name=body.name,
        scopes=body.scopes,
        token=device_token,  # Return token only on creation
    )


@app.post("/api/devices/{device_id}/revoke", name="api_revoke_device")
def api_revoke_device(request: Request, device_id: str) -> dict:
    """Revoke a device's access."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the device and check permission (require admin)
    rows = db.query("""
        SELECT d.device_id, d.agent_id
        FROM devices d
        INNER JOIN memberships m ON d.agent_id = m.agent_id
        WHERE d.device_id = :device_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner')
    """, {"device_id": device_id, "user_id": str(user.user_id)})

    if not rows:
        raise HTTPException(status_code=404, detail="Device not found or permission denied")

    try:
        from datetime import datetime, timezone
        db.execute("""
            UPDATE devices SET revoked_at = :now WHERE device_id = :device_id::uuid
        """, {"device_id": device_id, "now": datetime.now(timezone.utc)})
    except Exception as e:
        logger.error(f"Failed to revoke device: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke device")

    return {"message": "Device revoked", "device_id": device_id}


@app.get("/agents", name="gui_agents")
def gui_agents(request: Request) -> Response:
    """Agents management - list all agents."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/agents")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Build agent data list
    agents_data = []
    for agent in agents:
        agents_data.append({
            "agent_id": str(agent.agent_id),
            "name": agent.name,
            "role": agent.role,
            "relationship_label": agent.relationship_label,
            "disabled": agent.disabled,
        })

    # Count by role
    owner_count = sum(1 for a in agents_data if a["role"] == "owner")
    admin_count = sum(1 for a in agents_data if a["role"] == "admin")
    member_count = sum(1 for a in agents_data if a["role"] == "member")

    return templates.TemplateResponse(request, "agents.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "agents",
        "agents": agents_data,
        "owner_count": owner_count,
        "admin_count": admin_count,
        "member_count": member_count,
        "total_count": len(agents_data),
    })


@app.get("/spaces", name="gui_spaces")
def gui_spaces(request: Request) -> Response:
    """Spaces management - list all spaces."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/spaces")

    db = _get_db()
    spaces = list_spaces_for_user(db, user_id=user.user_id)
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Get privacy_mode and created_at for each space from database
    space_ids = [s.space_id for s in spaces]
    space_extra: dict[str, dict] = {}
    if space_ids:
        # Query for extra space data (privacy_mode, created_at)
        placeholders = ", ".join(f":id{i}" for i in range(len(space_ids)))
        params = {f"id{i}": sid for i, sid in enumerate(space_ids)}
        rows = db.query(
            f"SELECT space_id::TEXT as space_id, privacy_mode, created_at FROM spaces WHERE space_id::TEXT IN ({placeholders})",
            params,
        )
        for row in rows:
            sid = str(row.get("space_id", ""))
            space_extra[sid] = {
                "privacy_mode": row.get("privacy_mode", False),
                "created_at": row.get("created_at"),
            }

    # Build spaces data list
    spaces_data = []
    for space in spaces:
        extra = space_extra.get(space.space_id, {})
        created_at = extra.get("created_at")
        # Calculate relative time
        if created_at:
            try:
                from datetime import datetime, timezone
                if hasattr(created_at, "tzinfo"):
                    now = datetime.now(timezone.utc)
                    delta = now - created_at
                    if delta.days > 0:
                        created_at_relative = f"{delta.days}d ago"
                    elif delta.seconds >= 3600:
                        created_at_relative = f"{delta.seconds // 3600}h ago"
                    else:
                        created_at_relative = f"{delta.seconds // 60}m ago"
                else:
                    created_at_relative = str(created_at)[:10]
            except Exception:
                created_at_relative = str(created_at)[:10] if created_at else None
        else:
            created_at_relative = None

        spaces_data.append({
            "space_id": space.space_id,
            "name": space.name,
            "agent_id": space.agent_id,
            "agent_name": space.agent_name,
            "privacy_mode": extra.get("privacy_mode", False),
            "created_at_relative": created_at_relative,
        })

    # Build agents data for dropdown
    agents_data = [
        {"agent_id": a.agent_id, "name": a.name, "role": a.role}
        for a in agents
    ]

    return templates.TemplateResponse(request, "spaces.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "spaces",
        "spaces": spaces_data,
        "agents": agents_data,
    })


@app.get("/devices", name="gui_devices")
def gui_devices(request: Request) -> Response:
    """Devices management - list registered devices."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/devices")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Get devices for all agents the user has access to
    agent_ids = [a.agent_id for a in agents]
    devices_data = []
    if agent_ids:
        placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
        params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
        rows = db.query(
            f"""SELECT d.device_id::TEXT as device_id, d.agent_id::TEXT as agent_id,
                       d.name, d.scopes, d.revoked_at, d.created_at, d.last_seen,
                       a.name as agent_name
                FROM devices d
                JOIN agents a ON a.agent_id = d.agent_id
                WHERE d.agent_id::TEXT IN ({placeholders})
                ORDER BY d.created_at DESC""",
            params,
        )
        for row in rows:
            last_seen = row.get("last_seen")
            if last_seen:
                try:
                    from datetime import datetime, timezone
                    if hasattr(last_seen, "tzinfo"):
                        now = datetime.now(timezone.utc)
                        delta = now - last_seen
                        if delta.days > 0:
                            last_seen_relative = f"{delta.days}d ago"
                        elif delta.seconds >= 3600:
                            last_seen_relative = f"{delta.seconds // 3600}h ago"
                        else:
                            last_seen_relative = f"{delta.seconds // 60}m ago"
                    else:
                        last_seen_relative = str(last_seen)[:16]
                except Exception:
                    last_seen_relative = str(last_seen)[:16] if last_seen else None
            else:
                last_seen_relative = None

            scopes = row.get("scopes") or []
            if isinstance(scopes, str):
                import json
                try:
                    scopes = json.loads(scopes)
                except Exception:
                    scopes = []

            devices_data.append({
                "device_id": str(row.get("device_id", "")),
                "agent_id": str(row.get("agent_id", "")),
                "agent_name": row.get("agent_name", ""),
                "name": row.get("name") or "Unnamed Device",
                "scopes": scopes,
                "revoked": row.get("revoked_at") is not None,
                "last_seen_relative": last_seen_relative,
            })

    # Build agents data for dropdown
    agents_data = [
        {"agent_id": a.agent_id, "name": a.name, "role": a.role}
        for a in agents
    ]

    return templates.TemplateResponse(request, "devices.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "devices",
        "devices": devices_data,
        "agents": agents_data,
    })


# ---------------------------------------------------------------------------
# People & Consent API endpoints
# ---------------------------------------------------------------------------


class PersonCreate(BaseModel):
    """Request body for creating a person."""
    agent_id: str = Field(..., description="ID of the agent this person belongs to")
    display_name: str = Field(..., description="Display name of the person")


class PersonResponse(BaseModel):
    """Response body for person operations."""
    person_id: str
    agent_id: str
    display_name: str


class ConsentGrant(BaseModel):
    """A single consent grant."""
    type: str = Field(..., description="Type of consent: voice, face, or recording")
    expires_at: str | None = Field(None, description="Optional expiration date (ISO format)")


class ConsentUpdate(BaseModel):
    """Request body for updating consents."""
    consents: list[ConsentGrant] = Field(default_factory=list, description="List of consent grants")


@app.post("/api/people", name="api_create_person")
def api_create_person(request: Request, body: PersonCreate) -> PersonResponse:
    """Create a new person."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin permission on the agent
    if not check_agent_permission(db, user_id=user.user_id, agent_id=body.agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    person_id = str(uuid.uuid4())
    try:
        db.execute("""
            INSERT INTO people (person_id, agent_id, display_name)
            VALUES (:person_id::uuid, :agent_id::uuid, :display_name)
        """, {
            "person_id": person_id,
            "agent_id": body.agent_id,
            "display_name": body.display_name,
        })
    except Exception as e:
        logger.error(f"Failed to create person: {e}")
        raise HTTPException(status_code=500, detail="Failed to create person")

    return PersonResponse(
        person_id=person_id,
        agent_id=body.agent_id,
        display_name=body.display_name,
    )


@app.post("/api/people/{person_id}/consent", name="api_update_consent")
def api_update_consent(request: Request, person_id: str, body: ConsentUpdate) -> dict:
    """Update consent grants for a person."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the person and check permission
    rows = db.query("""
        SELECT p.person_id, p.agent_id
        FROM people p
        INNER JOIN memberships m ON p.agent_id = m.agent_id
        WHERE p.person_id = :person_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner')
    """, {"person_id": person_id, "user_id": str(user.user_id)})

    if not rows:
        raise HTTPException(status_code=404, detail="Person not found or permission denied")

    agent_id = str(rows[0].get("agent_id", ""))

    try:
        from datetime import datetime, timezone

        # First, revoke all existing active consents for this person
        db.execute("""
            UPDATE consent_grants SET revoked_at = :now
            WHERE person_id = :person_id::uuid AND revoked_at IS NULL
        """, {"person_id": person_id, "now": datetime.now(timezone.utc)})

        # Then create new consent grants
        for consent in body.consents:
            consent_id = str(uuid.uuid4())
            expires_at = None
            if consent.expires_at:
                try:
                    expires_at = datetime.fromisoformat(consent.expires_at.replace("Z", "+00:00"))
                except Exception:
                    expires_at = None

            db.execute("""
                INSERT INTO consent_grants (consent_id, agent_id, person_id, consent_type, expires_at)
                VALUES (:consent_id::uuid, :agent_id::uuid, :person_id::uuid, :consent_type, :expires_at)
            """, {
                "consent_id": consent_id,
                "agent_id": agent_id,
                "person_id": person_id,
                "consent_type": consent.type,
                "expires_at": expires_at,
            })

    except Exception as e:
        logger.error(f"Failed to update consent: {e}")
        raise HTTPException(status_code=500, detail="Failed to update consent")

    return {"message": "Consent updated", "person_id": person_id}


@app.get("/people", name="gui_people")
def gui_people(request: Request) -> Response:
    """People & consent management."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/people")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Get people for all agents the user has access to
    agent_ids = [a.agent_id for a in agents]
    people_data = []
    if agent_ids:
        from datetime import datetime, timezone
        placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
        params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
        rows = db.query(
            f"""SELECT p.person_id::TEXT as person_id, p.agent_id::TEXT as agent_id,
                       p.display_name, p.created_at,
                       a.name as agent_name
                FROM people p
                JOIN agents a ON a.agent_id = p.agent_id
                WHERE p.agent_id::TEXT IN ({placeholders})
                ORDER BY p.created_at DESC""",
            params,
        )

        # Build person list with consent status
        for row in rows:
            person_id = str(row.get("person_id", ""))
            created_at = row.get("created_at")
            created_at_relative = None
            if created_at:
                try:
                    if hasattr(created_at, "tzinfo"):
                        now = datetime.now(timezone.utc)
                        delta = now - created_at
                        if delta.days > 0:
                            created_at_relative = f"{delta.days}d ago"
                        elif delta.seconds >= 3600:
                            created_at_relative = f"{delta.seconds // 3600}h ago"
                        else:
                            created_at_relative = f"{delta.seconds // 60}m ago"
                except Exception:
                    pass

            # Get active consents for this person
            consent_rows = db.query("""
                SELECT consent_type, expires_at
                FROM consent_grants
                WHERE person_id = :person_id::uuid AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > :now)
            """, {"person_id": person_id, "now": datetime.now(timezone.utc)})

            voice_consent = None
            face_consent = None
            recording_consent = None
            for cr in consent_rows:
                ct = cr.get("consent_type", "")
                exp = cr.get("expires_at")
                exp_str = str(exp)[:10] if exp else "No expiry"
                if ct == "voice":
                    voice_consent = exp_str
                elif ct == "face":
                    face_consent = exp_str
                elif ct == "recording":
                    recording_consent = exp_str

            people_data.append({
                "person_id": person_id,
                "agent_id": str(row.get("agent_id", "")),
                "agent_name": row.get("agent_name", ""),
                "display_name": row.get("display_name", ""),
                "created_at_relative": created_at_relative,
                "voice_consent": voice_consent,
                "face_consent": face_consent,
                "recording_consent": recording_consent,
                "active_consents": bool(voice_consent or face_consent or recording_consent),
            })

    agents_data = [
        {"agent_id": a.agent_id, "name": a.name, "role": a.role}
        for a in agents
    ]

    return templates.TemplateResponse(request, "people.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "people",
        "people": people_data,
        "agents": agents_data,
    })


@app.get("/actions", name="gui_actions")
def gui_actions(request: Request) -> Response:
    """Actions dashboard - pending actions and history."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/actions")
    return _gui_html_page(title="Actions", body_html="<h1>Actions</h1><p>Coming soon - Phase 5.11</p>")


@app.get("/events", name="gui_events")
def gui_events(request: Request) -> Response:
    """Event stream viewer."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/events")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)
    spaces = list_spaces_for_user(db, user_id=user.user_id)

    # Get events for all agents the user has access to
    agent_ids = [a.agent_id for a in agents]
    events_data = []
    event_types_set: set = set()

    if agent_ids:
        from datetime import datetime, timezone
        import json
        placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
        params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
        rows = db.query(
            f"""SELECT e.event_id::TEXT as event_id, e.agent_id::TEXT as agent_id,
                       e.space_id::TEXT as space_id, e.device_id::TEXT as device_id,
                       e.person_id::TEXT as person_id, e.type, e.payload, e.created_at,
                       a.name as agent_name, s.name as space_name, p.display_name as person_name
                FROM events e
                JOIN agents a ON a.agent_id = e.agent_id
                LEFT JOIN spaces s ON s.space_id = e.space_id
                LEFT JOIN people p ON p.person_id = e.person_id
                WHERE e.agent_id::TEXT IN ({placeholders})
                ORDER BY e.created_at DESC
                LIMIT 200""",
            params,
        )

        for row in rows:
            event_type = row.get("type", "")
            event_types_set.add(event_type)

            # Categorize event type for badge styling
            type_lower = event_type.lower()
            if "audio" in type_lower or "sound" in type_lower:
                type_category = "audio"
            elif "video" in type_lower or "image" in type_lower:
                type_category = "video"
            elif "speech" in type_lower or "transcript" in type_lower or "voice" in type_lower:
                type_category = "speech"
            elif "action" in type_lower or "tool" in type_lower or "execute" in type_lower:
                type_category = "action"
            elif "system" in type_lower or "error" in type_lower or "connect" in type_lower:
                type_category = "system"
            else:
                type_category = "other"

            created_at = row.get("created_at")
            created_at_str = ""
            if created_at:
                try:
                    if hasattr(created_at, "strftime"):
                        created_at_str = created_at.strftime("%H:%M:%S")
                except Exception:
                    pass

            payload = row.get("payload") or {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            payload_str = json.dumps(payload) if payload else "{}"
            payload_preview = payload_str[:100] + ("..." if len(payload_str) > 100 else "")

            events_data.append({
                "event_id": str(row.get("event_id", "")),
                "agent_id": str(row.get("agent_id", "")),
                "agent_name": row.get("agent_name", ""),
                "space_id": str(row.get("space_id", "")) if row.get("space_id") else None,
                "space_name": row.get("space_name"),
                "person_id": str(row.get("person_id", "")) if row.get("person_id") else None,
                "person_name": row.get("person_name"),
                "type": event_type,
                "type_category": type_category,
                "payload_str": payload_str,
                "payload_preview": payload_preview,
                "created_at_str": created_at_str,
            })

    agents_data = [
        {"agent_id": a.agent_id, "name": a.name, "role": a.role}
        for a in agents
    ]
    spaces_data = [
        {"space_id": s.space_id, "name": s.name}
        for s in spaces
    ]

    return templates.TemplateResponse(request, "events.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "events",
        "events": events_data,
        "event_types": sorted(event_types_set),
        "agents": agents_data,
        "spaces": spaces_data,
    })


@app.get("/memories", name="gui_memories")
def gui_memories(request: Request) -> Response:
    """Memories browser."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/memories")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)
    spaces = list_spaces_for_user(db, user_id=user.user_id)

    # Get memories for all agents the user has access to
    agent_ids = [a.agent_id for a in agents]
    memories_data = []
    tier_counts = {"episodic": 0, "semantic": 0, "procedural": 0}

    if agent_ids:
        from datetime import datetime, timezone
        import json
        placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
        params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
        rows = db.query(
            f"""SELECT m.memory_id::TEXT as memory_id, m.agent_id::TEXT as agent_id,
                       m.space_id::TEXT as space_id, m.tier, m.content,
                       m.participants, m.provenance, m.created_at,
                       a.name as agent_name, s.name as space_name
                FROM memories m
                JOIN agents a ON a.agent_id = m.agent_id
                LEFT JOIN spaces s ON s.space_id = m.space_id
                WHERE m.agent_id::TEXT IN ({placeholders})
                ORDER BY m.created_at DESC
                LIMIT 100""",
            params,
        )

        for row in rows:
            tier = row.get("tier", "")
            if tier in tier_counts:
                tier_counts[tier] += 1

            created_at = row.get("created_at")
            created_at_relative = None
            if created_at:
                try:
                    if hasattr(created_at, "tzinfo"):
                        now = datetime.now(timezone.utc)
                        delta = now - created_at
                        if delta.days > 0:
                            created_at_relative = f"{delta.days}d ago"
                        elif delta.seconds >= 3600:
                            created_at_relative = f"{delta.seconds // 3600}h ago"
                        else:
                            created_at_relative = f"{delta.seconds // 60}m ago"
                except Exception:
                    pass

            participants = row.get("participants") or []
            if isinstance(participants, str):
                try:
                    participants = json.loads(participants)
                except Exception:
                    participants = []

            provenance = row.get("provenance") or {}
            if isinstance(provenance, str):
                try:
                    provenance = json.loads(provenance)
                except Exception:
                    provenance = {}

            memories_data.append({
                "memory_id": str(row.get("memory_id", "")),
                "agent_id": str(row.get("agent_id", "")),
                "agent_name": row.get("agent_name", ""),
                "space_id": str(row.get("space_id", "")) if row.get("space_id") else None,
                "space_name": row.get("space_name"),
                "tier": tier,
                "content": row.get("content", ""),
                "participants": participants,
                "provenance_source": provenance.get("source", ""),
                "created_at_relative": created_at_relative,
            })

    agents_data = [
        {"agent_id": a.agent_id, "name": a.name, "role": a.role}
        for a in agents
    ]
    spaces_data = [
        {"space_id": s.space_id, "name": s.name}
        for s in spaces
    ]

    return templates.TemplateResponse(request, "memories.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "memories",
        "memories": memories_data,
        "tier_counts": tier_counts,
        "agents": agents_data,
        "spaces": spaces_data,
    })


@app.delete("/api/memories/{memory_id}", name="api_delete_memory")
def api_delete_memory(request: Request, memory_id: str) -> dict:
    """Delete a memory."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the memory and check permission
    rows = db.query("""
        SELECT m.memory_id, m.agent_id
        FROM memories m
        INNER JOIN memberships mb ON m.agent_id = mb.agent_id
        WHERE m.memory_id = :memory_id::uuid AND mb.user_id = :user_id::uuid AND mb.role IN ('admin', 'owner')
    """, {"memory_id": memory_id, "user_id": str(user.user_id)})

    if not rows:
        raise HTTPException(status_code=404, detail="Memory not found or permission denied")

    try:
        db.execute("""
            DELETE FROM memories WHERE memory_id = :memory_id::uuid
        """, {"memory_id": memory_id})
    except Exception as e:
        logger.error(f"Failed to delete memory: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete memory")

    return {"message": "Memory deleted", "memory_id": memory_id}


@app.get("/audit", name="gui_audit")
def gui_audit(request: Request) -> Response:
    """Audit log viewer."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/audit")
    return _gui_html_page(title="Audit", body_html="<h1>Audit Log</h1><p>Coming soon - Phase 5.13</p>")


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
    )
    return _gui_html_page(title="Profile", body_html=body)


def _livekit_test_page_script() -> str:
    """Return the JavaScript for the LiveKit test page (separated for readability)."""
    return """
(function(){
  var room = null;
  var localVideoTrack = null;
  var localAudioTrack = null;
  var statusEl = document.getElementById('status');
  var selectEl = document.getElementById('space_id');
  var tokenUrl = document.getElementById('lkcfg').getAttribute('data-token-url');
  var participantsEl = document.getElementById('participants');
  var localVideoEl = document.getElementById('local-video');
  var remoteMediaEl = document.getElementById('remote-media');
  var chatMessagesEl = document.getElementById('chat-messages');
  var chatInputEl = document.getElementById('chat-input');
  var myIdentity = '';

  function log(msg) {
    var ts = new Date().toLocaleTimeString();
    statusEl.textContent = '[' + ts + '] ' + msg + '\\n' + statusEl.textContent;
    if (statusEl.textContent.length > 5000) {
      statusEl.textContent = statusEl.textContent.substring(0, 4000);
    }
  }

  function updateParticipantsList() {
    if (!room) { participantsEl.innerHTML = '<em>Not connected</em>'; return; }
    var items = [];
    // Local participant
    var lp = room.localParticipant;
    var lpAudio = lp.isMicrophoneEnabled ? '🎤' : '🔇';
    var lpVideo = lp.isCameraEnabled ? '📹' : '📷';
    items.push('<li><strong>' + escapeHtml(lp.identity) + '</strong> (you) ' + lpAudio + ' ' + lpVideo + '</li>');
    // Remote participants
    room.remoteParticipants.forEach(function(p) {
      var pAudio = '🔇', pVideo = '📷';
      p.trackPublications.forEach(function(pub) {
        if (pub.kind === 'audio' && pub.isSubscribed) pAudio = '🔊';
        if (pub.kind === 'video' && pub.isSubscribed) pVideo = '📹';
      });
      var state = p.connectionQuality || 'unknown';
      var isAgent = p.identity.startsWith('agent:') || p.identity.startsWith('device:');
      var label = isAgent ? '🤖 ' + escapeHtml(p.identity) : escapeHtml(p.identity);
      items.push('<li>' + label + ' ' + pAudio + ' ' + pVideo + ' <small>(' + state + ')</small></li>');
    });
    participantsEl.innerHTML = items.length ? '<ul style="margin:0;padding-left:20px;">' + items.join('') + '</ul>' : '<em>No participants</em>';
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function attachRemoteTrack(track, participant) {
    var el;
    if (track.kind === 'video') {
      el = document.createElement('video');
      el.autoplay = true;
      el.playsInline = true;
      el.style.maxWidth = '320px';
      el.style.maxHeight = '240px';
      el.style.margin = '4px';
      el.style.borderRadius = '8px';
      el.style.background = '#222';
    } else if (track.kind === 'audio') {
      el = document.createElement('audio');
      el.autoplay = true;
    }
    if (el) {
      el.id = 'track-' + track.sid;
      el.setAttribute('data-participant', participant.identity);
      track.attach(el);
      remoteMediaEl.appendChild(el);
      log('Attached ' + track.kind + ' from ' + participant.identity);
    }
  }

  function detachRemoteTrack(track) {
    var el = document.getElementById('track-' + track.sid);
    if (el) {
      track.detach(el);
      el.remove();
    }
  }

  function setupRoomEvents() {
    room.on('participantConnected', function(p) {
      log('Participant joined: ' + p.identity);
      updateParticipantsList();
    });
    room.on('participantDisconnected', function(p) {
      log('Participant left: ' + p.identity);
      // Remove their media elements
      remoteMediaEl.querySelectorAll('[data-participant="' + p.identity + '"]').forEach(function(el) { el.remove(); });
      updateParticipantsList();
    });
    room.on('trackSubscribed', function(track, pub, participant) {
      log('Track subscribed: ' + track.kind + ' from ' + participant.identity);
      attachRemoteTrack(track, participant);
      updateParticipantsList();
    });
    room.on('trackUnsubscribed', function(track, pub, participant) {
      log('Track unsubscribed: ' + track.kind + ' from ' + participant.identity);
      detachRemoteTrack(track);
      updateParticipantsList();
    });
    room.on('trackMuted', function(pub, participant) {
      log('Track muted: ' + pub.kind + ' from ' + participant.identity);
      updateParticipantsList();
    });
    room.on('trackUnmuted', function(pub, participant) {
      log('Track unmuted: ' + pub.kind + ' from ' + participant.identity);
      updateParticipantsList();
    });
    room.on('disconnected', function() {
      log('Disconnected from room');
      updateParticipantsList();
      updateMediaButtons();
    });
    room.on('dataReceived', function(payload, participant) {
      try {
        var msg = JSON.parse(new TextDecoder().decode(payload));
        if (msg.type === 'chat') {
          addChatMessage(participant ? participant.identity : 'unknown', msg.text, msg.ts);
        }
      } catch(e) { /* ignore non-chat data */ }
    });
  }

  function addChatMessage(sender, text, ts) {
    var time = ts ? new Date(ts).toLocaleTimeString() : new Date().toLocaleTimeString();
    var isMe = sender === myIdentity;
    var div = document.createElement('div');
    div.style.marginBottom = '8px';
    div.style.padding = '6px 10px';
    div.style.borderRadius = '8px';
    div.style.background = isMe ? '#1a472a' : '#2a2a3a';
    div.style.color = '#eee';
    div.innerHTML = '<small style="color:#aaa;">[' + escapeHtml(time) + '] <strong style="color:#fff;">' + escapeHtml(sender) + '</strong></small><br>' + escapeHtml(text);
    chatMessagesEl.appendChild(div);
    chatMessagesEl.scrollTop = chatMessagesEl.scrollHeight;
  }

  function sendChatMessage() {
    var text = (chatInputEl.value || '').trim();
    if (!text || !room) return;
    var msg = { type: 'chat', text: text, ts: Date.now() };
    var data = new TextEncoder().encode(JSON.stringify(msg));
    room.localParticipant.publishData(data, { reliable: true });
    addChatMessage(myIdentity, text, msg.ts);
    chatInputEl.value = '';
  }

  async function join() {
    var spaceId = (selectEl.value || '').trim();
    if (!spaceId) { log('Please select a space'); return; }
    log('Requesting token...');
    var resp = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ space_id: spaceId }) });
    if (!resp.ok) { log('Token request failed: ' + resp.status); return; }
    var data = await resp.json();
    log('Connecting to ' + data.url + '...');
    var lk = window.LivekitClient || window.livekit || window.LiveKit;
    if (!lk || !lk.Room) { log('LiveKit client not loaded'); return; }
    room = new lk.Room();
    setupRoomEvents();
    await room.connect(data.url, data.token);
    myIdentity = data.identity;
    log('Connected! room=' + data.room + ' identity=' + data.identity);
    updateParticipantsList();
    updateMediaButtons();
    // Subscribe to existing remote tracks
    room.remoteParticipants.forEach(function(p) {
      p.trackPublications.forEach(function(pub) {
        if (pub.isSubscribed && pub.track) {
          attachRemoteTrack(pub.track, p);
        }
      });
    });
  }

  async function leave() {
    if (localVideoTrack) { localVideoTrack.stop(); localVideoTrack = null; }
    if (localAudioTrack) { localAudioTrack.stop(); localAudioTrack = null; }
    localVideoEl.innerHTML = '';
    remoteMediaEl.innerHTML = '';
    if (room) { try { await room.disconnect(); } catch(e) {} room = null; }
    log('Left room');
    updateParticipantsList();
    updateMediaButtons();
  }

  function updateMediaButtons() {
    var connected = room && room.state === 'connected';
    document.getElementById('btn-mic').disabled = !connected;
    document.getElementById('btn-cam').disabled = !connected;
    document.getElementById('btn-send-chat').disabled = !connected;
    if (connected) {
      document.getElementById('btn-mic').textContent = room.localParticipant.isMicrophoneEnabled ? '🎤 Mic On' : '🔇 Mic Off';
      document.getElementById('btn-cam').textContent = room.localParticipant.isCameraEnabled ? '📹 Cam On' : '📷 Cam Off';
    } else {
      document.getElementById('btn-mic').textContent = '🔇 Mic Off';
      document.getElementById('btn-cam').textContent = '📷 Cam Off';
    }
  }

  async function toggleMic() {
    if (!room) return;
    try {
      await room.localParticipant.setMicrophoneEnabled(!room.localParticipant.isMicrophoneEnabled);
      log('Microphone ' + (room.localParticipant.isMicrophoneEnabled ? 'enabled' : 'disabled'));
      updateMediaButtons();
      updateParticipantsList();
    } catch(e) {
      log('Mic error: ' + e.message);
    }
  }

  async function toggleCam() {
    if (!room) return;
    try {
      var wasEnabled = room.localParticipant.isCameraEnabled;
      await room.localParticipant.setCameraEnabled(!wasEnabled);
      log('Camera ' + (room.localParticipant.isCameraEnabled ? 'enabled' : 'disabled'));
      updateMediaButtons();
      updateParticipantsList();
      // Attach/detach local video preview
      if (room.localParticipant.isCameraEnabled) {
        var camPub = room.localParticipant.getTrackPublication('camera');
        if (camPub && camPub.track) {
          var vid = document.createElement('video');
          vid.autoplay = true;
          vid.playsInline = true;
          vid.muted = true;
          vid.style.maxWidth = '240px';
          vid.style.borderRadius = '8px';
          camPub.track.attach(vid);
          localVideoEl.innerHTML = '';
          localVideoEl.appendChild(vid);
        }
      } else {
        localVideoEl.innerHTML = '';
      }
    } catch(e) {
      log('Camera error: ' + e.message);
    }
  }

  // Event listeners
  document.getElementById('join').addEventListener('click', function() { join().catch(function(e) { log('Join error: ' + e); }); });
  document.getElementById('leave').addEventListener('click', function() { leave().catch(function(e) { log('Leave error: ' + e); }); });
  document.getElementById('btn-mic').addEventListener('click', function() { toggleMic().catch(function(e) { log('Mic error: ' + e); }); });
  document.getElementById('btn-cam').addEventListener('click', function() { toggleCam().catch(function(e) { log('Cam error: ' + e); }); });
  document.getElementById('btn-send-chat').addEventListener('click', sendChatMessage);
  chatInputEl.addEventListener('keypress', function(e) { if (e.key === 'Enter') sendChatMessage(); });

  // Initial state
  updateMediaButtons();
  updateParticipantsList();
})();
"""


@app.get("/livekit-test", name="gui_livekit_test")
def gui_livekit_test(request: Request, space_id: str | None = None) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    # Fetch spaces for dropdown
    spaces = list_spaces_for_user(_get_db(), user_id=user.user_id)

    sid = str(space_id or "").strip()
    home_href = html.escape(_gui_path(request, "/"))
    logout_href = html.escape(_gui_path(request, "/logout"))
    token_url = _gui_path(request, "/livekit/token")
    token_url_attr = html.escape(token_url, quote=True)

    # Build dropdown options
    options = ['<option value="">-- Select a space --</option>']
    for sp in spaces:
        sp_id = html.escape(sp.space_id, quote=True)
        sp_name = html.escape(sp.name)
        agent_name = html.escape(sp.agent_name)
        selected = " selected" if sp.space_id == sid else ""
        options.append(f'<option value="{sp_id}"{selected}>{sp_name} ({agent_name}) - {sp_id}</option>')
    options_html = "\n".join(options)

    body = f"""
<div style='display:flex; justify-content:space-between; align-items:center;'>
  <h1>LiveKit Test</h1>
  <div><a href='{home_href}'>Home</a> | <a href='{logout_href}'>Logout</a></div>
</div>

<p>Join a LiveKit room mapped from a Marvain <code>space_id</code>.</p>
<div id='lkcfg' data-token-url="{token_url_attr}" style='display:none'></div>

<!-- Connection Controls -->
<div style='margin-bottom:16px; padding:12px; background:#1a1a2e; border-radius:8px;'>
  <label><strong>Space:</strong> <select id='space_id' style='min-width:400px;'>{options_html}</select></label>
  <button id='join' style='margin-left:8px;'>🔗 Join</button>
  <button id='leave'>🚪 Leave</button>
</div>

<!-- Media Controls -->
<div style='margin-bottom:16px; padding:12px; background:#1a1a2e; border-radius:8px;'>
  <strong>Media:</strong>
  <button id='btn-mic' disabled>🔇 Mic Off</button>
  <button id='btn-cam' disabled>📷 Cam Off</button>
  <span style='margin-left:16px; color:#888;'>Click to enable after joining</span>
</div>

<!-- Main Content Grid -->
<div style='display:grid; grid-template-columns:1fr 1fr; gap:16px;'>
  <!-- Left Column: Video & Participants -->
  <div>
    <!-- Local Video Preview -->
    <div style='margin-bottom:16px;'>
      <h3 style='margin:0 0 8px 0;'>📹 Local Preview</h3>
      <div id='local-video' style='min-height:180px; background:#111; border-radius:8px; display:flex; align-items:center; justify-content:center; color:#666;'>
        Camera off
      </div>
    </div>

    <!-- Remote Media -->
    <div style='margin-bottom:16px;'>
      <h3 style='margin:0 0 8px 0;'>🔊 Remote Media</h3>
      <div id='remote-media' style='min-height:120px; background:#111; border-radius:8px; padding:8px; display:flex; flex-wrap:wrap; gap:8px;'>
      </div>
    </div>

    <!-- Participants List -->
    <div>
      <h3 style='margin:0 0 8px 0;'>👥 Participants</h3>
      <div id='participants' style='background:#111; border-radius:8px; padding:12px; min-height:60px; color:#eee;'>
        <em>Not connected</em>
      </div>
    </div>
  </div>

  <!-- Right Column: Chat & Status -->
  <div>
    <!-- Chat Interface -->
    <div style='margin-bottom:16px;'>
      <h3 style='margin:0 0 8px 0;'>💬 Chat</h3>
      <div id='chat-messages' style='background:#111; border-radius:8px; padding:12px; height:200px; overflow-y:auto; margin-bottom:8px; color:#eee;'>
        <em style='color:#888;'>Messages will appear here...</em>
      </div>
      <div style='display:flex; gap:8px;'>
        <input id='chat-input' type='text' placeholder='Type a message...' style='flex:1; padding:8px; border-radius:4px; border:1px solid #333; background:#222; color:#eee;' />
        <button id='btn-send-chat' disabled>Send</button>
      </div>
    </div>

    <!-- Status Log -->
    <div>
      <h3 style='margin:0 0 8px 0;'>📋 Status Log</h3>
      <pre id='status' style='background:#111; color:#0f0; padding:12px; border-radius:8px; height:180px; overflow-y:auto; font-size:12px; margin:0;'>idle</pre>
    </div>
  </div>
</div>

<!-- Agent Worker Instructions -->
<details style='margin-top:24px; padding:12px; background:#1a1a2e; border-radius:8px; color:#eee;'>
  <summary style='cursor:pointer; font-weight:bold;'>🤖 Running an Agent Worker (Satellite)</summary>
  <div style='margin-top:12px; font-size:14px; line-height:1.6;'>
    <p>To test agent voice interaction, run the agent worker locally:</p>
    <pre style='background:#111; padding:12px; border-radius:4px; overflow-x:auto;'>
# 1. Navigate to the agent worker directory
cd apps/agent_worker

# 2. Export environment variables (get values from marvain-config.yaml or bootstrap output)
export LIVEKIT_URL="wss://&lt;your-livekit-url&gt;"
export LIVEKIT_API_KEY="&lt;from AWS Secrets Manager or LiveKit dashboard&gt;"
export LIVEKIT_API_SECRET="&lt;from AWS Secrets Manager or LiveKit dashboard&gt;"
export OPENAI_API_KEY="&lt;your-openai-key&gt;"
export HUB_API_BASE="&lt;ApiUrl from marvain-config.yaml resources&gt;"
export HUB_DEVICE_TOKEN="&lt;device token from bootstrap output&gt;"
export SPACE_ID="&lt;space_id to join&gt;"

# Or use marvain CLI to get config values:
# ./bin/marvain monitor outputs  # Shows stack outputs including ApiUrl
# Check ~/.config/marvain/marvain-config.yaml for LiveKitUrl, LiveKitSecretArn

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the worker (it will auto-join rooms when users connect)
python worker.py start
    </pre>
    <p><strong>Identity format:</strong></p>
    <ul>
      <li>Users join as <code>user:&lt;user_id&gt;</code></li>
      <li>Devices/agents join as <code>device:&lt;device_id&gt;</code> or <code>agent:&lt;agent_id&gt;</code></li>
    </ul>
    <p>The agent worker uses LiveKit's agent framework to automatically join rooms and respond with voice.</p>
    <p><strong>Note:</strong> LiveKit credentials are stored in AWS Secrets Manager. Use <code>aws secretsmanager get-secret-value --secret-id &lt;LiveKitSecretArn&gt;</code> to retrieve them.</p>
  </div>
</details>

<script src='https://cdn.jsdelivr.net/npm/livekit-client/dist/livekit-client.umd.min.js'></script>
<script>
{_livekit_test_page_script()}
</script>
"""
    return _gui_html_page(title="LiveKit Test", body_html=body)


@app.post("/livekit/token", response_model=LiveKitTokenOut)
def gui_livekit_token(request: Request, body: LiveKitTokenIn) -> LiveKitTokenOut:
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _mint_livekit_token_for_user(user=user, space_id=body.space_id)


@app.get("/agents/{agent_id}", name="gui_agent_detail")
def gui_agent_detail(request: Request, agent_id: str) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    db = _get_db()
    # Ensure the user can see this agent by filtering their memberships.
    agents = list_agents_for_user(db, user_id=user.user_id)
    match = next((a for a in agents if a.agent_id == agent_id), None)
    if not match:
        return PlainTextResponse("not found", status_code=404)

    # Fetch members for this agent
    members_rows = db.query(
        "SELECT m.user_id, m.role, m.created_at, u.email "
        "FROM memberships m LEFT JOIN users u ON m.user_id = u.user_id "
        "WHERE m.agent_id = :agent_id ORDER BY m.created_at",
        {"agent_id": agent_id},
    )
    members = [
        {
            "user_id": str(row.get("user_id", "")),
            "role": row.get("role", "member"),
            "email": row.get("email"),
            "created_at": str(row.get("created_at", ""))[:10] if row.get("created_at") else None,
        }
        for row in members_rows
    ]

    agent_data = {
        "agent_id": str(match.agent_id),
        "name": match.name,
        "role": match.role,
        "relationship_label": match.relationship_label,
        "disabled": match.disabled,
    }

    return templates.TemplateResponse(request, "agent_detail.html", {
        "user": {"email": user.email, "user_id": str(user.user_id)},
        "stage": _cfg.stage,
        "active_page": "agents",
        "agent": agent_data,
        "members": members,
    })
