"""Full Hub application with both API and GUI routes.

This module is for LOCAL DEVELOPMENT ONLY. It includes:
- All API routes from api_app.py
- GUI routes (login, callback, logout, home, profile, livekit-test, agent detail)

For Lambda deployment, use api_app.py instead (via lambda_handler.py).
"""

from __future__ import annotations

import base64
import html
import json
import logging
import os
import secrets
import urllib.parse
import uuid
from pathlib import Path
from typing import Optional

from agent_hub.auth import (
    AuthenticatedUser,
    ensure_user_row,
    lookup_cognito_user_by_email,
)
from agent_hub.cognito import (
    CognitoAuthError,
    CognitoUserInfo,  # noqa: F401 — used via module attr in tests
    build_login_url,
    build_logout_url,
    exchange_code_for_tokens,
    get_user_info_from_tokens,
)
from agent_hub.livekit_tokens import mint_livekit_join_token  # noqa: F401 — used via module attr in tests
from agent_hub.memberships import (
    SpaceInfo,  # noqa: F401 — used via module attr in tests
    check_agent_permission,
    grant_membership,
    list_agents_for_user,
    list_spaces_for_user,
    revoke_membership,
    update_membership,
)
from agent_hub.secrets import get_secret_json

# Import the API app and its shared state
from api_app import (
    LiveKitTokenIn,
    LiveKitTokenOut,
    _get_db,
    _get_s3,
    _mint_livekit_token_for_user,
    api_app,
    get_config,
)
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.responses import Response

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


# -----------------------------
# Startup Configuration Validation
# -----------------------------


class ConfigurationError(Exception):
    """Raised when critical configuration is missing or invalid."""

    pass


def _is_placeholder(value: str | None) -> bool:
    """Check if a value is a placeholder or empty."""
    if not value:
        return True
    v = str(value).strip().upper()
    return v in ("", "REPLACE_ME", "CHANGEME", "TODO", "XXX", "YOUR_KEY_HERE", "YOUR_SECRET_HERE")


def _validate_critical_secrets(cfg) -> list[str]:
    """Validate all critical secrets at startup.

    Returns a list of configuration errors. Empty list means all valid.
    """
    errors: list[str] = []

    # 1. Cognito Configuration
    if not cfg.cognito_user_pool_id:
        errors.append("COGNITO_USER_POOL_ID not set")
    if not cfg.cognito_user_pool_client_id:
        errors.append("COGNITO_APP_CLIENT_ID not set")
    if not cfg.cognito_domain:
        errors.append("COGNITO_DOMAIN not set")

    # 2. Database Configuration (required for any operation)
    if not cfg.db_resource_arn:
        errors.append("DB_RESOURCE_ARN not set")
    if not cfg.db_secret_arn:
        errors.append("DB_SECRET_ARN not set")

    # 3. LiveKit Configuration (required for voice/video features)
    if not cfg.livekit_url:
        errors.append("LIVEKIT_URL not set")
    if not cfg.livekit_secret_arn:
        errors.append("LIVEKIT_SECRET_ARN not set")
    else:
        try:
            # Clear cache to get fresh value
            get_secret_json.cache_clear()
            lk_secret = get_secret_json(cfg.livekit_secret_arn)
            lk_api_key = lk_secret.get("api_key", "")
            lk_api_secret = lk_secret.get("api_secret", "")
            if _is_placeholder(lk_api_key):
                errors.append("LiveKit api_key is a placeholder (REPLACE_ME). Update secret in AWS Secrets Manager.")
            if _is_placeholder(lk_api_secret):
                errors.append("LiveKit api_secret is a placeholder (REPLACE_ME). Update secret in AWS Secrets Manager.")
        except Exception as e:
            errors.append(f"Failed to read LiveKit secret: {e}")

    # 4. OpenAI Configuration (required for embeddings/AI features)
    if cfg.openai_secret_arn:
        try:
            # Clear cache to get fresh value
            get_secret_json.cache_clear()
            openai_secret = get_secret_json(cfg.openai_secret_arn)
            openai_api_key = openai_secret.get("api_key", "")
            if _is_placeholder(openai_api_key):
                errors.append("OpenAI api_key is a placeholder (REPLACE_ME). Update secret in AWS Secrets Manager.")
        except Exception as e:
            errors.append(f"Failed to read OpenAI secret: {e}")

    # 5. Session Secret (required for secure sessions)
    if not cfg.session_secret_key and not cfg.session_secret_arn:
        errors.append(
            "SESSION_SECRET_KEY or SESSION_SECRET_ARN not set - sessions will use random key (not persistent)"
        )

    return errors


def validate_configuration_or_fail():
    """Validate all critical configuration and fail hard if any issues.

    This is called at startup to ensure the GUI won't run with misconfigured secrets.
    """
    cfg = get_config()
    errors = _validate_critical_secrets(cfg)

    if errors:
        error_msg = "\n".join(f"  - {e}" for e in errors)
        full_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CRITICAL CONFIGURATION ERROR                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ The GUI cannot start because critical secrets are missing or invalid.        ║
║                                                                              ║
║ Fix the following issues:                                                    ║
{chr(10).join(f"║ • {e[:72]:<72}║" for e in errors)}
║                                                                              ║
║ To update secrets in AWS Secrets Manager:                                    ║
║   aws secretsmanager put-secret-value --secret-id <ARN> \\                   ║
║       --secret-string '{{"api_key":"<YOUR_KEY>"}}'                            ║
║                                                                              ║
║ For LiveKit credentials, check: ~/.livekit/cli-config.yaml                   ║
║ For OpenAI credentials, set your API key from platform.openai.com            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        logger.critical(full_msg)  # nosec - private repo, helpful for debugging config issues
        raise ConfigurationError(f"Critical configuration errors:\n{error_msg}")


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
# Startup Event - Validate Configuration
# -----------------------------


@app.on_event("startup")
async def startup_validate_configuration():
    """Validate critical configuration on startup.

    This runs when the GUI server starts and will raise an exception
    (crashing the server) if critical secrets are missing or invalid.
    """
    logger.info("Validating critical configuration...")
    validate_configuration_or_fail()
    logger.info("Configuration validation passed - all critical secrets are set")


# -----------------------------
# GUI Routes (local development only)
# -----------------------------

_GUI_ACCESS_TOKEN_COOKIE = "marvain_access_token"
_GUI_OAUTH_STATE_COOKIE = "marvain_oauth_state"
_GUI_OAUTH_VERIFIER_COOKIE = "marvain_oauth_verifier"
_GUI_OAUTH_NEXT_COOKIE = "marvain_oauth_next"


def _get_ws_context(request: Request) -> dict[str, str | None]:
    """Get WebSocket context for template rendering.

    Returns dict with ws_url and access_token for WebSocket connection.
    """
    ws_url = _cfg.ws_api_url
    access_token = request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE)
    logger.debug(
        f"_get_ws_context: ws_url={ws_url}, access_token present={bool(access_token)}, length={len(access_token) if access_token else 0}"
    )
    return {
        "ws_url": ws_url,
        "access_token": access_token if ws_url else None,
    }


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
    # nosec - next_path is validated by _safe_next_app_path (blocks //, schemes, CRLF injection)
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
    body = f"<h1>{html.escape(title)}</h1><p>{html.escape(message)}</p><p><a href='{login_href}'>Log in</a></p>"
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
        access_token = tokens.get("access_token")

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
        request.session.update(
            {
                "user_sub": cognito_user.sub,
                "user_id": user_id,
                "email": cognito_user.email,
                "name": cognito_user.name,
                "roles": cognito_user.roles,
                "cognito_groups": cognito_user.cognito_groups,
            }
        )

        logger.info(f"User {cognito_user.email} ({cognito_user.sub}) logged in")
        logger.info(f"Access token received: {bool(access_token)}, length: {len(access_token) if access_token else 0}")

        # Redirect to the next URL or home
        next_url = request.session.pop("oauth_next", None) or "/"
        resp = RedirectResponse(url=_gui_path(request, next_url), status_code=302)

        # Store access token in cookie for WebSocket authentication
        if access_token:
            logger.info(f"Setting access token cookie, secure={_cookie_secure(request)}")
            resp.set_cookie(
                key=_GUI_ACCESS_TOKEN_COOKIE,
                value=access_token,
                httponly=True,
                secure=_cookie_secure(request),
                samesite="lax",
                max_age=3600,  # 1 hour (Cognito access token default expiry)
                path="/",
            )
        else:
            logger.warning("No access token received from Cognito!")

        return resp

    except CognitoAuthError as e:
        logger.error(f"Cognito auth error: {e}")
        return _gui_error_page(
            request=request,
            title="Authentication Error",
            message=str(e),
            status_code=401,
        )
    except Exception:
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
        return _gui_redirect_to_login(
            request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear
        )

    db = _get_db()

    # Get agents for user
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Get spaces for user
    spaces = list_spaces_for_user(db, user_id=user.user_id)

    # Get pending actions count
    pending_actions = 0
    try:
        rows = db.query(
            """
            SELECT COUNT(*) as cnt FROM actions a
            INNER JOIN agent_memberships m ON a.agent_id = m.agent_id
            WHERE m.user_id = :user_id AND m.revoked_at IS NULL AND a.status = 'proposed'
        """,
            {"user_id": str(user.user_id)},
        )
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

    # Get devices count and recent devices for the user's agents
    devices_count = 0
    devices_data: list[dict] = []
    agent_ids = [str(a.agent_id) for a in agents]
    if agent_ids:
        try:
            placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
            params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
            count_rows = db.query(
                f"SELECT COUNT(*) as cnt FROM devices WHERE agent_id::TEXT IN ({placeholders})",
                params,
            )
            if count_rows:
                devices_count = count_rows[0].get("cnt", 0) or 0

            dev_rows = db.query(
                f"""SELECT d.device_id::TEXT as device_id, d.name,
                           a.name as agent_name, d.revoked_at
                    FROM devices d
                    JOIN agents a ON a.agent_id = d.agent_id
                    WHERE d.agent_id::TEXT IN ({placeholders})
                    ORDER BY d.created_at DESC LIMIT 5""",
                params,
            )
            for row in dev_rows:
                devices_data.append(
                    {
                        "device_id": str(row.get("device_id", "")),
                        "name": row.get("name") or "Unnamed Device",
                        "agent_name": row.get("agent_name", ""),
                        "revoked": row.get("revoked_at") is not None,
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to fetch devices for home: {e}")

    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "home",
            "agents": agents_data,
            "agents_count": len(agents_data),
            "spaces_count": len(spaces),
            "pending_actions": pending_actions,
            "devices_count": devices_count,
            "devices": devices_data,
            **_get_ws_context(request),
        },
    )


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
        db.execute(
            """
            INSERT INTO spaces (space_id, agent_id, name, privacy_mode)
            VALUES (:space_id::uuid, :agent_id::uuid, :name, :privacy_mode)
        """,
            {
                "space_id": space_id,
                "agent_id": body.agent_id,
                "name": body.name,
                "privacy_mode": body.privacy_mode,
            },
        )
    except Exception as e:
        logger.error(f"Failed to create space: {e}")
        raise HTTPException(status_code=500, detail="Failed to create space")

    return SpaceResponse(
        space_id=space_id,
        agent_id=body.agent_id,
        name=body.name,
        privacy_mode=body.privacy_mode,
    )


@app.delete("/api/spaces/{space_id}", name="api_delete_space")
def api_delete_space(request: Request, space_id: str) -> dict:
    """Delete a space."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the space and check permission (require admin/owner on the agent)
    rows = db.query(
        """
        SELECT s.space_id, s.agent_id, s.name
        FROM spaces s
        INNER JOIN agent_memberships m ON s.agent_id = m.agent_id
        WHERE s.space_id = :space_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.role IN ('admin', 'owner')
          AND m.revoked_at IS NULL
    """,
        {"space_id": space_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Space not found or permission denied")

    space_name = rows[0].get("name", "")

    try:
        db.execute(
            """
            DELETE FROM spaces WHERE space_id = :space_id::uuid
        """,
            {"space_id": space_id},
        )
    except Exception as e:
        logger.error(f"Failed to delete space: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete space")

    return {"message": "Space deleted", "space_id": space_id, "name": space_name}


class SpaceUpdate(BaseModel):
    name: str | None = None
    privacy_mode: bool | None = None


@app.patch("/api/spaces/{space_id}", name="api_update_space")
def api_update_space(request: Request, space_id: str, body: SpaceUpdate) -> dict:
    """Update a space's name or privacy mode."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin permission on the space's agent
    rows = db.query(
        """
        SELECT s.space_id, s.name, s.privacy_mode
        FROM spaces s
        INNER JOIN agent_memberships m ON s.agent_id = m.agent_id
        WHERE s.space_id = :space_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.role IN ('admin', 'owner')
          AND m.revoked_at IS NULL
    """,
        {"space_id": space_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Space not found or permission denied")

    # Build the update query dynamically
    updates = []
    params = {"space_id": space_id}

    if body.name is not None:
        if len(body.name.strip()) == 0:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        updates.append("name = :name")
        params["name"] = body.name.strip()

    if body.privacy_mode is not None:
        updates.append("privacy_mode = :privacy_mode")
        params["privacy_mode"] = body.privacy_mode

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        db.execute(
            f"""
            UPDATE spaces SET {", ".join(updates)} WHERE space_id = :space_id::uuid
        """,
            params,
        )
    except Exception as e:
        logger.error(f"Failed to update space: {e}")
        raise HTTPException(status_code=500, detail="Failed to update space")

    return {"message": "Space updated", "space_id": space_id}


@app.get("/api/spaces/{space_id}", name="api_get_space")
def api_get_space(request: Request, space_id: str) -> dict:
    """Get space details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    rows = db.query(
        """
        SELECT s.space_id::TEXT as space_id, s.agent_id::TEXT as agent_id,
               s.name, s.privacy_mode, s.created_at::TEXT as created_at,
               a.name as agent_name
        FROM spaces s
        INNER JOIN agents a ON s.agent_id = a.agent_id
        INNER JOIN agent_memberships m ON s.agent_id = m.agent_id
        WHERE s.space_id = :space_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.role IN ('member', 'admin', 'owner')
          AND m.revoked_at IS NULL
    """,
        {"space_id": space_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Space not found or permission denied")

    row = rows[0]
    return {
        "space_id": row["space_id"],
        "agent_id": row["agent_id"],
        "agent_name": row.get("agent_name", ""),
        "name": row["name"],
        "privacy_mode": row["privacy_mode"],
        "created_at": row["created_at"],
    }


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

        db.execute(
            """
            INSERT INTO devices (device_id, agent_id, name, scopes, token_hash)
            VALUES (:device_id::uuid, :agent_id::uuid, :name, :scopes::jsonb, :token_hash)
        """,
            {
                "device_id": device_id,
                "agent_id": body.agent_id,
                "name": body.name,
                "scopes": json.dumps(body.scopes),
                "token_hash": token_hash,
            },
        )
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
    rows = db.query(
        """
        SELECT d.device_id, d.agent_id
        FROM devices d
        INNER JOIN agent_memberships m ON d.agent_id = m.agent_id
        WHERE d.device_id = :device_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner') AND m.revoked_at IS NULL
    """,
        {"device_id": device_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Device not found or permission denied")

    try:
        db.execute(
            """
            UPDATE devices SET revoked_at = NOW() WHERE device_id = :device_id::uuid
        """,
            {"device_id": device_id},
        )
    except Exception as e:
        logger.error(f"Failed to revoke device: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke device")

    return {"message": "Device revoked", "device_id": device_id}


@app.post("/api/devices/{device_id}/delete", name="api_delete_device")
def api_delete_device(request: Request, device_id: str) -> dict:
    """Delete a device permanently."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the device and check permission (require admin/owner)
    rows = db.query(
        """
        SELECT d.device_id, d.agent_id
        FROM devices d
        INNER JOIN agent_memberships m ON d.agent_id = m.agent_id
        WHERE d.device_id = :device_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner') AND m.revoked_at IS NULL
    """,
        {"device_id": device_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Device not found or permission denied")

    try:
        db.execute(
            """
            DELETE FROM devices WHERE device_id = :device_id::uuid
        """,
            {"device_id": device_id},
        )
    except Exception as e:
        logger.error(f"Failed to delete device: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete device")

    return {"message": "Device deleted", "device_id": device_id}


# ---------------------------------------------------------------------------
# Agents API endpoints (session-based auth for GUI)
# ---------------------------------------------------------------------------


class AgentCreate(BaseModel):
    """Request body for creating an agent."""

    name: str = Field(..., min_length=1, max_length=255, description="Name of the agent")
    relationship_label: str | None = Field(None, max_length=255, description="Optional label for the relationship")


class AgentResponse(BaseModel):
    """Response body for agent creation."""

    agent_id: str
    name: str
    role: str
    relationship_label: str | None
    disabled: bool


@app.post("/api/agents", name="api_create_agent")
def api_create_agent(request: Request, body: AgentCreate) -> AgentResponse:
    """Create a new agent and make the creating user the owner."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()
    agent_id = str(uuid.uuid4())

    # Use a transaction to ensure atomicity
    tx = db.begin()
    try:
        # Create the agent
        db.execute(
            "INSERT INTO agents(agent_id, name, disabled) VALUES (:agent_id::uuid, :name, false)",
            {"agent_id": agent_id, "name": body.name},
            transaction_id=tx,
        )

        # Make the creating user the owner
        db.execute(
            """
            INSERT INTO agent_memberships (agent_id, user_id, role, relationship_label)
            VALUES (:agent_id::uuid, :user_id::uuid, 'owner', :relationship_label)
            """,
            {"agent_id": agent_id, "user_id": user.user_id, "relationship_label": body.relationship_label},
            transaction_id=tx,
        )

        db.commit(tx)
    except Exception as e:
        db.rollback(tx)
        logger.error(f"Failed to create agent: {e}")
        raise HTTPException(status_code=500, detail="Failed to create agent")

    # Add audit log entry if audit bucket is configured
    if _cfg.audit_bucket:
        from agent_hub.audit import append_audit_entry

        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="agent_created",
            entry={"user_id": user.user_id, "name": body.name},
        )

    return AgentResponse(
        agent_id=agent_id,
        name=body.name,
        role="owner",
        relationship_label=body.relationship_label,
        disabled=False,
    )


class AgentUpdate(BaseModel):
    name: str | None = None
    disabled: bool | None = None


@app.patch("/api/agents/{agent_id}", name="api_update_agent")
def api_update_agent(request: Request, agent_id: str, body: AgentUpdate) -> dict:
    """Update an agent's name or disabled status."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin or owner permission
    if not check_agent_permission(db, user_id=user.user_id, agent_id=agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    # Build the update query dynamically
    updates = []
    params = {"agent_id": agent_id}

    if body.name is not None:
        if len(body.name.strip()) == 0:
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        updates.append("name = :name")
        params["name"] = body.name.strip()

    if body.disabled is not None:
        updates.append("disabled = :disabled")
        params["disabled"] = body.disabled

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        db.execute(
            f"""
            UPDATE agents SET {", ".join(updates)} WHERE agent_id = :agent_id::uuid
        """,
            params,
        )
    except Exception as e:
        logger.error(f"Failed to update agent: {e}")
        raise HTTPException(status_code=500, detail="Failed to update agent")

    return {"message": "Agent updated", "agent_id": agent_id}


@app.get("/api/agents/{agent_id}", name="api_get_agent")
def api_get_agent(request: Request, agent_id: str) -> dict:
    """Get agent details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    rows = db.query(
        """
        SELECT a.agent_id::TEXT as agent_id, a.name, a.disabled,
               a.created_at::TEXT as created_at,
               mb.role, mb.relationship_label
        FROM agents a
        INNER JOIN agent_memberships mb ON a.agent_id = mb.agent_id
        WHERE a.agent_id = :agent_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('member', 'admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"agent_id": agent_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Agent not found or permission denied")

    row = rows[0]
    return {
        "agent_id": row["agent_id"],
        "name": row["name"],
        "disabled": row["disabled"],
        "role": row["role"],
        "relationship_label": row.get("relationship_label"),
        "created_at": row["created_at"],
    }


# ----- Membership Management API Endpoints -----


@app.get("/api/cognito/users", name="api_list_cognito_users")
def api_list_cognito_users(request: Request) -> list[dict]:
    """List all users in the Cognito user pool (for member selection)."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not _cfg.cognito_user_pool_id:
        raise HTTPException(status_code=500, detail="Cognito not configured")

    import boto3

    client = boto3.client("cognito-idp")
    users = []
    paginator = client.get_paginator("list_users")
    for page in paginator.paginate(UserPoolId=_cfg.cognito_user_pool_id):
        for u in page.get("Users", []):
            attrs = {a["Name"]: a["Value"] for a in u.get("Attributes", [])}
            email = attrs.get("email", u.get("Username", ""))
            if email:
                users.append(
                    {
                        "email": email,
                        "status": u.get("UserStatus", "UNKNOWN"),
                        "enabled": u.get("Enabled", False),
                    }
                )
    return users


class MemberAdd(BaseModel):
    email: str
    role: str = "member"
    relationship_label: str | None = None


class MemberUpdate(BaseModel):
    role: str
    relationship_label: str | None = None


class MemberResponse(BaseModel):
    user_id: str
    email: str | None
    role: str


@app.post("/api/agents/{agent_id}/memberships", name="api_add_member")
def api_add_member(request: Request, agent_id: str, body: MemberAdd) -> MemberResponse:
    """Add a member to an agent."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()
    if not check_agent_permission(db, agent_id=agent_id, user_id=user.user_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Look up the user by email in Cognito
    if not _cfg.cognito_user_pool_id:
        raise HTTPException(status_code=500, detail="Cognito not configured")

    try:
        cognito_sub, resolved_email = lookup_cognito_user_by_email(
            user_pool_id=_cfg.cognito_user_pool_id, email=body.email
        )
    except LookupError:
        # Provide a more helpful error message
        raise HTTPException(
            status_code=404,
            detail=f"User '{body.email}' not found in Cognito. They must have a Cognito account before being added as a member. Use 'marvain cognito create-user' to create one.",
        )

    # Ensure user exists in local DB
    target_user_id = ensure_user_row(db, cognito_sub=cognito_sub, email=resolved_email or body.email)

    try:
        grant_membership(
            db, agent_id=agent_id, user_id=target_user_id, role=body.role, relationship_label=body.relationship_label
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if _cfg.audit_bucket:
        from agent_hub.audit import append_audit_entry

        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_granted",
            entry={
                "by_user_id": user.user_id,
                "user_id": target_user_id,
                "email": resolved_email or body.email,
                "role": body.role,
            },
        )

    return MemberResponse(user_id=target_user_id, email=resolved_email or body.email, role=body.role)


@app.patch("/api/agents/{agent_id}/memberships/{member_user_id}", name="api_update_member")
def api_update_member(request: Request, agent_id: str, member_user_id: str, body: MemberUpdate) -> dict:
    """Update a member's role in an agent."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()
    if not check_agent_permission(db, agent_id=agent_id, user_id=user.user_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Forbidden")

    try:
        update_membership(
            db, agent_id=agent_id, user_id=member_user_id, role=body.role, relationship_label=body.relationship_label
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if _cfg.audit_bucket:
        from agent_hub.audit import append_audit_entry

        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_updated",
            entry={"by_user_id": user.user_id, "user_id": member_user_id, "role": body.role},
        )

    return {"ok": True}


@app.delete("/api/agents/{agent_id}/memberships/{member_user_id}", name="api_delete_member")
def api_delete_member(request: Request, agent_id: str, member_user_id: str) -> dict:
    """Remove a member from an agent."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()
    if not check_agent_permission(db, agent_id=agent_id, user_id=user.user_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Forbidden")

    revoke_membership(db, agent_id=agent_id, user_id=member_user_id)

    if _cfg.audit_bucket:
        from agent_hub.audit import append_audit_entry

        append_audit_entry(
            db,
            bucket=_cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="member_revoked",
            entry={"by_user_id": user.user_id, "user_id": member_user_id},
        )

    return {"ok": True}


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
        agents_data.append(
            {
                "agent_id": str(agent.agent_id),
                "name": agent.name,
                "role": agent.role,
                "relationship_label": agent.relationship_label,
                "disabled": agent.disabled,
            }
        )

    # Count by role
    owner_count = sum(1 for a in agents_data if a["role"] == "owner")
    admin_count = sum(1 for a in agents_data if a["role"] == "admin")
    member_count = sum(1 for a in agents_data if a["role"] == "member")

    return templates.TemplateResponse(
        request,
        "agents.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "agents",
            "agents": agents_data,
            "owner_count": owner_count,
            "admin_count": admin_count,
            "member_count": member_count,
            "total_count": len(agents_data),
            **_get_ws_context(request),
        },
    )


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

        spaces_data.append(
            {
                "space_id": space.space_id,
                "name": space.name,
                "agent_id": space.agent_id,
                "agent_name": space.agent_name,
                "privacy_mode": extra.get("privacy_mode", False),
                "created_at_relative": created_at_relative,
            }
        )

    # Build agents data for dropdown
    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    return templates.TemplateResponse(
        request,
        "spaces.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "spaces",
            "spaces": spaces_data,
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


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

            devices_data.append(
                {
                    "device_id": str(row.get("device_id", "")),
                    "agent_id": str(row.get("agent_id", "")),
                    "agent_name": row.get("agent_name", ""),
                    "name": row.get("name") or "Unnamed Device",
                    "scopes": scopes,
                    "revoked": row.get("revoked_at") is not None,
                    "last_seen_relative": last_seen_relative,
                }
            )

    # Build agents data for dropdown
    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "devices",
            "devices": devices_data,
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


@app.get("/devices/{device_id}", name="gui_device_detail")
def gui_device_detail(request: Request, device_id: str) -> Response:
    """Device detail page - view a specific device."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path=f"/devices/{device_id}")

    db = _get_db()

    # Get device with permission check
    rows = db.query(
        """
        SELECT d.device_id::TEXT, d.agent_id::TEXT, d.name, d.scopes,
               d.revoked_at, d.created_at, d.last_seen, d.last_heartbeat_at,
               a.name as agent_name,
               CASE
                   WHEN d.last_heartbeat_at > now() - interval '60 seconds' THEN true
                   ELSE false
               END as is_online
        FROM devices d
        JOIN agents a ON a.agent_id = d.agent_id
        JOIN agent_memberships m ON d.agent_id = m.agent_id
        WHERE d.device_id = :device_id::uuid
          AND m.user_id = :user_id::uuid
          AND m.revoked_at IS NULL
    """,
        {"device_id": device_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Device not found")

    row = rows[0]

    # Parse scopes
    scopes = row.get("scopes") or []
    if isinstance(scopes, str):
        import json as json_module

        try:
            scopes = json_module.loads(scopes)
        except Exception:
            scopes = []

    # Format timestamps
    created_at = row.get("created_at")
    if created_at:
        created_at = str(created_at)[:19] if hasattr(created_at, "isoformat") else str(created_at)[:19]

    last_seen = row.get("last_seen")
    if last_seen:
        last_seen = str(last_seen)[:19] if hasattr(last_seen, "isoformat") else str(last_seen)[:19]

    device_data = {
        "device_id": str(row.get("device_id", "")),
        "agent_id": str(row.get("agent_id", "")),
        "agent_name": row.get("agent_name", ""),
        "name": row.get("name") or "Unnamed Device",
        "scopes": scopes,
        "revoked": row.get("revoked_at") is not None,
        "created_at": created_at,
        "last_seen": last_seen,
        "is_online": bool(row.get("is_online")),
    }

    return templates.TemplateResponse(
        request,
        "device_detail.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "devices",
            "device": device_data,
            **_get_ws_context(request),
        },
    )


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
        db.execute(
            """
            INSERT INTO people (person_id, agent_id, display_name)
            VALUES (:person_id::uuid, :agent_id::uuid, :display_name)
        """,
            {
                "person_id": person_id,
                "agent_id": body.agent_id,
                "display_name": body.display_name,
            },
        )
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
    rows = db.query(
        """
        SELECT p.person_id, p.agent_id
        FROM people p
        INNER JOIN agent_memberships m ON p.agent_id = m.agent_id
        WHERE p.person_id = :person_id::uuid AND m.user_id = :user_id::uuid AND m.role IN ('admin', 'owner') AND m.revoked_at IS NULL
    """,
        {"person_id": person_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Person not found or permission denied")

    agent_id = str(rows[0].get("agent_id", ""))

    try:
        from datetime import datetime, timezone

        # First, revoke all existing active consents for this person
        db.execute(
            """
            UPDATE consent_grants SET revoked_at = :now
            WHERE person_id = :person_id::uuid AND revoked_at IS NULL
        """,
            {"person_id": person_id, "now": datetime.now(timezone.utc)},
        )

        # Then create new consent grants
        for consent in body.consents:
            consent_id = str(uuid.uuid4())
            expires_at = None
            if consent.expires_at:
                try:
                    expires_at = datetime.fromisoformat(consent.expires_at.replace("Z", "+00:00"))
                except Exception:
                    expires_at = None

            db.execute(
                """
                INSERT INTO consent_grants (consent_id, agent_id, person_id, consent_type, expires_at)
                VALUES (:consent_id::uuid, :agent_id::uuid, :person_id::uuid, :consent_type, :expires_at)
            """,
                {
                    "consent_id": consent_id,
                    "agent_id": agent_id,
                    "person_id": person_id,
                    "consent_type": consent.type,
                    "expires_at": expires_at,
                },
            )

    except Exception as e:
        logger.error(f"Failed to update consent: {e}")
        raise HTTPException(status_code=500, detail="Failed to update consent")

    return {"message": "Consent updated", "person_id": person_id}


class PersonUpdate(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)


@app.patch("/api/people/{person_id}", name="api_update_person")
def api_update_person(request: Request, person_id: str, body: PersonUpdate) -> dict:
    """Update a person's display name."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check the person exists and user has admin permission on the agent
    rows = db.query(
        """
        SELECT p.person_id, p.agent_id, p.display_name
        FROM people p
        INNER JOIN agent_memberships mb ON p.agent_id = mb.agent_id
        WHERE p.person_id = :person_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"person_id": person_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Person not found or permission denied")

    try:
        db.execute(
            """
            UPDATE people SET display_name = :display_name WHERE person_id = :person_id::uuid
        """,
            {"person_id": person_id, "display_name": body.display_name},
        )
    except Exception as e:
        logger.error(f"Failed to update person: {e}")
        raise HTTPException(status_code=500, detail="Failed to update person")

    return {"message": "Person updated", "person_id": person_id, "display_name": body.display_name}


@app.get("/api/people/{person_id}", name="api_get_person")
def api_get_person(request: Request, person_id: str) -> dict:
    """Get a person's details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    rows = db.query(
        """
        SELECT p.person_id::TEXT as person_id, p.agent_id::TEXT as agent_id,
               p.display_name, p.created_at::TEXT as created_at, a.name as agent_name
        FROM people p
        INNER JOIN agents a ON p.agent_id = a.agent_id
        INNER JOIN agent_memberships mb ON p.agent_id = mb.agent_id
        WHERE p.person_id = :person_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('member', 'admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"person_id": person_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Person not found or permission denied")

    row = rows[0]
    return {
        "person_id": row["person_id"],
        "agent_id": row["agent_id"],
        "agent_name": row.get("agent_name", ""),
        "display_name": row["display_name"],
        "created_at": row["created_at"],
    }


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
            consent_rows = db.query(
                """
                SELECT consent_type, expires_at
                FROM consent_grants
                WHERE person_id = :person_id::uuid AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > :now)
            """,
                {"person_id": person_id, "now": datetime.now(timezone.utc)},
            )

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

            people_data.append(
                {
                    "person_id": person_id,
                    "agent_id": str(row.get("agent_id", "")),
                    "agent_name": row.get("agent_name", ""),
                    "display_name": row.get("display_name", ""),
                    "created_at_relative": created_at_relative,
                    "voice_consent": voice_consent,
                    "face_consent": face_consent,
                    "recording_consent": recording_consent,
                    "active_consents": bool(voice_consent or face_consent or recording_consent),
                }
            )

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    return templates.TemplateResponse(
        request,
        "people.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "people",
            "people": people_data,
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


@app.get("/actions", name="gui_actions")
def gui_actions(request: Request) -> Response:
    """Actions dashboard - pending actions and history."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/actions")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)
    spaces = list_spaces_for_user(db, user_id=user.user_id)

    # Get actions for all agents the user has access to
    agent_ids = [a.agent_id for a in agents]
    actions_data = []
    status_counts = {"proposed": 0, "approved": 0, "executed": 0, "failed": 0}
    action_kinds_set: set = set()

    if agent_ids:
        import json
        from datetime import datetime, timezone

        placeholders = ", ".join(f":id{i}" for i in range(len(agent_ids)))
        params = {f"id{i}": aid for i, aid in enumerate(agent_ids)}
        rows = db.query(
            f"""SELECT ac.action_id::TEXT as action_id, ac.agent_id::TEXT as agent_id,
                       ac.space_id::TEXT as space_id, ac.kind, ac.payload,
                       ac.required_scopes, ac.status, ac.created_at, ac.updated_at, ac.executed_at,
                       a.name as agent_name, s.name as space_name
                FROM actions ac
                JOIN agents a ON a.agent_id = ac.agent_id
                LEFT JOIN spaces s ON s.space_id = ac.space_id
                WHERE ac.agent_id::TEXT IN ({placeholders})
                ORDER BY ac.created_at DESC
                LIMIT 100""",
            params,
        )

        for row in rows:
            status = row.get("status", "")
            if status in status_counts:
                status_counts[status] += 1

            kind = row.get("kind", "")
            action_kinds_set.add(kind)

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

            payload = row.get("payload") or {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}
            payload_str = json.dumps(payload) if payload else "{}"
            payload_preview = payload_str[:150] + ("..." if len(payload_str) > 150 else "")

            required_scopes = row.get("required_scopes") or []
            if isinstance(required_scopes, str):
                try:
                    required_scopes = json.loads(required_scopes)
                except Exception:
                    required_scopes = []

            actions_data.append(
                {
                    "action_id": str(row.get("action_id", "")),
                    "agent_id": str(row.get("agent_id", "")),
                    "agent_name": row.get("agent_name", ""),
                    "space_id": str(row.get("space_id", "")) if row.get("space_id") else None,
                    "space_name": row.get("space_name"),
                    "kind": kind,
                    "status": status,
                    "payload_str": payload_str,
                    "payload_preview": payload_preview,
                    "required_scopes": required_scopes,
                    "created_at_relative": created_at_relative,
                }
            )

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    # Build spaces by agent for the create modal
    spaces_by_agent: dict = {}
    for space in spaces:
        agent_id = str(space.agent_id)
        if agent_id not in spaces_by_agent:
            spaces_by_agent[agent_id] = []
        spaces_by_agent[agent_id].append(
            {
                "space_id": str(space.space_id),
                "name": space.name,
            }
        )

    return templates.TemplateResponse(
        request,
        "actions.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "actions",
            "actions": actions_data,
            "status_counts": status_counts,
            "action_kinds": sorted(action_kinds_set),
            "agents": agents_data,
            "spaces_by_agent": spaces_by_agent,
            **_get_ws_context(request),
        },
    )


class ActionApproveReject(BaseModel):
    reason: str | None = None


@app.get("/api/actions/{action_id}", name="api_get_action")
def api_get_action(request: Request, action_id: str) -> dict:
    """Get action details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the action and check permission (member role sufficient for viewing)
    rows = db.query(
        """
        SELECT ac.action_id::TEXT as action_id, ac.agent_id::TEXT as agent_id,
               ac.space_id::TEXT as space_id, ac.kind, ac.payload::TEXT as payload,
               ac.required_scopes::TEXT as required_scopes, ac.status,
               ac.created_at::TEXT as created_at, ac.updated_at::TEXT as updated_at,
               ac.executed_at::TEXT as executed_at, ac.approved_by::TEXT as approved_by,
               ac.approved_at::TEXT as approved_at, ac.result::TEXT as result,
               ac.error, ac.completed_at::TEXT as completed_at,
               a.name as agent_name, s.name as space_name
        FROM actions ac
        INNER JOIN agents a ON ac.agent_id = a.agent_id
        LEFT JOIN spaces s ON ac.space_id = s.space_id
        INNER JOIN agent_memberships mb ON ac.agent_id = mb.agent_id
        WHERE ac.action_id = :action_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('member', 'admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"action_id": action_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Action not found or permission denied")

    row = rows[0]

    # Parse JSON fields
    try:
        payload = json.loads(row.get("payload") or "{}")
    except Exception:
        payload = {}
    try:
        required_scopes = json.loads(row.get("required_scopes") or "[]")
    except Exception:
        required_scopes = []
    try:
        result = json.loads(row.get("result") or "null")
    except Exception:
        result = row.get("result")

    return {
        "action_id": row["action_id"],
        "agent_id": row["agent_id"],
        "agent_name": row.get("agent_name", ""),
        "space_id": row.get("space_id"),
        "space_name": row.get("space_name"),
        "kind": row["kind"],
        "payload": payload,
        "required_scopes": required_scopes,
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row.get("updated_at"),
        "executed_at": row.get("executed_at"),
        "approved_by": row.get("approved_by"),
        "approved_at": row.get("approved_at"),
        "result": result,
        "error": row.get("error"),
        "completed_at": row.get("completed_at"),
    }


@app.post("/api/actions/{action_id}/approve", name="api_approve_action")
def api_approve_action(request: Request, action_id: str) -> dict:
    """Approve a proposed action."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the action and check permission (admin/owner only)
    rows = db.query(
        """
        SELECT ac.action_id, ac.agent_id, ac.status
        FROM actions ac
        INNER JOIN agent_memberships mb ON ac.agent_id = mb.agent_id
        WHERE ac.action_id = :action_id::uuid AND mb.user_id = :user_id::uuid AND mb.role IN ('admin', 'owner') AND mb.revoked_at IS NULL
    """,
        {"action_id": action_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Action not found or permission denied")

    action = rows[0]
    if action.get("status") != "proposed":
        raise HTTPException(
            status_code=400, detail=f"Action is not in proposed status (current: {action.get('status')})"
        )

    try:
        db.execute(
            """
            UPDATE actions
            SET status = 'approved', updated_at = now(),
                approved_by = :user_id::uuid, approved_at = now()
            WHERE action_id = :action_id::uuid
        """,
            {"action_id": action_id, "user_id": str(user.user_id)},
        )
    except Exception as e:
        logger.error(f"Failed to approve action: {e}")
        raise HTTPException(status_code=500, detail="Failed to approve action")

    return {"message": "Action approved", "action_id": action_id, "status": "approved"}


@app.post("/api/actions/{action_id}/reject", name="api_reject_action")
def api_reject_action(request: Request, action_id: str, body: ActionApproveReject | None = None) -> dict:
    """Reject a proposed action."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the action and check permission (admin/owner only)
    rows = db.query(
        """
        SELECT ac.action_id, ac.agent_id, ac.status
        FROM actions ac
        INNER JOIN agent_memberships mb ON ac.agent_id = mb.agent_id
        WHERE ac.action_id = :action_id::uuid AND mb.user_id = :user_id::uuid AND mb.role IN ('admin', 'owner') AND mb.revoked_at IS NULL
    """,
        {"action_id": action_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Action not found or permission denied")

    action = rows[0]
    if action.get("status") != "proposed":
        raise HTTPException(
            status_code=400, detail=f"Action is not in proposed status (current: {action.get('status')})"
        )

    try:
        db.execute(
            """
            UPDATE actions SET status = 'rejected', updated_at = now() WHERE action_id = :action_id::uuid
        """,
            {"action_id": action_id},
        )
    except Exception as e:
        logger.error(f"Failed to reject action: {e}")
        raise HTTPException(status_code=500, detail="Failed to reject action")

    return {"message": "Action rejected", "action_id": action_id, "status": "rejected"}


class ActionCreate(BaseModel):
    agent_id: str
    space_id: str | None = None
    kind: str
    payload: dict
    required_scopes: list[str] = []
    auto_approve: bool = False


@app.post("/api/actions", name="api_create_action")
def api_create_action(request: Request, body: ActionCreate) -> dict:
    """Create a new action manually."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check user has admin permission on the agent
    if not check_agent_permission(db, user_id=user.user_id, agent_id=body.agent_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Requires admin permission on the agent")

    # Validate kind
    valid_kinds = ["send_message", "create_memory", "http_request", "device_command", "shell_command"]
    if body.kind not in valid_kinds:
        raise HTTPException(status_code=400, detail=f"Invalid action kind. Valid kinds: {valid_kinds}")

    # If space_id provided, verify it belongs to the agent
    if body.space_id:
        space_rows = db.query(
            """
            SELECT space_id FROM spaces WHERE space_id = :space_id::uuid AND agent_id = :agent_id::uuid
        """,
            {"space_id": body.space_id, "agent_id": body.agent_id},
        )
        if not space_rows:
            raise HTTPException(status_code=400, detail="Space not found or does not belong to agent")

    import json

    action_id = str(uuid.uuid4())
    status = "approved" if body.auto_approve else "proposed"

    try:
        db.execute(
            """
            INSERT INTO actions (action_id, agent_id, space_id, kind, payload, required_scopes, status)
            VALUES (:action_id::uuid, :agent_id::uuid, :space_id::uuid, :kind, :payload::jsonb, :scopes::jsonb, :status)
        """,
            {
                "action_id": action_id,
                "agent_id": body.agent_id,
                "space_id": body.space_id,
                "kind": body.kind,
                "payload": json.dumps(body.payload),
                "scopes": json.dumps(body.required_scopes),
                "status": status,
            },
        )

        # If auto-approved, update with approver info
        if body.auto_approve:
            db.execute(
                """
                UPDATE actions SET approved_by = :user_id::uuid, approved_at = now() WHERE action_id = :action_id::uuid
            """,
                {"action_id": action_id, "user_id": str(user.user_id)},
            )

    except Exception as e:
        logger.error(f"Failed to create action: {e}")
        raise HTTPException(status_code=500, detail="Failed to create action")

    return {
        "message": "Action created",
        "action_id": action_id,
        "status": status,
        "auto_approved": body.auto_approve,
    }


@app.get("/api/events/{event_id}", name="api_get_event")
def api_get_event(request: Request, event_id: str) -> dict:
    """Get event details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    rows = db.query(
        """
        SELECT e.event_id::TEXT as event_id, e.agent_id::TEXT as agent_id,
               e.space_id::TEXT as space_id, e.device_id::TEXT as device_id,
               e.person_id::TEXT as person_id, e.type, e.payload::TEXT as payload,
               e.created_at::TEXT as created_at,
               a.name as agent_name, s.name as space_name,
               d.name as device_name, p.display_name as person_name
        FROM events e
        INNER JOIN agents a ON e.agent_id = a.agent_id
        LEFT JOIN spaces s ON e.space_id = s.space_id
        LEFT JOIN devices d ON e.device_id = d.device_id
        LEFT JOIN people p ON e.person_id = p.person_id
        INNER JOIN agent_memberships mb ON e.agent_id = mb.agent_id
        WHERE e.event_id = :event_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('member', 'admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"event_id": event_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Event not found or permission denied")

    row = rows[0]

    # Parse JSON payload
    try:
        payload = json.loads(row.get("payload") or "{}")
    except Exception:
        payload = {}

    return {
        "event_id": row["event_id"],
        "agent_id": row["agent_id"],
        "agent_name": row.get("agent_name", ""),
        "space_id": row.get("space_id"),
        "space_name": row.get("space_name"),
        "device_id": row.get("device_id"),
        "device_name": row.get("device_name"),
        "person_id": row.get("person_id"),
        "person_name": row.get("person_name"),
        "type": row["type"],
        "payload": payload,
        "created_at": row["created_at"],
    }


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

            events_data.append(
                {
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
                }
            )

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]
    spaces_data = [{"space_id": s.space_id, "name": s.name} for s in spaces]

    return templates.TemplateResponse(
        request,
        "events.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "events",
            "events": events_data,
            "event_types": sorted(event_types_set),
            "agents": agents_data,
            "spaces": spaces_data,
            **_get_ws_context(request),
        },
    )


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
        import json
        from datetime import datetime, timezone

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

            memories_data.append(
                {
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
                }
            )

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]
    spaces_data = [{"space_id": s.space_id, "name": s.name} for s in spaces]

    return templates.TemplateResponse(
        request,
        "memories.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "memories",
            "memories": memories_data,
            "tier_counts": tier_counts,
            "agents": agents_data,
            "spaces": spaces_data,
            **_get_ws_context(request),
        },
    )


@app.delete("/api/memories/{memory_id}", name="api_delete_memory")
def api_delete_memory(request: Request, memory_id: str) -> dict:
    """Delete a memory."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the memory and check permission
    rows = db.query(
        """
        SELECT m.memory_id, m.agent_id
        FROM memories m
        INNER JOIN agent_memberships mb ON m.agent_id = mb.agent_id
        WHERE m.memory_id = :memory_id::uuid AND mb.user_id = :user_id::uuid AND mb.role IN ('admin', 'owner') AND mb.revoked_at IS NULL
    """,
        {"memory_id": memory_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Memory not found or permission denied")

    try:
        db.execute(
            """
            DELETE FROM memories WHERE memory_id = :memory_id::uuid
        """,
            {"memory_id": memory_id},
        )
    except Exception as e:
        logger.error(f"Failed to delete memory: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete memory")

    return {"message": "Memory deleted", "memory_id": memory_id}


@app.get("/api/memories/{memory_id}", name="api_get_memory")
def api_get_memory(request: Request, memory_id: str) -> dict:
    """Get memory details."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Get the memory and check permission (member role sufficient for viewing)
    rows = db.query(
        """
        SELECT m.memory_id::TEXT as memory_id, m.agent_id::TEXT as agent_id,
               m.space_id::TEXT as space_id, m.tier, m.content,
               m.participants::TEXT as participants,
               m.provenance::TEXT as provenance,
               m.retention::TEXT as retention,
               m.created_at::TEXT as created_at,
               a.name as agent_name, s.name as space_name
        FROM memories m
        INNER JOIN agents a ON m.agent_id = a.agent_id
        LEFT JOIN spaces s ON m.space_id = s.space_id
        INNER JOIN agent_memberships mb ON m.agent_id = mb.agent_id
        WHERE m.memory_id = :memory_id::uuid
          AND mb.user_id = :user_id::uuid
          AND mb.role IN ('member', 'admin', 'owner')
          AND mb.revoked_at IS NULL
    """,
        {"memory_id": memory_id, "user_id": str(user.user_id)},
    )

    if not rows:
        raise HTTPException(status_code=404, detail="Memory not found or permission denied")

    row = rows[0]

    # Parse JSON fields
    try:
        participants = json.loads(row.get("participants") or "[]")
    except Exception:
        participants = []
    try:
        provenance = json.loads(row.get("provenance") or "{}")
    except Exception:
        provenance = {}
    try:
        retention = json.loads(row.get("retention") or "{}")
    except Exception:
        retention = {}

    return {
        "memory_id": row["memory_id"],
        "agent_id": row["agent_id"],
        "agent_name": row.get("agent_name", ""),
        "space_id": row.get("space_id"),
        "space_name": row.get("space_name"),
        "tier": row["tier"],
        "content": row["content"],
        "participants": participants,
        "provenance": provenance,
        "retention": retention,
        "created_at": row["created_at"],
    }


def _get_file_icon(filename: str) -> str:
    """Get Font Awesome icon class for a file type."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    icon_map = {
        "pdf": "fa-file-pdf",
        "doc": "fa-file-word",
        "docx": "fa-file-word",
        "xls": "fa-file-excel",
        "xlsx": "fa-file-excel",
        "ppt": "fa-file-powerpoint",
        "pptx": "fa-file-powerpoint",
        "jpg": "fa-file-image",
        "jpeg": "fa-file-image",
        "png": "fa-file-image",
        "gif": "fa-file-image",
        "webp": "fa-file-image",
        "mp3": "fa-file-audio",
        "wav": "fa-file-audio",
        "ogg": "fa-file-audio",
        "flac": "fa-file-audio",
        "mp4": "fa-file-video",
        "webm": "fa-file-video",
        "mov": "fa-file-video",
        "avi": "fa-file-video",
        "zip": "fa-file-archive",
        "tar": "fa-file-archive",
        "gz": "fa-file-archive",
        "rar": "fa-file-archive",
        "txt": "fa-file-alt",
        "md": "fa-file-alt",
        "py": "fa-file-code",
        "js": "fa-file-code",
        "ts": "fa-file-code",
        "html": "fa-file-code",
        "css": "fa-file-code",
        "json": "fa-file-code",
    }
    return icon_map.get(ext, "fa-file")


def _format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


@app.get("/artifacts", name="gui_artifacts")
def gui_artifacts(request: Request) -> Response:
    """Artifacts browser."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/artifacts")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # List artifacts from S3 for each agent
    agent_ids = [a.agent_id for a in agents]
    artifacts_data = []
    total_size = 0

    if agent_ids and _cfg.artifact_bucket:
        from datetime import datetime, timezone

        s3 = _get_s3()
        agent_name_map = {a.agent_id: a.name for a in agents}

        for agent_id in agent_ids:
            prefix = f"artifacts/agent_id={agent_id}/"
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=_cfg.artifact_bucket, Prefix=prefix):
                    for obj in page.get("Contents", []):
                        key = obj.get("Key", "")
                        size = obj.get("Size", 0)
                        last_modified = obj.get("LastModified")
                        total_size += size

                        # Extract filename from key
                        filename = key.split("/")[-1]
                        # Remove UUID prefix if present
                        if "_" in filename and len(filename.split("_")[0]) == 36:
                            filename = "_".join(filename.split("_")[1:])

                        # Calculate relative time
                        created_at_relative = None
                        if last_modified:
                            now = datetime.now(timezone.utc)
                            delta = now - last_modified
                            if delta.days > 0:
                                created_at_relative = f"{delta.days}d ago"
                            elif delta.seconds >= 3600:
                                created_at_relative = f"{delta.seconds // 3600}h ago"
                            else:
                                created_at_relative = f"{delta.seconds // 60}m ago"

                        # Generate presigned download URL
                        download_url = s3.generate_presigned_url(
                            ClientMethod="get_object",
                            Params={"Bucket": _cfg.artifact_bucket, "Key": key},
                            ExpiresIn=3600,
                        )

                        artifacts_data.append(
                            {
                                "key": key,
                                "filename": filename,
                                "agent_id": agent_id,
                                "agent_name": agent_name_map.get(agent_id, "Unknown"),
                                "size": size,
                                "size_formatted": _format_file_size(size),
                                "created_at_relative": created_at_relative,
                                "icon": _get_file_icon(filename),
                                "download_url": download_url,
                            }
                        )
            except Exception as e:
                logger.warning(f"Failed to list artifacts for agent {agent_id}: {e}")

        # Sort by last modified (most recent first)
        artifacts_data.sort(key=lambda x: x.get("created_at_relative", ""), reverse=False)

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    return templates.TemplateResponse(
        request,
        "artifacts.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "artifacts",
            "artifacts": artifacts_data,
            "total_size_formatted": _format_file_size(total_size),
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


class ArtifactPresign(BaseModel):
    agent_id: str
    filename: str
    content_type: str = "application/octet-stream"


@app.post("/api/artifacts/presign", name="api_presign_upload")
def api_presign_upload(request: Request, body: ArtifactPresign) -> dict:
    """Get presigned URL for uploading an artifact."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()

    # Check admin/owner permission
    if not check_agent_permission(db, agent_id=body.agent_id, user_id=user.user_id, required_role="admin"):
        raise HTTPException(status_code=403, detail="Admin permission required")

    if not _cfg.artifact_bucket:
        raise HTTPException(status_code=500, detail="Artifact bucket not configured")

    import uuid as uuid_mod

    key = f"artifacts/agent_id={body.agent_id}/{uuid_mod.uuid4()}_{body.filename}"
    s3 = _get_s3()
    url = s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={"Bucket": _cfg.artifact_bucket, "Key": key, "ContentType": body.content_type},
        ExpiresIn=900,
    )

    return {"upload_url": url, "key": key, "bucket": _cfg.artifact_bucket}


@app.get("/audit", name="gui_audit")
def gui_audit(request: Request) -> Response:
    """Audit log viewer."""
    user = _gui_get_user(request)
    if not user:
        return _gui_redirect_to_login(request=request, next_path="/audit")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # List audit entries from S3 for each agent
    agent_ids = [a.agent_id for a in agents]
    entries_data = []
    entry_types = set()

    if agent_ids and _cfg.audit_bucket:
        from datetime import datetime, timezone

        s3 = _get_s3()
        agent_name_map = {a.agent_id: a.name for a in agents}

        for agent_id in agent_ids:
            prefix = f"audit/agent_id={agent_id}/"
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=_cfg.audit_bucket, Prefix=prefix, MaxKeys=100):
                    for obj in page.get("Contents", []):
                        key = obj.get("Key", "")
                        last_modified = obj.get("LastModified")

                        # Download and parse the audit entry
                        try:
                            resp = s3.get_object(Bucket=_cfg.audit_bucket, Key=key)
                            body = resp["Body"].read().decode("utf-8")
                            import json

                            entry = json.loads(body)

                            # Calculate relative time
                            ts_relative = None
                            if last_modified:
                                now = datetime.now(timezone.utc)
                                delta = now - last_modified
                                if delta.days > 0:
                                    ts_relative = f"{delta.days}d ago"
                                elif delta.seconds >= 3600:
                                    ts_relative = f"{delta.seconds // 3600}h ago"
                                else:
                                    ts_relative = f"{delta.seconds // 60}m ago"

                            # Data preview (truncate to 100 chars)
                            data_str = json.dumps(entry.get("data", {}))
                            data_preview = data_str[:100] + "..." if len(data_str) > 100 else data_str

                            entry_type = entry.get("type", "unknown")
                            entry_types.add(entry_type)

                            entries_data.append(
                                {
                                    "entry_id": entry.get("entry_id", ""),
                                    "agent_id": agent_id,
                                    "agent_name": agent_name_map.get(agent_id, "Unknown"),
                                    "type": entry_type,
                                    "ts": entry.get("ts", ""),
                                    "ts_relative": ts_relative,
                                    "hash": entry.get("hash", ""),
                                    "prev_hash": entry.get("prev_hash", "GENESIS"),
                                    "data": entry.get("data", {}),
                                    "data_preview": data_preview,
                                }
                            )
                        except Exception as e:
                            logger.warning(f"Failed to parse audit entry {key}: {e}")
            except Exception as e:
                logger.warning(f"Failed to list audit entries for agent {agent_id}: {e}")

        # Sort by timestamp (most recent first)
        entries_data.sort(key=lambda x: x.get("ts", ""), reverse=True)
        # Limit to 100 most recent
        entries_data = entries_data[:100]

    agents_data = [{"agent_id": a.agent_id, "name": a.name, "role": a.role} for a in agents]

    import json

    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "audit",
            "entries": entries_data,
            "entries_json": json.dumps(entries_data),
            "entry_types": sorted(entry_types),
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


@app.post("/api/audit/verify", name="api_audit_verify")
def api_audit_verify(request: Request) -> dict:
    """Verify the integrity of the audit chain."""
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)

    # Only admin/owner can verify
    admin_agents = [a for a in agents if a.role in ("admin", "owner")]
    if not admin_agents:
        raise HTTPException(status_code=403, detail="Admin permission required")

    if not _cfg.audit_bucket:
        return {"valid": False, "error": "Audit bucket not configured", "entries_checked": 0}

    import hashlib
    import json
    from typing import Any as _Any

    def _canon_json(obj: _Any) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    s3 = _get_s3()
    entries_checked = 0
    errors = []

    for agent in admin_agents:
        agent_id = agent.agent_id
        prefix = f"audit/agent_id={agent_id}/"
        entries = []

        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=_cfg.audit_bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    try:
                        resp = s3.get_object(Bucket=_cfg.audit_bucket, Key=key)
                        body = resp["Body"].read().decode("utf-8")
                        entry = json.loads(body)
                        entries.append(entry)
                    except Exception as e:
                        errors.append(f"Failed to read {key}: {e}")
        except Exception as e:
            errors.append(f"Failed to list audit for agent {agent_id}: {e}")
            continue

        # Sort by timestamp
        entries.sort(key=lambda x: x.get("ts", ""))

        # Verify chain
        expected_prev = "GENESIS"
        for entry in entries:
            prev_hash = entry.get("prev_hash", "")
            if prev_hash != expected_prev:
                errors.append(
                    f"Chain break at entry {entry.get('entry_id')}: expected prev_hash {expected_prev[:12]}..., got {prev_hash[:12]}..."
                )

            # Verify hash
            stored_hash = entry.get("hash", "")
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            computed_hash = _sha256_hex(prev_hash + _canon_json(entry_copy))
            if computed_hash != stored_hash:
                errors.append(f"Hash mismatch at entry {entry.get('entry_id')}")

            expected_prev = stored_hash
            entries_checked += 1

    if errors:
        return {"valid": False, "error": "; ".join(errors[:5]), "entries_checked": entries_checked}

    return {"valid": True, "entries_checked": entries_checked}


@app.get("/profile", name="profile")
def gui_profile(request: Request) -> Response:
    """User profile page - shows account info and agent memberships."""
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(
            request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear
        )

    db = _get_db()
    agents = list_agents_for_user(db, user_id=user.user_id)
    agents_data = [
        {
            "agent_id": str(a.agent_id),
            "name": a.name,
            "role": a.role,
            "relationship_label": a.relationship_label,
        }
        for a in agents
    ]

    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "user": {
                "email": user.email,
                "user_id": str(user.user_id),
                "cognito_sub": getattr(user, "cognito_sub", None),
            },
            "stage": _cfg.stage,
            "active_page": "profile",
            "agents": agents_data,
            **_get_ws_context(request),
        },
    )


@app.get("/livekit-test", name="gui_livekit_test")
def gui_livekit_test(request: Request, space_id: str | None = None) -> Response:
    """LiveKit test page - join a LiveKit room mapped from a Marvain space."""
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(
            request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear
        )

    # Fetch spaces for dropdown
    spaces = list_spaces_for_user(_get_db(), user_id=user.user_id)
    spaces_data = [
        {
            "space_id": sp.space_id,
            "name": sp.name,
            "agent_name": sp.agent_name,
        }
        for sp in spaces
    ]

    selected_space = str(space_id or "").strip()
    token_url = _gui_path(request, "/livekit/token")

    return templates.TemplateResponse(
        request,
        "livekit_test.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "livekit",
            "spaces": spaces_data,
            "selected_space": selected_space,
            "token_url": token_url,
            **_get_ws_context(request),
        },
    )


@app.post("/livekit/token", response_model=LiveKitTokenOut)
async def gui_livekit_token(request: Request, body: LiveKitTokenIn) -> LiveKitTokenOut:
    user = _gui_get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return await _mint_livekit_token_for_user(user=user, space_id=body.space_id)


@app.get("/agents/{agent_id}", name="gui_agent_detail")
def gui_agent_detail(request: Request, agent_id: str) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(
            request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear
        )

    db = _get_db()
    # Ensure the user can see this agent by filtering their memberships.
    agents = list_agents_for_user(db, user_id=user.user_id)
    match = next((a for a in agents if a.agent_id == agent_id), None)
    if not match:
        return PlainTextResponse("not found", status_code=404)

    # Fetch members for this agent
    members_rows = db.query(
        "SELECT m.user_id, m.role, m.relationship_label, m.created_at, u.email "
        "FROM agent_memberships m LEFT JOIN users u ON m.user_id = u.user_id "
        "WHERE m.agent_id = :agent_id::uuid AND m.revoked_at IS NULL ORDER BY m.created_at",
        {"agent_id": agent_id},
    )
    members = [
        {
            "user_id": str(row.get("user_id", "")),
            "role": row.get("role", "member"),
            "relationship_label": row.get("relationship_label"),
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

    return templates.TemplateResponse(
        request,
        "agent_detail.html",
        {
            "user": {"email": user.email, "user_id": str(user.user_id)},
            "stage": _cfg.stage,
            "active_page": "agents",
            "agent": agent_data,
            "members": members,
            **_get_ws_context(request),
        },
    )
