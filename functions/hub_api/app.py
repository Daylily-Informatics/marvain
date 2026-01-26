"""Full Hub application with both API and GUI routes.

This module is for LOCAL DEVELOPMENT ONLY. It includes:
- All API routes from api_app.py
- GUI routes (login, callback, logout, home, profile, livekit-test, agent detail)

For Lambda deployment, use api_app.py instead (via lambda_handler.py).
"""
from __future__ import annotations

import html
import logging
import os
import secrets
import urllib.parse

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
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


@app.get("/", name="home")
def gui_home(request: Request) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    items = []
    agents = list_agents_for_user(_get_db(), user_id=user.user_id)
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


@app.get("/livekit-test", name="livekit_test")
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

# 2. Create .env file with your credentials
cat &gt; .env &lt;&lt;EOF
LIVEKIT_URL=wss://marvain-dev-fo5ki513.livekit.cloud
LIVEKIT_API_KEY=your-api-key
LIVEKIT_API_SECRET=your-api-secret
OPENAI_API_KEY=your-openai-key
HUB_API_BASE=https://your-hub-api.execute-api.us-east-1.amazonaws.com/dev
HUB_DEVICE_TOKEN=your-device-token
SPACE_ID=your-space-id
EOF

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


@app.get("/agents/{agent_id}", name="agent_detail")
def gui_agent_detail(request: Request, agent_id: str) -> Response:
    user = _gui_get_user(request)
    if not user:
        clear = bool(str(request.cookies.get(_GUI_ACCESS_TOKEN_COOKIE) or "").strip())
        return _gui_redirect_to_login(request=request, next_path=str(request.scope.get("path") or "/"), clear_session=clear)

    # Ensure the user can see this agent by filtering their memberships.
    agents = list_agents_for_user(_get_db(), user_id=user.user_id)
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
