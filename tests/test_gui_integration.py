"""
Integration tests for GUI endpoints using requests against a running server.

These tests require:
1. GUI server running: `marvain gui start`
2. Valid session cookie (or tests will verify redirect to login)

Run with: pytest tests/test_gui_integration.py -v

To run authenticated tests, set environment variables:
  GUI_SESSION_COOKIE=<your session cookie value>
  GUI_BASE_URL=https://127.0.0.1:8084  (default)
"""

import os
import pytest
import requests
import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("GUI_BASE_URL", "https://127.0.0.1:8084")
SESSION_COOKIE = os.environ.get("GUI_SESSION_COOKIE", "")


def get_session() -> requests.Session:
    """Create a requests session with optional auth cookie."""
    session = requests.Session()
    session.verify = False  # Accept self-signed certs
    if SESSION_COOKIE:
        session.cookies.set("session", SESSION_COOKIE)
    return session


def is_server_running() -> bool:
    """Check if the GUI server is running."""
    try:
        r = requests.get(f"{BASE_URL}/health", verify=False, timeout=5)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False


# Skip all tests if server not running
pytestmark = pytest.mark.skipif(
    not is_server_running(),
    reason="GUI server not running. Start with: marvain gui start"
)


class TestPublicEndpoints:
    """Test endpoints that don't require authentication."""

    def test_health_returns_200(self):
        """Health endpoint should return 200."""
        r = requests.get(f"{BASE_URL}/health", verify=False)
        assert r.status_code == 200
        data = r.json()
        assert data.get("ok") is True or data.get("status") == "ok"

    def test_login_returns_redirect_to_cognito(self):
        """Login should redirect to Cognito OAuth."""
        session = get_session()
        r = session.get(f"{BASE_URL}/login", allow_redirects=False)
        assert r.status_code in (302, 307)
        location = r.headers.get("location", "")
        assert "cognito" in location.lower() or "oauth" in location.lower()

    def test_logged_out_page_renders(self):
        """Logged out page should render."""
        r = requests.get(f"{BASE_URL}/logged-out", verify=False)
        assert r.status_code == 200
        assert "logged out" in r.text.lower() or "sign in" in r.text.lower()


class TestAuthenticatedEndpointsRedirect:
    """Test that protected endpoints redirect to login when unauthenticated."""

    PROTECTED_ROUTES = [
        "/",
        "/profile",
        "/agents",
        "/spaces",
        "/devices",
        "/people",
        "/remotes",
        "/actions",
        "/events",
        "/memories",
        "/artifacts",
        "/audit",
        "/livekit-test",
    ]

    @pytest.mark.parametrize("path", PROTECTED_ROUTES)
    def test_protected_route_redirects_to_login(self, path):
        """Protected routes should redirect to login when no session."""
        session = requests.Session()
        session.verify = False
        # Don't set any cookies
        r = session.get(f"{BASE_URL}{path}", allow_redirects=False)
        assert r.status_code in (302, 307), f"{path} should redirect, got {r.status_code}"
        location = r.headers.get("location", "")
        assert "/login" in location, f"{path} should redirect to /login, got {location}"


@pytest.mark.skipif(not SESSION_COOKIE, reason="GUI_SESSION_COOKIE not set")
class TestAuthenticatedEndpoints:
    """Test endpoints with valid session cookie."""

    def test_home_renders_dashboard(self):
        """Home page should render dashboard with agents."""
        session = get_session()
        r = session.get(f"{BASE_URL}/")
        assert r.status_code == 200
        assert "dashboard" in r.text.lower() or "agent" in r.text.lower()

    def test_profile_renders_user_info(self):
        """Profile page should show user information."""
        session = get_session()
        r = session.get(f"{BASE_URL}/profile")
        assert r.status_code == 200
        assert "profile" in r.text.lower() or "email" in r.text.lower()

    def test_agents_renders_list(self):
        """Agents page should render agent list."""
        session = get_session()
        r = session.get(f"{BASE_URL}/agents")
        assert r.status_code == 200
        assert "agent" in r.text.lower()

    def test_spaces_renders_list(self):
        """Spaces page should render space list."""
        session = get_session()
        r = session.get(f"{BASE_URL}/spaces")
        assert r.status_code == 200
        assert "space" in r.text.lower()

    def test_devices_renders_list(self):
        """Devices page should render device list."""
        session = get_session()
        r = session.get(f"{BASE_URL}/devices")
        assert r.status_code == 200
        assert "device" in r.text.lower()

    def test_remotes_renders_list(self):
        """Remotes page should render remote list."""
        session = get_session()
        r = session.get(f"{BASE_URL}/remotes")
        assert r.status_code == 200
        assert "remote" in r.text.lower()

    def test_events_renders_stream(self):
        """Events page should render event stream."""
        session = get_session()
        r = session.get(f"{BASE_URL}/events")
        assert r.status_code == 200
        assert "event" in r.text.lower()

    def test_livekit_test_renders(self):
        """LiveKit test page should render."""
        session = get_session()
        r = session.get(f"{BASE_URL}/livekit-test")
        assert r.status_code == 200
        assert "livekit" in r.text.lower() or "room" in r.text.lower()

    def test_people_renders_list(self):
        """People page should render people list."""
        session = get_session()
        r = session.get(f"{BASE_URL}/people")
        assert r.status_code == 200
        assert "people" in r.text.lower() or "person" in r.text.lower()

    def test_actions_renders_dashboard(self):
        """Actions page should render actions dashboard."""
        session = get_session()
        r = session.get(f"{BASE_URL}/actions")
        assert r.status_code == 200
        assert "action" in r.text.lower()

    def test_memories_renders_browser(self):
        """Memories page should render memories browser."""
        session = get_session()
        r = session.get(f"{BASE_URL}/memories")
        assert r.status_code == 200
        assert "memor" in r.text.lower()

    def test_artifacts_renders_browser(self):
        """Artifacts page should render artifacts browser."""
        session = get_session()
        r = session.get(f"{BASE_URL}/artifacts")
        assert r.status_code == 200
        assert "artifact" in r.text.lower()

    def test_audit_renders_log(self):
        """Audit page should render audit log."""
        session = get_session()
        r = session.get(f"{BASE_URL}/audit")
        assert r.status_code == 200
        assert "audit" in r.text.lower()


@pytest.mark.skipif(not SESSION_COOKIE, reason="GUI_SESSION_COOKIE not set")
class TestGUIApiEndpoints:
    """Test GUI API endpoints (POST/DELETE actions)."""

    def test_remotes_status_returns_json(self):
        """GET /api/remotes/status should return JSON."""
        session = get_session()
        r = session.get(f"{BASE_URL}/api/remotes/status")
        assert r.status_code == 200
        data = r.json()
        assert "remotes" in data

    def test_livekit_token_requires_space_id(self):
        """POST /livekit/token requires space_id."""
        session = get_session()
        r = session.post(f"{BASE_URL}/livekit/token", json={})
        # Should fail with 400 or 422 for missing space_id
        assert r.status_code in (400, 422)

    def test_create_agent_requires_name(self):
        """POST /api/agents requires name field."""
        session = get_session()
        r = session.post(f"{BASE_URL}/api/agents", json={})
        assert r.status_code in (400, 422)

    def test_create_space_requires_name(self):
        """POST /api/spaces requires name field."""
        session = get_session()
        r = session.post(f"{BASE_URL}/api/spaces", json={})
        assert r.status_code in (400, 422)

    def test_create_remote_requires_fields(self):
        """POST /api/remotes requires name and address."""
        session = get_session()
        r = session.post(f"{BASE_URL}/api/remotes", json={})
        assert r.status_code in (400, 422)


class TestAPIEndpointsNoAuth:
    """Test API endpoints without authentication."""

    def test_v1_me_requires_auth(self):
        """GET /v1/me requires authentication."""
        r = requests.get(f"{BASE_URL}/v1/me", verify=False)
        assert r.status_code == 401

    def test_v1_agents_requires_auth(self):
        """GET /v1/agents requires authentication."""
        r = requests.get(f"{BASE_URL}/v1/agents", verify=False)
        assert r.status_code == 401

    def test_v1_events_requires_device_token(self):
        """POST /v1/events requires device token."""
        r = requests.post(f"{BASE_URL}/v1/events", json={}, verify=False)
        assert r.status_code == 401

    def test_v1_admin_bootstrap_requires_admin_key(self):
        """POST /v1/admin/bootstrap requires admin key."""
        r = requests.post(f"{BASE_URL}/v1/admin/bootstrap", json={}, verify=False)
        assert r.status_code in (401, 403)

