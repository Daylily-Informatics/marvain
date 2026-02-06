from __future__ import annotations

import dataclasses
import html
import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

# Module-level cached module to ensure all test classes share the same module instance.
# This is critical because route handlers capture function references at import time,
# so mocking functions on a different module instance won't affect route behavior.
_cached_hub_api_module = None


def _load_hub_api_app_module():
    """Load functions/hub_api/app.py as a module without requiring it be a package.

    Returns a cached module if already loaded to ensure all test classes share
    the same module instance and route handlers.
    """
    global _cached_hub_api_module
    if _cached_hub_api_module is not None:
        return _cached_hub_api_module

    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    # Add hub_api directory to path so api_app imports work
    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    # Ensure SessionMiddleware cookies are not marked Secure in tests
    # (httpx TestClient uses http://testserver).
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    # Make session secret deterministic for stable cookie behavior.
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    # Clear cached api_app module to prevent route duplication when reloading
    # app.py (which imports api_app and adds routes to the same app object)
    for mod_name in ["api_app", "hub_api_app_for_tests_gui"]:
        if mod_name in sys.modules:
            del sys.modules[mod_name]

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests_gui", app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)

    _cached_hub_api_module = mod
    return mod


class TestGuiApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        # Capture originals so per-test mocks don't leak across tests.
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_ensure_user_row = cls.mod.ensure_user_row
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_get_secret_json = cls.mod.get_secret_json
        cls._orig_mint_livekit_join_token = cls.mod.mint_livekit_join_token
        cls._orig_check_agent_permission = cls.mod.check_agent_permission
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        # Fresh client per test to avoid cookie persistence across tests.
        self.client = self.__class__._TestClient(self.mod.app)

        # Reset any module-level mocks applied by other tests.
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod.ensure_user_row = self.__class__._orig_ensure_user_row
        self.mod.list_agents_for_user = self.__class__._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self.__class__._orig_list_spaces_for_user
        self.mod.get_secret_json = self.__class__._orig_get_secret_json
        self.mod.mint_livekit_join_token = self.__class__._orig_mint_livekit_join_token
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission
        self.mod._get_db = self.__class__._orig_get_db

        # Provide Cognito config for GUI routes.
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            cognito_domain="marvain-dev.auth.us-west-2.amazoncognito.com",
            cognito_user_pool_id="pool-123",
            cognito_user_pool_client_id="client-123",
            cognito_redirect_uri="http://testserver/auth/callback",
        )

    def tearDown(self) -> None:
        # Restore originals after each test to prevent pollution to other test classes.
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod.ensure_user_row = self.__class__._orig_ensure_user_row
        self.mod.list_agents_for_user = self.__class__._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self.__class__._orig_list_spaces_for_user
        self.mod.get_secret_json = self.__class__._orig_get_secret_json
        self.mod.mint_livekit_join_token = self.__class__._orig_mint_livekit_join_token
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission
        self.mod._get_db = self.__class__._orig_get_db

    def test_login_redirect_sets_state_and_verifier_cookies(self) -> None:
        r = self.client.get("/login", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        loc = r.headers.get("location") or ""
        self.assertIn("https://marvain-dev.auth.us-west-2.amazoncognito.com/oauth2/authorize?", loc)
        self.assertIn("response_type=code", loc)
        self.assertIn("client_id=client-123", loc)
        self.assertIn("redirect_uri=http%3A%2F%2Ftestserver%2Fauth%2Fcallback", loc)
        self.assertIn("scope=openid+email+profile", loc)
        self.assertIn("state=", loc)

        # Starlette TestClient uses httpx; headers API varies slightly by version.
        if hasattr(r.headers, "get_list"):
            set_cookie_headers = r.headers.get_list("set-cookie")
        elif hasattr(r.headers, "getlist"):
            set_cookie_headers = r.headers.getlist("set-cookie")
        else:
            v = r.headers.get("set-cookie")
            set_cookie_headers = [v] if v else []

        set_cookie = "\n".join(set_cookie_headers)
        # SessionMiddleware cookie
        self.assertIn("marvain_session=", set_cookie)

    def test_home_redirects_to_login_without_cookie(self) -> None:
        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/login?next=%2F")

    def test_livekit_test_redirects_to_login_without_cookie(self) -> None:
        r = self.client.get("/livekit-test", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/login?next=%2Flivekit-test")

    def test_auth_callback_rejects_invalid_state(self) -> None:
        r = self.client.get("/auth/callback?code=c1&state=s1", follow_redirects=False)
        self.assertEqual(r.status_code, 400)

    def test_auth_callback_sets_access_cookie_on_success(self) -> None:
        # First hit /login to establish a session cookie with deterministic state.
        with mock.patch.object(self.mod.secrets, "token_urlsafe", return_value="s1"):
            self.client.get("/login", follow_redirects=False)

        with mock.patch.object(self.mod, "exchange_code_for_tokens", new_callable=mock.AsyncMock) as ex:
            ex.return_value = {"id_token": "itok"}
            with mock.patch.object(self.mod, "get_user_info_from_tokens", new_callable=mock.AsyncMock) as gui:
                gui.return_value = self.mod.CognitoUserInfo(
                    sub="sub-1",
                    email="u1@example.com",
                    name="U1",
                    cognito_groups=[],
                    roles=[],
                    email_verified=True,
                )
                self.mod.ensure_user_row = mock.Mock(return_value="u1")
                r = self.client.get(
                    "/auth/callback?code=c1&state=s1",
                    follow_redirects=False,
                )
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/")

        if hasattr(r.headers, "get_list"):
            set_cookie_headers = r.headers.get_list("set-cookie")
        elif hasattr(r.headers, "getlist"):
            set_cookie_headers = r.headers.getlist("set-cookie")
        else:
            v = r.headers.get("set-cookie")
            set_cookie_headers = [v] if v else []
        set_cookie = "\n".join(set_cookie_headers)
        self.assertIn("marvain_session=", set_cookie)

    def test_home_renders_agents_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                types.SimpleNamespace(agent_id="a1", name="Agent One", role="owner", relationship_label=None, disabled=False),
                types.SimpleNamespace(agent_id="a2", name="Agent Two", role="member", relationship_label=None, disabled=True),
            ]
        )
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])

        # Mock the database object to return empty results for remotes/actions queries
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Your Agents", r.text)
        self.assertIn("Agent One", r.text)
        self.assertIn("Agent Two", r.text)

    def test_home_redirects_to_login_and_clears_invalid_access_cookie(self) -> None:
        # We no longer authenticate via `marvain_access_token`, but we still clear it
        # for backward-compat when an unauthenticated browser shows up with it.
        self.client.cookies.set("marvain_access_token", "atok")

        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/login?next=%2F")

        if hasattr(r.headers, "get_list"):
            set_cookie_headers = r.headers.get_list("set-cookie")
        elif hasattr(r.headers, "getlist"):
            set_cookie_headers = r.headers.getlist("set-cookie")
        else:
            v = r.headers.get("set-cookie")
            set_cookie_headers = [v] if v else []

        set_cookie = "\n".join(set_cookie_headers)
        # Starlette delete_cookie emits a Set-Cookie that includes Max-Age=0 and empty value.
        self.assertIn("marvain_access_token=", set_cookie)
        self.assertIn("Max-Age=0", set_cookie)

    def test_livekit_test_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        # Mock list_spaces_for_user to return test spaces
        self.mod.list_spaces_for_user = mock.Mock(return_value=[
            self.mod.SpaceInfo(space_id="sp-1", name="home", agent_id="ag-1", agent_name="Forge"),
        ])

        r = self.client.get("/livekit-test")
        self.assertEqual(r.status_code, 200)
        self.assertIn("LiveKit Test", r.text)
        self.assertIn("livekit-client.umd.min.js", r.text)
        # Check that dropdown is rendered with the space
        self.assertIn("<select", r.text)
        self.assertIn("sp-1", r.text)
        self.assertIn("home (Forge)", r.text)

    def test_livekit_test_escapes_space_id_in_html(self) -> None:
        # Regression test for reflected XSS: user-controlled `space_id` must not be
        # injected into <script> blocks.
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        # Mock list_spaces_for_user with a malicious space_id
        space_id = "</script><img src=x onerror=alert(1)>"
        self.mod.list_spaces_for_user = mock.Mock(return_value=[
            self.mod.SpaceInfo(space_id=space_id, name="evil", agent_id="ag-1", agent_name="Forge"),
        ])

        r = self.client.get("/livekit-test", params={"space_id": space_id})
        self.assertEqual(r.status_code, 200)

        escaped = html.escape(space_id, quote=True)
        # The space_id should be escaped in the option value attribute
        self.assertIn(f'value="{escaped}"', r.text)
        # Raw malicious script should never appear
        self.assertNotIn(space_id, r.text)

    def test_gui_livekit_token_mints_token(self) -> None:
        # Mock user authentication for GUI route.
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )

        # Mock the token minting function that's imported from api_app.
        # The GUI route calls _mint_livekit_token_for_user which is imported from api_app,
        # so we need to mock it on the app module where it's used.
        # Note: _mint_livekit_token_for_user is now async, so we use AsyncMock.
        expected_response = self.mod.LiveKitTokenOut(
            url="wss://livekit.example",
            token="jwt",
            room="space-1:abc123",  # Ephemeral room format
            identity="user:u1",
        )
        self.mod._mint_livekit_token_for_user = mock.AsyncMock(return_value=expected_response)

        r = self.client.post("/livekit/token", json={"space_id": "space-1"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "wss://livekit.example")
        self.assertEqual(body["token"], "jwt")
        self.assertTrue(body["room"].startswith("space-1:"), f"Expected ephemeral room, got: {body['room']}")
        self.assertEqual(body["identity"], "user:u1")


class TestRemotesGui(unittest.TestCase):
    """Tests for the remotes GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.client = self._TestClient(self.mod.app)

    def test_remotes_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/remotes", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("location", ""))

    def test_remotes_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                types.SimpleNamespace(agent_id="a1", name="Agent One", role="owner", relationship_label=None, disabled=False),
            ]
        )

        # Mock the database object
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[
            {
                "remote_id": "r1",
                "name": "Camera 1",
                "address": "192.168.1.100",
                "connection_type": "network",
                "capabilities": ["video", "audio"],
                "status": "online",
                "last_ping": None,
                "last_seen": None,
                "agent_name": "Agent One",
            }
        ])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/remotes")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Remote Satellites", r.text)
        self.assertIn("Camera 1", r.text)
        self.assertIn("192.168.1.100", r.text)

    def test_create_remote_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/remotes", json={
            "name": "Test Remote",
            "address": "192.168.1.200",
            "connection_type": "network",
            "agent_id": "a1",
        })
        self.assertEqual(r.status_code, 401)

    def test_create_remote_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        mock_db = mock.Mock()
        mock_db.execute = mock.Mock(return_value=None)
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/remotes", json={
            "name": "Test Remote",
            "address": "192.168.1.200",
            "connection_type": "network",
            "agent_id": "a1",
        })
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["name"], "Test Remote")
        self.assertEqual(body["address"], "192.168.1.200")
        self.assertEqual(body["status"], "offline")

    def test_ping_remote_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/remotes/r1/ping")
        self.assertEqual(r.status_code, 401)

    def test_delete_remote_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )

        # Mock database to return no results (permission denied)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.delete("/api/remotes/r1")
        self.assertEqual(r.status_code, 404)

    def test_ping_remote_returns_status(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )

        # Mock database
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{
            "remote_id": "r1",
            "agent_id": "a1",
            "address": "192.168.1.100",
            "connection_type": "network",
            "status": "offline",
        }])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock the ping function to avoid actual network calls
        with mock.patch.object(self.mod, "_ping_remote_address", return_value=(True, "online")):
            r = self.client.post("/api/remotes/r1/ping")

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["remote_id"], "r1")
        self.assertEqual(body["status"], "online")
        self.assertTrue(body["is_online"])
        self.assertIn("last_ping", body)

    def test_remotes_status_endpoint_returns_all_statuses(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )

        # Mock database
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[
            {"remote_id": "r1", "name": "Remote 1", "status": "online", "last_ping": None, "last_seen": None},
            {"remote_id": "r2", "name": "Remote 2", "status": "offline", "last_ping": None, "last_seen": None},
        ])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/remotes/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["total_count"], 2)
        self.assertEqual(body["online_count"], 1)
        self.assertEqual(body["offline_count"], 1)
        self.assertEqual(len(body["remotes"]), 2)


class TestAgentsGui(unittest.TestCase):
    """Tests for the agents management GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_agents_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/agents", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("location", ""))

    def test_agents_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        # Mock database
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user
        mock_agent = mock.Mock()
        mock_agent.agent_id = "a1"
        mock_agent.name = "Test Agent"
        mock_agent.role = "owner"
        mock_agent.relationship_label = "My Assistant"
        mock_agent.disabled = False
        self.mod.list_agents_for_user = mock.Mock(return_value=[mock_agent])

        r = self.client.get("/agents")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Test Agent", r.text)
        self.assertIn("Owner", r.text)

    def test_agent_detail_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        # Mock list_agents_for_user
        mock_agent = mock.Mock()
        mock_agent.agent_id = "a1"
        mock_agent.name = "Test Agent"
        mock_agent.role = "admin"
        mock_agent.relationship_label = "Work Helper"
        mock_agent.disabled = False
        self.mod.list_agents_for_user = mock.Mock(return_value=[mock_agent])

        # Mock database for members query
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[
            {"user_id": "u1", "role": "admin", "relationship_label": "Work Helper", "email": "user@example.com", "created_at": "2025-01-01"},
            {"user_id": "u2", "role": "member", "relationship_label": None, "email": "member@example.com", "created_at": "2025-01-02"},
        ])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/agents/a1")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Test Agent", r.text)
        self.assertIn("Admin", r.text)
        self.assertIn("member@example.com", r.text)

    def test_agent_detail_returns_404_for_unknown_agent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        r = self.client.get("/agents/unknown-id")

        self.assertEqual(r.status_code, 404)

    def test_agent_detail_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/agents/some-agent-id", follow_redirects=False)

        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("location", ""))

    def test_agent_detail_shows_member_relationship_labels(self) -> None:
        """Test that member relationship labels are displayed correctly."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        mock_agent = mock.Mock()
        mock_agent.agent_id = "a1"
        mock_agent.name = "Test Agent"
        mock_agent.role = "owner"
        mock_agent.relationship_label = "My Assistant"
        mock_agent.disabled = False
        self.mod.list_agents_for_user = mock.Mock(return_value=[mock_agent])

        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[
            {"user_id": "u1", "role": "owner", "relationship_label": "My Assistant", "email": "owner@example.com", "created_at": "2025-01-01"},
            {"user_id": "u2", "role": "admin", "relationship_label": "Work Partner", "email": "admin@example.com", "created_at": "2025-01-02"},
        ])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/agents/a1")

        self.assertEqual(r.status_code, 200)
        # Members query should use agent_memberships table with UUID cast
        mock_db.query.assert_called_once()
        call_args = mock_db.query.call_args
        query_sql = call_args[0][0]
        self.assertIn("agent_memberships", query_sql)
        self.assertIn("::uuid", query_sql)

    def test_create_agent_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/agents", json={"name": "New Agent"})

        self.assertEqual(r.status_code, 401)

    def test_create_agent_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        mock_db = mock.Mock()
        mock_db.begin = mock.Mock(return_value="tx-123")
        mock_db.execute = mock.Mock()
        mock_db.commit = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock the config to not have audit_bucket
        orig_cfg = self.mod._cfg
        mock_cfg = mock.Mock()
        mock_cfg.audit_bucket = None
        self.mod._cfg = mock_cfg

        try:
            r = self.client.post("/api/agents", json={"name": "New Agent", "relationship_label": "My Helper"})

            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["name"], "New Agent")
            self.assertEqual(data["role"], "owner")
            self.assertEqual(data["relationship_label"], "My Helper")
            self.assertFalse(data["disabled"])
            self.assertIn("agent_id", data)

            # Verify transaction was used
            mock_db.begin.assert_called_once()
            mock_db.commit.assert_called_once_with("tx-123")
            self.assertEqual(mock_db.execute.call_count, 2)  # Create agent + create membership
        finally:
            self.mod._cfg = orig_cfg

    def test_create_agent_without_relationship_label(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        mock_db = mock.Mock()
        mock_db.begin = mock.Mock(return_value="tx-123")
        mock_db.execute = mock.Mock()
        mock_db.commit = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        orig_cfg = self.mod._cfg
        mock_cfg = mock.Mock()
        mock_cfg.audit_bucket = None
        self.mod._cfg = mock_cfg

        try:
            r = self.client.post("/api/agents", json={"name": "Simple Agent"})

            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["name"], "Simple Agent")
            self.assertIsNone(data["relationship_label"])
        finally:
            self.mod._cfg = orig_cfg

    def test_create_agent_requires_name(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        r = self.client.post("/api/agents", json={})

        self.assertEqual(r.status_code, 422)  # Validation error

    def test_create_agent_rollback_on_error(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        mock_db = mock.Mock()
        mock_db.begin = mock.Mock(return_value="tx-123")
        mock_db.execute = mock.Mock(side_effect=Exception("DB error"))
        mock_db.rollback = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/agents", json={"name": "Failing Agent"})

        self.assertEqual(r.status_code, 500)
        mock_db.rollback.assert_called_once_with("tx-123")


class TestSpacesGui(unittest.TestCase):
    """Tests for the spaces management GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_spaces_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/spaces", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_spaces_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        r = self.client.get("/spaces")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Spaces", r.text)

    def test_create_space_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/spaces", json={
            "agent_id": "agent-1",
            "name": "Test Space",
            "privacy_mode": False
        })

        self.assertEqual(r.status_code, 401)

    def test_create_space_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post("/api/spaces", json={
            "agent_id": "agent-1",
            "name": "Test Space",
            "privacy_mode": False
        })

        self.assertEqual(r.status_code, 403)

    def test_create_space_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post("/api/spaces", json={
            "agent_id": "agent-1",
            "name": "Test Space",
            "privacy_mode": True
        })

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["name"], "Test Space")
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertTrue(data["privacy_mode"])
        self.assertIn("space_id", data)


class TestDevicesGui(unittest.TestCase):
    """Tests for the devices management GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_devices_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/devices", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_devices_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        r = self.client.get("/devices")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Devices", r.text)

    def test_create_device_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/devices", json={
            "agent_id": "agent-1",
            "name": "Test Device",
            "scopes": ["events:read"]
        })

        self.assertEqual(r.status_code, 401)

    def test_create_device_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post("/api/devices", json={
            "agent_id": "agent-1",
            "name": "Test Device",
            "scopes": ["events:read"]
        })

        self.assertEqual(r.status_code, 403)

    def test_create_device_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post("/api/devices", json={
            "agent_id": "agent-1",
            "name": "Test Device",
            "scopes": ["events:read", "presence:write"]
        })

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["name"], "Test Device")
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertEqual(data["scopes"], ["events:read", "presence:write"])
        self.assertIn("device_id", data)
        self.assertIn("token", data)
        self.assertIsNotNone(data["token"])

    def test_revoke_device_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/devices/device-1/revoke")

        self.assertEqual(r.status_code, 401)

    def test_revoke_device_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"device_id": "device-1", "agent_id": "agent-1"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/devices/device-1/revoke")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Device revoked")
        self.assertEqual(data["device_id"], "device-1")


class TestPeopleGui(unittest.TestCase):
    """Tests for the people & consent management GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_people_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/people", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_people_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        r = self.client.get("/people")

        self.assertEqual(r.status_code, 200)
        self.assertIn("People", r.text)

    def test_create_person_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/people", json={
            "agent_id": "agent-1",
            "display_name": "John Doe"
        })

        self.assertEqual(r.status_code, 401)

    def test_create_person_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post("/api/people", json={
            "agent_id": "agent-1",
            "display_name": "John Doe"
        })

        self.assertEqual(r.status_code, 403)

    def test_create_person_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post("/api/people", json={
            "agent_id": "agent-1",
            "display_name": "John Doe"
        })

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["display_name"], "John Doe")
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertIn("person_id", data)

    def test_update_consent_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/people/person-1/consent", json={
            "consents": [{"type": "voice", "expires_at": None}]
        })

        self.assertEqual(r.status_code, 401)

    def test_update_consent_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"person_id": "person-1", "agent_id": "agent-1"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/people/person-1/consent", json={
            "consents": [{"type": "voice", "expires_at": None}]
        })

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Consent updated")
        self.assertEqual(data["person_id"], "person-1")


class TestMemoriesGui(unittest.TestCase):
    """Tests for the memories browser GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._get_db = self._orig_get_db
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_memories_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/memories", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_memories_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])

        r = self.client.get("/memories")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Memories", r.text)

    def test_delete_memory_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.delete("/api/memories/memory-1")

        self.assertEqual(r.status_code, 401)

    def test_delete_memory_requires_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])  # No permission
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.delete("/api/memories/memory-1")

        self.assertEqual(r.status_code, 404)

    def test_delete_memory_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"memory_id": "memory-1", "agent_id": "agent-1"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.delete("/api/memories/memory-1")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Memory deleted")
        self.assertEqual(data["memory_id"], "memory-1")


class TestEventsGui(unittest.TestCase):
    """Tests for the events viewer GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._get_db = self._orig_get_db
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_events_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/events", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_events_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])

        r = self.client.get("/events")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Event Stream", r.text)


class TestActionsGui(unittest.TestCase):
    """Tests for the actions dashboard GUI routes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._get_db = self._orig_get_db
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)

    def test_actions_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/actions", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_actions_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])

        r = self.client.get("/actions")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Actions", r.text)

    def test_approve_action_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/actions/action-1/approve")

        self.assertEqual(r.status_code, 401)

    def test_approve_action_requires_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])  # No permission
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/actions/action-1/approve")

        self.assertEqual(r.status_code, 404)

    def test_approve_action_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"action_id": "action-1", "agent_id": "agent-1", "status": "proposed"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/actions/action-1/approve")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Action approved")
        self.assertEqual(data["status"], "approved")

    def test_reject_action_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/actions/action-1/reject")

        self.assertEqual(r.status_code, 401)

    def test_reject_action_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"action_id": "action-1", "agent_id": "agent-1", "status": "proposed"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/actions/action-1/reject", json={"reason": "Not needed"})

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Action rejected")
        self.assertEqual(data["status"], "rejected")


class TestArtifactsGui(unittest.TestCase):
    """Tests for artifacts GUI routes."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission
        cls._orig_get_s3 = cls.mod._get_s3
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.mod._get_s3 = self._orig_get_s3
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._cfg = self._orig_cfg

    def test_artifacts_redirects_to_login_when_unauthenticated(self):
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/artifacts", follow_redirects=False)
        self.assertIn(r.status_code, [302, 307])

    def test_artifacts_renders_when_authenticated(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Agent 1", role="owner")
        ])

        # Mock S3 client with empty artifacts
        mock_s3 = mock.Mock()
        mock_paginator = mock.Mock()
        mock_paginator.paginate = mock.Mock(return_value=[{"Contents": []}])
        mock_s3.get_paginator = mock.Mock(return_value=mock_paginator)
        self.mod._get_s3 = mock.Mock(return_value=mock_s3)

        # Mock config with artifact bucket
        self.mod._cfg = mock.Mock(artifact_bucket="test-bucket", stage="dev")

        r = self.client.get("/artifacts")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Artifacts", r.text)

    def test_presign_requires_authentication(self):
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.post("/api/artifacts/presign", json={"agent_id": "agent-1", "filename": "test.txt"})
        self.assertEqual(r.status_code, 401)

    def test_presign_requires_permission(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/artifacts/presign", json={"agent_id": "agent-1", "filename": "test.txt"})
        self.assertEqual(r.status_code, 403)

    def test_presign_success(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        mock_s3 = mock.Mock()
        mock_s3.generate_presigned_url = mock.Mock(return_value="https://s3.amazonaws.com/presigned-url")
        self.mod._get_s3 = mock.Mock(return_value=mock_s3)

        # Mock config
        self.mod._cfg = mock.Mock(artifact_bucket="test-bucket", stage="dev")

        r = self.client.post("/api/artifacts/presign", json={"agent_id": "agent-1", "filename": "test.txt"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("upload_url", data)
        self.assertIn("key", data)


class TestAuditGui(unittest.TestCase):
    """Tests for audit GUI routes."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_get_s3 = cls.mod._get_s3
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod._get_s3 = self._orig_get_s3
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._cfg = self._orig_cfg

    def test_audit_redirects_to_login_when_unauthenticated(self):
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/audit", follow_redirects=False)
        self.assertIn(r.status_code, [302, 307])

    def test_audit_renders_when_authenticated(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Agent 1", role="owner")
        ])

        # Mock S3 client with empty audit entries
        mock_s3 = mock.Mock()
        mock_paginator = mock.Mock()
        mock_paginator.paginate = mock.Mock(return_value=[{"Contents": []}])
        mock_s3.get_paginator = mock.Mock(return_value=mock_paginator)
        self.mod._get_s3 = mock.Mock(return_value=mock_s3)

        # Mock config with audit bucket
        self.mod._cfg = mock.Mock(audit_bucket="test-audit-bucket", stage="dev")

        r = self.client.get("/audit")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Audit Log", r.text)

    def test_verify_requires_authentication(self):
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.post("/api/audit/verify")
        self.assertEqual(r.status_code, 401)

    def test_verify_requires_admin_permission(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user with only guest role
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Agent 1", role="guest")
        ])

        r = self.client.post("/api/audit/verify")
        self.assertEqual(r.status_code, 403)

    def test_verify_success_with_empty_chain(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user with admin role
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Agent 1", role="admin")
        ])

        # Mock S3 client with empty audit entries
        mock_s3 = mock.Mock()
        mock_paginator = mock.Mock()
        mock_paginator.paginate = mock.Mock(return_value=[{"Contents": []}])
        mock_s3.get_paginator = mock.Mock(return_value=mock_paginator)
        self.mod._get_s3 = mock.Mock(return_value=mock_s3)

        # Mock config with audit bucket
        self.mod._cfg = mock.Mock(audit_bucket="test-audit-bucket", stage="dev")

        r = self.client.post("/api/audit/verify")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["entries_checked"], 0)


class TestLiveKitTestGui(unittest.TestCase):
    """Tests for the LiveKit test page GUI routes."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._cfg = self._orig_cfg

    def test_livekit_test_requires_authentication(self):
        """LiveKit test page should redirect unauthenticated users."""
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/livekit-test", follow_redirects=False)
        self.assertIn(r.status_code, (302, 303))
        self.assertIn("/login", r.headers.get("location", ""))

    def test_livekit_test_renders_for_authenticated_user(self):
        """LiveKit test page should render for authenticated users."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        # Mock list_spaces_for_user to return some spaces
        self.mod.list_spaces_for_user = mock.Mock(return_value=[
            mock.Mock(space_id="space-1", name="Test Space", agent_name="Test Agent"),
            mock.Mock(space_id="space-2", name="Another Space", agent_name="Another Agent"),
        ])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/livekit-test", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        # Should contain page title
        self.assertIn("LiveKit Test", r.text)
        # Should contain space selector
        self.assertIn("space_id", r.text)
        self.assertIn("Test Space", r.text)
        self.assertIn("Another Space", r.text)
        # Should contain connection controls
        self.assertIn("btn-join", r.text)
        self.assertIn("btn-leave", r.text)
        # Should contain media controls
        self.assertIn("btn-mic", r.text)
        self.assertIn("btn-cam", r.text)
        # Should contain LiveKit client script
        self.assertIn("livekit-client", r.text)

    def test_livekit_test_with_space_preselected(self):
        """LiveKit test page should preselect space when space_id is provided."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_spaces_for_user = mock.Mock(return_value=[
            mock.Mock(space_id="space-1", name="Test Space", agent_name="Test Agent"),
            mock.Mock(space_id="space-2", name="Another Space", agent_name="Another Agent"),
        ])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/livekit-test?space_id=space-1", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        # Should have space-1 option selected
        self.assertIn('value="space-1" selected', r.text)


class TestWebSocketContext(unittest.TestCase):
    """Tests for WebSocket context in templates."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._cfg = self._orig_cfg

    def test_ws_context_not_included_when_no_ws_url(self):
        """WebSocket context should be empty when WS_API_URL is not configured."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        # Config without ws_api_url
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        # Should NOT contain WebSocket initialization
        self.assertNotIn("wsConnect", r.text)

    def test_ws_context_included_when_ws_url_configured(self):
        """WebSocket context should be present when WS_API_URL is configured."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        # Config with ws_api_url
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url="wss://test-ws.example.com")

        r = self.client.get("/", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        # Should contain WebSocket initialization
        self.assertIn("wsConnect", r.text)
        self.assertIn("wss://test-ws.example.com", r.text)

    def test_ws_indicator_present_in_authenticated_pages(self):
        """WebSocket indicator should be present in header for authenticated users."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url="wss://test-ws.example.com")

        r = self.client.get("/", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        # Should contain WebSocket indicator
        self.assertIn("ws-indicator", r.text)
        self.assertIn("ws-status-text", r.text)


class TestProfileGui(unittest.TestCase):
    """Tests for the profile page GUI routes."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._cfg = self._orig_cfg

    def test_profile_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/profile", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_profile_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(
                user_id="u1", cognito_sub="sub-1", email="user@example.com"
            )
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Test Agent", role="owner", relationship_label="self"),
        ])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/profile", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("Profile", r.text)
        self.assertIn("u1", r.text)
        self.assertIn("user@example.com", r.text)
        self.assertIn("Test Agent", r.text)

    def test_profile_shows_agent_memberships(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(
                user_id="u1", cognito_sub="sub-1", email="user@example.com"
            )
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[
            mock.Mock(agent_id="agent-1", name="Agent One", role="owner", relationship_label="self"),
            mock.Mock(agent_id="agent-2", name="Agent Two", role="member", relationship_label="friend"),
        ])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/profile", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("Agent One", r.text)
        self.assertIn("Agent Two", r.text)
        self.assertIn("owner", r.text)
        self.assertIn("member", r.text)


class TestWebSocketReconnection(unittest.TestCase):
    """Tests for WebSocket reconnection behavior in marvain.js."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._cfg = self._orig_cfg

    def test_marvain_js_contains_reconnect_logic(self) -> None:
        """Verify marvain.js contains WebSocket reconnection logic."""
        r = self.client.get("/static/js/marvain.js")

        self.assertEqual(r.status_code, 200)
        # Check for reconnection-related code
        self.assertIn("wsReconnectAttempts", r.text)
        self.assertIn("wsMaxReconnectAttempts", r.text)
        self.assertIn("wsReconnectDelay", r.text)
        # Check for exponential backoff
        self.assertIn("Math.pow", r.text)

    def test_marvain_js_has_max_reconnect_limit(self) -> None:
        """Verify marvain.js limits reconnection attempts."""
        r = self.client.get("/static/js/marvain.js")

        self.assertEqual(r.status_code, 200)
        # Should check against max attempts before reconnecting
        self.assertIn("wsReconnectAttempts < this.wsMaxReconnectAttempts", r.text)


class TestLiveKitTokenExpiration(unittest.TestCase):
    """Tests for LiveKit token expiration handling."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_spaces_for_user = cls.mod.list_spaces_for_user
        cls._orig_mint_livekit_join_token = cls.mod.mint_livekit_join_token
        cls._orig_cfg = cls.mod._cfg

    def setUp(self):
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod.mint_livekit_join_token = self._orig_mint_livekit_join_token
        self.mod._cfg = self._orig_cfg

    def test_livekit_token_requires_authentication(self) -> None:
        """Token endpoint should reject unauthenticated requests."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post(
            "/livekit/token",
            json={"space_id": "space-1"},
        )

        self.assertEqual(r.status_code, 401)

    def test_livekit_token_returns_token_for_authenticated_user(self) -> None:
        """Token endpoint should return a token for authenticated users."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(
                user_id="u1", cognito_sub="sub-1", email="user@example.com"
            )
        )
        # _mint_livekit_token_for_user is now async, so mock with AsyncMock
        expected_response = self.mod.LiveKitTokenOut(
            url="wss://livekit.example",
            token="jwt-token-123",
            room="space-1:abc123",
            identity="user:u1",
        )
        self.mod._mint_livekit_token_for_user = mock.AsyncMock(return_value=expected_response)

        r = self.client.post(
            "/livekit/token",
            json={"space_id": "space-1"},
            cookies={"marvain_access_token": "test-token"},
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("token", data)
        self.assertIn("room", data)

    def test_livekit_test_page_has_token_refresh_capability(self) -> None:
        """LiveKit test page should have ability to request new tokens."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(
                user_id="u1", cognito_sub="sub-1", email="user@example.com"
            )
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/livekit-test", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        # Should have token URL for fetching tokens (data-token-url attribute)
        self.assertIn("data-token-url", r.text)
        self.assertIn("/livekit/token", r.text)
