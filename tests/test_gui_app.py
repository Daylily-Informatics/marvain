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
        expected_response = self.mod.LiveKitTokenOut(
            url="wss://livekit.example",
            token="jwt",
            room="space-1",
            identity="user:u1",
        )
        self.mod._mint_livekit_token_for_user = mock.Mock(return_value=expected_response)

        r = self.client.post("/livekit/token", json={"space_id": "space-1"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "wss://livekit.example")
        self.assertEqual(body["token"], "jwt")
        self.assertEqual(body["room"], "space-1")
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
            {"user_id": "u1", "role": "admin", "email": "user@example.com", "created_at": "2025-01-01"},
            {"user_id": "u2", "role": "member", "email": "member@example.com", "created_at": "2025-01-02"},
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
