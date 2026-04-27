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
        self.assertEqual(r.headers.get("location"), "/login")

    def test_livekit_test_redirects_to_login_without_cookie(self) -> None:
        r = self.client.get("/livekit-test", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/login")

    def test_logged_out_page_is_not_cacheable(self) -> None:
        r = self.client.get("/logged-out")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get("cache-control"), "no-store")
        self.assertEqual(r.headers.get("pragma"), "no-cache")
        self.assertEqual(r.headers.get("expires"), "0")

    def test_auth_callback_rejects_invalid_state(self) -> None:
        r = self.client.get("/auth/callback?code=c1&state=s1", follow_redirects=False)
        self.assertEqual(r.status_code, 400)

    def test_auth_callback_sets_browser_session_on_success(self) -> None:
        # First hit /login to establish a session cookie with deterministic state.
        with mock.patch.object(self.mod.secrets, "token_urlsafe", return_value="s1"):
            self.client.get("/login", follow_redirects=False)

        with mock.patch(
            "daylily_auth_cognito.browser.session.exchange_authorization_code_async",
            new_callable=mock.AsyncMock,
        ) as ex:
            ex.return_value = {"id_token": "itok", "access_token": "atok"}
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
                types.SimpleNamespace(
                    agent_id="a1", name="Agent One", role="owner", relationship_label=None, disabled=False
                ),
                types.SimpleNamespace(
                    agent_id="a2", name="Agent Two", role="member", relationship_label=None, disabled=True
                ),
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

    def test_home_redirects_to_login_when_unauthenticated(self) -> None:
        r = self.client.get("/", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers.get("location"), "/login")

    def test_livekit_test_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        # Mock list_spaces_for_user to return test spaces
        self.mod.list_spaces_for_user = mock.Mock(
            return_value=[
                self.mod.SpaceInfo(space_id="sp-1", name="home", agent_id="ag-1", agent_name="Forge"),
            ]
        )

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
        self.mod.list_spaces_for_user = mock.Mock(
            return_value=[
                self.mod.SpaceInfo(space_id=space_id, name="evil", agent_id="ag-1", agent_name="Forge"),
            ]
        )

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
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
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
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "user_id": "u1",
                    "role": "admin",
                    "relationship_label": "Work Helper",
                    "email": "user@example.com",
                    "created_at": "2025-01-01",
                },
                {
                    "user_id": "u2",
                    "role": "member",
                    "relationship_label": None,
                    "email": "member@example.com",
                    "created_at": "2025-01-02",
                },
            ]
        )
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

        members_rows = [
            {
                "user_id": "u1",
                "role": "owner",
                "relationship_label": "My Assistant",
                "email": "owner@example.com",
                "created_at": "2025-01-01",
            },
            {
                "user_id": "u2",
                "role": "admin",
                "relationship_label": "Work Partner",
                "email": "admin@example.com",
                "created_at": "2025-01-02",
            },
        ]
        summary_rows = [{"device_count": 1, "space_count": 2, "memory_count": 3, "event_count": 4}]
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(side_effect=[members_rows, summary_rows])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/agents/a1")

        self.assertEqual(r.status_code, 200)
        # Members query + summary query = 2 calls
        self.assertEqual(mock_db.query.call_count, 2)
        members_call_args = mock_db.query.call_args_list[0]
        query_sql = members_call_args[0][0]
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
            self.assertEqual(mock_db.execute.call_count, 3)  # Create agent + membership + default persona
            persona_call = mock_db.execute.call_args_list[2]
            persona_sql = persona_call.args[0]
            persona_params = persona_call.args[1]
            self.assertIn("INSERT INTO personas", persona_sql)
            self.assertEqual(persona_params["name"], self.mod.DEFAULT_AGENT_PERSONA_NAME)
            self.assertEqual(persona_call.kwargs["transaction_id"], "tx-123")
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

        r = self.client.post("/api/spaces", json={"agent_id": "agent-1", "name": "Test Space", "privacy_mode": False})

        self.assertEqual(r.status_code, 401)

    def test_create_space_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post("/api/spaces", json={"agent_id": "agent-1", "name": "Test Space", "privacy_mode": False})

        self.assertEqual(r.status_code, 403)

    def test_create_space_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"count": 0}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post("/api/spaces", json={"agent_id": "agent-1", "name": "Test Space", "privacy_mode": True})

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["name"], "Test Space")
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertTrue(data["privacy_mode"])
        self.assertIn("space_id", data)

    def test_create_space_enforces_max_spaces_limit(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod._cfg = dataclasses.replace(self.mod._cfg, max_spaces_per_agent=5)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"count": 5}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post(
            "/api/spaces", json={"agent_id": "agent-1", "name": "Overflow Space", "privacy_mode": False}
        )

        self.assertEqual(r.status_code, 409)
        self.assertIn("Space limit reached (5)", r.text)
        mock_db.execute.assert_not_called()


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

        r = self.client.post(
            "/api/devices", json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:read"]}
        )

        self.assertEqual(r.status_code, 401)

    def test_create_device_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post(
            "/api/devices", json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:read"]}
        )

        self.assertEqual(r.status_code, 403)

    def test_create_device_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post(
            "/api/devices",
            json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:read", "presence:write"]},
        )

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
        cls._orig_enqueue_recognition_event = cls.mod._enqueue_recognition_event

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._get_db = self._orig_get_db
        self.mod.check_agent_permission = self._orig_check_agent_permission
        self.mod._enqueue_recognition_event = self._orig_enqueue_recognition_event
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

    def test_people_voice_browser_upload_uses_people_enrollment_endpoint(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        r = self.client.get("/people")

        self.assertEqual(r.status_code, 200)
        self.assertIn("/api/people/${encodeURIComponent(personId)}/enroll/voice", r.text)
        self.assertIn("/api/people/${encodeURIComponent(personId)}/enroll/face", r.text)
        self.assertNotIn("fetch('/api/recognition/enrollments'", r.text)

    def test_create_person_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/people", json={"agent_id": "agent-1", "display_name": "John Doe"})

        self.assertEqual(r.status_code, 401)

    def test_create_person_requires_admin_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post("/api/people", json={"agent_id": "agent-1", "display_name": "John Doe"})

        self.assertEqual(r.status_code, 403)

    def test_create_person_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post("/api/people", json={"agent_id": "agent-1", "display_name": "John Doe"})

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["display_name"], "John Doe")
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertIn("person_id", data)

    def test_update_consent_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/people/person-1/consent", json={"consents": [{"type": "voice", "expires_at": None}]})

        self.assertEqual(r.status_code, 401)

    def test_update_consent_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"person_id": "person-1", "agent_id": "agent-1"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/people/person-1/consent", json={"consents": [{"type": "voice", "expires_at": None}]})

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Consent updated")
        self.assertEqual(data["person_id"], "person-1")

    def test_browser_voice_enrollment_requires_active_voice_consent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [{"person_id": "person-1", "agent_id": "agent-1"}],
                [],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod._enqueue_recognition_event = mock.Mock(return_value=False)

        r = self.client.post(
            "/api/people/person-1/enroll/voice",
            json={"artifact_bucket": "bucket", "artifact_key": "recognition/sample.webm", "content_type": "audio/webm"},
        )

        self.assertEqual(r.status_code, 403)
        self.assertIn("Missing active consent for voice", r.json()["detail"])
        mock_db.execute.assert_not_called()

    def test_browser_voice_enrollment_records_event_after_upload_and_consent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [{"person_id": "person-1", "agent_id": "agent-1"}],
                [{"consent_id": "consent-1", "consent_type": "voice"}],
                [{"space_id": "space-1"}],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod._enqueue_recognition_event = mock.Mock(return_value=False)

        r = self.client.post(
            "/api/people/person-1/enroll/voice",
            json={"artifact_bucket": "bucket", "artifact_key": "recognition/sample.webm", "content_type": "audio/webm"},
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["space_id"], "space-1")
        self.assertIn("event_id", data)
        executed_sql = "\n".join(str(call.args[0]) for call in mock_db.execute.call_args_list)
        self.assertIn("INSERT INTO events", executed_sql)
        event_params = mock_db.execute.call_args_list[0].args[1]
        self.assertEqual(event_params["person_id"], "person-1")
        self.assertEqual(event_params["type"], "voice.sample")


class TestRecognitionGui(unittest.TestCase):
    """Tests for the recognition/presence GUI route contract."""

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

    def test_recognition_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/recognition", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))
        self.assertNotIn("next=", r.headers.get("location", ""))

    def test_recognition_renders_route_context_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[types.SimpleNamespace(agent_id="agent-1", name="Agent One", role="owner")]
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [
                    {
                        "observation_id": "obs-1",
                        "agent_id": "agent-1",
                        "agent_name": "Agent One",
                        "space_name": "Kitchen",
                        "device_name": "Wall Display",
                        "artifact_id": "artifact-1",
                        "modality": "face",
                        "lifecycle_state": "embedded",
                        "model_name": "face-v1",
                        "created_at": "2026-04-26T10:00:00Z",
                    }
                ],
                [
                    {
                        "hypothesis_id": "hyp-1",
                        "observation_id": "obs-1",
                        "agent_id": "agent-1",
                        "candidate_person_id": "person-1",
                        "person_name": "Major",
                        "score": 0.98,
                        "decision": "accepted",
                        "consent_id": "consent-1",
                        "created_at": "2026-04-26T10:00:03Z",
                    }
                ],
                [],
                [],
                [
                    {
                        "presence_assertion_id": "pa-1",
                        "agent_id": "agent-1",
                        "person_id": "person-1",
                        "person_name": "Major",
                        "space_id": "space-1",
                        "space_name": "Kitchen",
                        "status": "present",
                        "source": "recognition",
                        "asserted_at": "2026-04-26T10:00:04Z",
                    }
                ],
                [],
                [],
                [],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/recognition")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Recognition", r.text)
        self.assertIn("obs-1", r.text)
        self.assertIn("hyp-1", r.text)
        self.assertIn("pa-1", r.text)
        self.assertIn("Consent Grant Context Pending", r.text)
        self.assertIn("Artifact Reference Context Pending", r.text)

    def test_create_recognition_enrollment_requires_active_consent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [{"person_id": "person-1", "agent_id": "agent-1"}],
                [],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post(
            "/api/recognition/enrollments",
            json={
                "person_id": "person-1",
                "modality": "voice",
                "artifact_bucket": "bucket",
                "artifact_key": "recognition/sample.webm",
                "content_type": "audio/webm",
            },
        )

        self.assertEqual(r.status_code, 403)
        self.assertIn("Missing active consent", r.json()["detail"])
        mock_db.execute.assert_not_called()

    def test_create_recognition_enrollment_records_observation_after_consent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [{"person_id": "person-1", "agent_id": "agent-1"}],
                [{"consent_id": "consent-1", "consent_type": "voice"}],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post(
            "/api/recognition/enrollments",
            json={
                "person_id": "person-1",
                "modality": "voice",
                "artifact_bucket": "bucket",
                "artifact_key": "recognition/sample.webm",
                "content_type": "audio/webm",
            },
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["person_id"], "person-1")
        self.assertEqual(data["consent_id"], "consent-1")
        executed_sql = "\n".join(str(call.args[0]) for call in mock_db.execute.call_args_list)
        self.assertIn("INSERT INTO artifact_references", executed_sql)
        self.assertIn("INSERT INTO recognition_observations", executed_sql)
        self.assertIn("INSERT INTO recognition_hypotheses", executed_sql)
        self.assertNotIn("INSERT INTO people", executed_sql)

    def test_accept_hypothesis_requires_active_candidate_consent(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [
                    {
                        "hypothesis_id": "hyp-1",
                        "observation_id": "obs-1",
                        "person_id": "person-1",
                        "confidence": 0.97,
                        "agent_id": "agent-1",
                        "space_id": "space-1",
                        "location_id": "loc-1",
                        "modality": "face",
                    }
                ],
                [],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/recognition/hypotheses/hyp-1/accept", json={})

        self.assertEqual(r.status_code, 403)
        self.assertIn("Missing active consent", r.json()["detail"])
        mock_db.execute.assert_not_called()

    def test_accept_hypothesis_creates_presence_assertion(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            side_effect=[
                [
                    {
                        "hypothesis_id": "hyp-1",
                        "observation_id": "obs-1",
                        "person_id": "person-1",
                        "confidence": 0.97,
                        "agent_id": "agent-1",
                        "space_id": "space-1",
                        "location_id": "loc-1",
                        "modality": "face",
                    }
                ],
                [{"consent_id": "consent-face-1", "consent_type": "face"}],
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/recognition/hypotheses/hyp-1/accept", json={"reason": "operator confirmed"})

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["decision"], "accepted")
        self.assertEqual(data["consent_id"], "consent-face-1")
        executed_sql = "\n".join(str(call.args[0]) for call in mock_db.execute.call_args_list)
        self.assertIn("UPDATE recognition_hypotheses", executed_sql)
        self.assertIn("UPDATE recognition_observations", executed_sql)
        self.assertIn("INSERT INTO presence_assertions", executed_sql)

    def test_observation_no_match_does_not_create_people(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"observation_id": "obs-1", "agent_id": "agent-1"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/recognition/observations/obs-1/no-match", json={"reason": "unknown visitor"})

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["decision"], "no_match")
        executed_sql = "\n".join(str(call.args[0]) for call in mock_db.execute.call_args_list)
        self.assertIn("SET lifecycle_state = 'no_match'", executed_sql)
        self.assertIn("candidate_person_id", executed_sql)
        self.assertNotIn("INSERT INTO people", executed_sql)

    def test_revoke_biometric_projection_updates_matching_projection(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "modality": "voice",
                    "projection_id": "voiceprint-1",
                    "agent_id": "agent-1",
                    "person_id": "person-1",
                }
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/recognition/biometrics/voiceprint-1/revoke", json={"reason": "consent revoked"})

        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["revoked"])
        executed_sql = "\n".join(str(call.args[0]) for call in mock_db.execute.call_args_list)
        self.assertIn("UPDATE voiceprints", executed_sql)
        self.assertIn("revoked_at = now()", executed_sql)


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

    def test_gui_create_memory_records_evidence_candidate_not_direct_memory(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"ok": 1}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post(
            "/api/memories",
            json={
                "agent_id": "agent-1",
                "space_id": "space-1",
                "tier": "semantic",
                "content": "User prefers evidence-backed memory review.",
                "confidence": 0.9,
            },
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["memory_candidate_id"])
        self.assertTrue(data["source_event_id"])
        executed_sql = "\n".join(call.args[0] for call in mock_db.execute.call_args_list)
        self.assertIn("INSERT INTO events", executed_sql)
        self.assertIn("memory.evidence", executed_sql)
        self.assertIn("INSERT INTO memory_candidates", executed_sql)
        self.assertNotIn("INSERT INTO memories", executed_sql)

    def test_list_memory_candidates_returns_visible_candidates(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "memory_candidate_id": "candidate-1",
                    "agent_id": "agent-1",
                    "agent_name": "Agent One",
                    "source_event_id": "event-1",
                    "source_action_id": None,
                    "space_id": "space-1",
                    "space_name": "Kitchen",
                    "session_id": "session-1",
                    "subject_person_id": None,
                    "subject_person_name": None,
                    "tier": "semantic",
                    "content": "Candidate content",
                    "participants": '["person:1"]',
                    "model": None,
                    "confidence": 0.8,
                    "lifecycle_state": "candidate",
                    "tapdb_euid": None,
                    "created_at": "2026-04-26T10:00:00+00:00",
                    "reviewed_at": None,
                }
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/memory-candidates")

        self.assertEqual(r.status_code, 200)
        candidate = r.json()["candidates"][0]
        self.assertEqual(candidate["memory_candidate_id"], "candidate-1")
        self.assertEqual(candidate["participants"], ["person:1"])
        query_sql, query_params = mock_db.query.call_args.args
        self.assertNotIn(":agent_id IS NULL", query_sql)
        self.assertNotIn("agent_id", query_params)

    def test_list_memory_candidates_returns_json_error_when_database_fails(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(side_effect=RuntimeError("database unavailable"))
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/memory-candidates")

        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.headers["content-type"].split(";")[0], "application/json")
        self.assertEqual(r.json()["detail"], "Failed to list memory candidates")

    def test_commit_memory_candidate_requires_source_evidence_for_semantic_memory(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "memory_candidate_id": "candidate-1",
                    "agent_id": "agent-1",
                    "source_event_id": None,
                    "source_action_id": None,
                    "space_id": "space-1",
                    "session_id": None,
                    "subject_person_id": None,
                    "tier": "semantic",
                    "content": "No evidence",
                    "participants": "[]",
                    "confidence": 1.0,
                    "lifecycle_state": "candidate",
                }
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/memory-candidates/candidate-1/commit", json={})

        self.assertEqual(r.status_code, 400)
        self.assertIn("source evidence", r.text)
        mock_db.execute.assert_not_called()

    def test_commit_memory_candidate_inserts_memory_projection_and_marks_committed(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "memory_candidate_id": "candidate-1",
                    "agent_id": "agent-1",
                    "source_event_id": "event-1",
                    "source_action_id": "action-1",
                    "space_id": "space-1",
                    "session_id": "session-1",
                    "subject_person_id": "person-1",
                    "tier": "semantic",
                    "content": "Evidence-backed memory",
                    "participants": '["person:1"]',
                    "confidence": 0.77,
                    "lifecycle_state": "candidate",
                }
            ]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/memory-candidates/candidate-1/commit", json={"tags": ["gui"]})

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "committed")
        insert_sql, insert_params = mock_db.execute.call_args_list[0].args
        update_sql = mock_db.execute.call_args_list[1].args[0]
        self.assertIn("INSERT INTO memories", insert_sql)
        self.assertEqual(insert_params["source_event_id"], "event-1")
        self.assertEqual(insert_params["candidate_id"], "candidate-1")
        self.assertIn("lifecycle_state = 'committed'", update_sql)

    def test_patch_and_reject_memory_candidate_routes(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        row = {
            "memory_candidate_id": "candidate-1",
            "agent_id": "agent-1",
            "source_event_id": "event-1",
            "space_id": "space-1",
            "tier": "semantic",
            "content": "Draft",
            "participants": "[]",
            "confidence": 0.5,
            "lifecycle_state": "candidate",
        }
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[row])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        patch = self.client.patch(
            "/api/memory-candidates/candidate-1",
            json={"content": "Edited", "confidence": 0.7, "participants": ["person:1"]},
        )
        reject = self.client.post("/api/memory-candidates/candidate-1/reject", json={"reason": "duplicate"})

        self.assertEqual(patch.status_code, 200)
        self.assertTrue(patch.json()["updated"])
        self.assertEqual(reject.status_code, 200)
        self.assertEqual(reject.json()["status"], "rejected")

    def test_supersede_memory_marks_projection_superseded(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[{"memory_id": "memory-1", "agent_id": "agent-1", "lifecycle_state": "committed"}]
        )
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post(
            "/api/memories/memory-1/supersede",
            json={"superseded_by_memory_id": "memory-2", "reason": "newer evidence"},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "superseded")
        sql, params = mock_db.execute.call_args.args
        self.assertIn("lifecycle_state = 'superseded'", sql)
        self.assertEqual(params["superseded_by_memory_id"], "memory-2")

    def test_get_memory_exposes_lifecycle_provenance_and_recall_fields(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "memory_id": "memory-1",
                    "agent_id": "agent-1",
                    "agent_name": "Agent One",
                    "space_id": "space-1",
                    "space_name": "Kitchen",
                    "memory_candidate_id": "candidate-1",
                    "source_event_id": "event-1",
                    "source_action_id": "action-1",
                    "session_id": "session-1",
                    "location_id": "location-1",
                    "location_name": "Home",
                    "lifecycle_state": "tombstoned",
                    "tapdb_euid": "mvn-memory-1",
                    "tombstoned_at": "2026-04-26T10:00:00+00:00",
                    "tier": "semantic",
                    "content": "User prefers brief memory detail views.",
                    "participants": '["person:user-1"]',
                    "provenance": '{"source":"planner","source_event_id":"event-1","source_action_id":"action-1"}',
                    "retention": "{}",
                    "recall_explanation": (
                        '{"explanation":"Matched by source event and semantic distance.",'
                        '"memory_candidate_id":"candidate-1","source_event_id":"event-1","session_id":"session-1"}'
                    ),
                    "memory_tombstone_id": "tombstone-1",
                    "tombstone_reason": "gui_delete",
                    "tombstone_actor_type": "user",
                    "tombstone_actor_id": "u1",
                    "tombstone_tapdb_euid": "mvn-tombstone-1",
                    "tombstone_created_at": "2026-04-26T10:00:00+00:00",
                    "created_at": "2026-04-26T09:00:00+00:00",
                    "subject_person_id": "person-1",
                    "subject_person_name": "Major",
                    "tags": ["gui"],
                    "scene_context": "Kitchen",
                    "modality": "text",
                    "confidence": 0.91,
                    "related_memory_ids": [],
                }
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/memories/memory-1")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["memory_candidate_id"], "candidate-1")
        self.assertEqual(data["source_event_id"], "event-1")
        self.assertEqual(data["source_action_id"], "action-1")
        self.assertEqual(data["session_id"], "session-1")
        self.assertEqual(data["location_id"], "location-1")
        self.assertEqual(data["location_name"], "Home")
        self.assertEqual(data["lifecycle_state"], "tombstoned")
        self.assertEqual(data["tombstoned_at"], "2026-04-26T10:00:00+00:00")
        self.assertEqual(data["recall_explanation"]["memory_candidate_id"], "candidate-1")
        self.assertEqual(data["recall_explanation"]["source_event_id"], "event-1")
        self.assertEqual(data["tombstone"]["memory_tombstone_id"], "tombstone-1")
        self.assertEqual(data["tombstone"]["reason"], "gui_delete")

    def test_memories_template_surfaces_provenance_and_lineage_details(self) -> None:
        template = (Path(__file__).resolve().parents[1] / "functions/hub_api/templates/memories.html").read_text(
            encoding="utf-8"
        )

        for label in (
            "Memory Candidate ID",
            "Source Event",
            "Source Action",
            "Session",
            "Location",
            "Lifecycle State",
            "Tombstone",
            "Recall Explanation",
            "Lineage",
        ):
            self.assertIn(label, template)

        for field in (
            "memory_candidate_id",
            "source_event_id",
            "source_action_id",
            "session_id",
            "location_id",
            "lifecycle_state",
            "tombstoned_at",
            "recall_explanation",
            "tapdb_euid",
        ):
            self.assertIn(field, template)

        self.assertIn("/api/events/", template)
        self.assertIn("/api/actions/", template)
        self.assertIn("/tapdb/graph?start_euid=", template)

    def test_memories_template_uses_json_or_text_fetch_errors(self) -> None:
        template = (Path(__file__).resolve().parents[1] / "functions/hub_api/templates/memories.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("async function readMemoryFetchResponse", template)
        self.assertIn("JSON.parse(text)", template)
        self.assertNotIn("await response.json()", template)

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


class TestTapdbNativeGraphIntegration(unittest.TestCase):
    """Tests for the embedded native TapDB graph and DAG surfaces."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_resolve_tapdb_runtime_config = cls.mod._resolve_tapdb_runtime_config
        cls._orig_create_tapdb_web_app = cls.mod.create_tapdb_web_app
        cls._orig_create_tapdb_dag_router = cls.mod.create_tapdb_dag_router

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app, raise_server_exceptions=False)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._resolve_tapdb_runtime_config = self.__class__._orig_resolve_tapdb_runtime_config
        self.mod.create_tapdb_web_app = self.__class__._orig_create_tapdb_web_app
        self.mod.create_tapdb_dag_router = self.__class__._orig_create_tapdb_dag_router
        self.mod._tapdb_web_asgi_app = None
        self.mod._tapdb_dag_asgi_app = None

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._resolve_tapdb_runtime_config = self.__class__._orig_resolve_tapdb_runtime_config
        self.mod.create_tapdb_web_app = self.__class__._orig_create_tapdb_web_app
        self.mod.create_tapdb_dag_router = self.__class__._orig_create_tapdb_dag_router
        self.mod._tapdb_web_asgi_app = None
        self.mod._tapdb_dag_asgi_app = None

    def _auth_user(self):
        return self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")

    def test_tapdb_graph_mount_redirects_unauthenticated_users(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/tapdb/graph?start_euid=MVN1", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))
        self.assertNotIn("/tapdb/login", r.headers.get("location", ""))
        self.assertNotIn("next=", r.headers.get("location", ""))

    def test_tapdb_graph_mount_uses_host_session_bridge_when_authenticated(self) -> None:
        captured: dict[str, object] = {}

        async def fake_tapdb_app(scope, receive, send):
            captured["scoped_user"] = scope.get("marvain_authenticated_user")
            captured["tapdb_host_user"] = scope.get("tapdb_host_user")
            response = self.mod.PlainTextResponse("tapdb graph ok")
            await response(scope, receive, send)

        def fake_create_tapdb_web_app(*, config_path, env_name, host_bridge):
            captured["config_path"] = config_path
            captured["env_name"] = env_name
            captured["host_bridge"] = host_bridge
            return fake_tapdb_app

        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            return_value=self.mod.TapdbRuntimeConfig(config_path="/tmp/tapdb-config.yaml", env_name="test")
        )
        self.mod.create_tapdb_web_app = fake_create_tapdb_web_app

        r = self.client.get("/tapdb/graph?start_euid=MVN1")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "tapdb graph ok")
        self.assertEqual(captured["config_path"], "/tmp/tapdb-config.yaml")
        self.assertEqual(captured["env_name"], "test")
        self.assertEqual(captured["host_bridge"].auth_mode, "host_session")
        self.assertEqual(captured["scoped_user"].email, "user@example.com")
        self.assertEqual(captured["tapdb_host_user"]["email"], "user@example.com")

    def test_tapdb_graph_mount_returns_clear_config_error_when_missing(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            side_effect=self.mod.MarvainTapdbConfigError("TapDB runtime is not configured. Set TAPDB_CONFIG_PATH.")
        )

        r = self.client.get("/tapdb/graph?start_euid=MVN1")

        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["code"], "tapdb_runtime_not_configured")
        self.assertIn("TAPDB_CONFIG_PATH", r.json()["detail"])

    def test_tapdb_query_mount_returns_200_when_authenticated(self) -> None:
        captured: dict[str, object] = {}

        async def fake_tapdb_app(scope, receive, send):
            captured["path"] = scope.get("path")
            captured["query_string"] = scope.get("query_string")
            captured["tapdb_host_user"] = scope.get("tapdb_host_user")
            response = self.mod.HTMLResponse("<html><body>Complex Query</body></html>")
            await response(scope, receive, send)

        def fake_create_tapdb_web_app(*, config_path, env_name, host_bridge):
            captured["host_bridge"] = host_bridge
            return fake_tapdb_app

        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            return_value=self.mod.TapdbRuntimeConfig(config_path="/tmp/tapdb-config.yaml", env_name="test")
        )
        self.mod.create_tapdb_web_app = fake_create_tapdb_web_app

        r = self.client.get("/tapdb/query?kind=instance&category=&type=&subtype=&name_like=&euid_like=&limit=50")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Complex Query", r.text)
        self.assertEqual(captured["path"], "/query")
        self.assertIn(b"kind=instance", captured["query_string"])
        self.assertEqual(captured["host_bridge"].auth_mode, "host_session")
        self.assertEqual(captured["tapdb_host_user"]["email"], "user@example.com")

    def test_tapdb_query_mount_returns_clear_config_error_when_missing(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            side_effect=self.mod.MarvainTapdbConfigError("TapDB runtime is not configured. Set TAPDB_CONFIG_PATH.")
        )

        r = self.client.get("/tapdb/query?kind=instance&category=&type=&subtype=&name_like=&euid_like=&limit=50")

        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.headers.get("content-type"), "application/json")
        self.assertEqual(r.json()["code"], "tapdb_runtime_not_configured")
        self.assertIn("TAPDB_CONFIG_PATH", r.json()["detail"])

    def test_tapdb_query_mount_converts_child_runtime_exception_to_503_json(self) -> None:
        async def fake_tapdb_app(scope, receive, send):
            raise ConnectionError("database unavailable")

        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            return_value=self.mod.TapdbRuntimeConfig(config_path="/tmp/tapdb-config.yaml", env_name="test")
        )
        self.mod.create_tapdb_web_app = mock.Mock(return_value=fake_tapdb_app)

        r = self.client.get("/tapdb/query?kind=instance&category=&type=&subtype=&name_like=&euid_like=&limit=50")

        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.headers.get("content-type"), "application/json")
        self.assertEqual(r.json()["code"], "tapdb_runtime_unavailable")
        self.assertNotIn("database unavailable", r.json()["detail"])

    def test_api_dag_routes_require_marvain_session_auth(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/api/dag/data?start_euid=MVN1")

        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["detail"], "Not authenticated")

    def test_api_dag_routes_return_clear_config_error_when_missing(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            side_effect=self.mod.MarvainTapdbConfigError("TapDB runtime is not configured. Set TAPDB_CONFIG_PATH.")
        )

        r = self.client.get("/api/dag/data?start_euid=MVN1")

        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.json()["code"], "tapdb_runtime_not_configured")
        self.assertIn("TAPDB_CONFIG_PATH", r.json()["detail"])

    def test_api_dag_routes_are_registered_from_tapdb_router(self) -> None:
        from fastapi import APIRouter

        captured: dict[str, str] = {}

        def fake_create_tapdb_dag_router(*, config_path, env_name, service_name=None):
            captured["config_path"] = config_path
            captured["env_name"] = env_name
            captured["service_name"] = service_name
            router = APIRouter()

            @router.get("/api/dag/data")
            async def fake_dag_data(start_euid: str):
                return {"ok": True, "start_euid": start_euid}

            return router

        self.mod._gui_get_user = mock.Mock(return_value=self._auth_user())
        self.mod._resolve_tapdb_runtime_config = mock.Mock(
            return_value=self.mod.TapdbRuntimeConfig(config_path="/tmp/tapdb-config.yaml", env_name="test")
        )
        self.mod.create_tapdb_dag_router = fake_create_tapdb_dag_router

        r = self.client.get("/api/dag/data?start_euid=MVN1")

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"ok": True, "start_euid": "MVN1"})
        self.assertEqual(
            captured, {"config_path": "/tmp/tapdb-config.yaml", "env_name": "test", "service_name": "marvain"}
        )


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
        cls._orig_get_sqs = cls.mod._get_sqs
        cls._orig_cfg = cls.mod._cfg

    def setUp(self) -> None:
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod.list_spaces_for_user = self._orig_list_spaces_for_user
        self.mod._get_db = self._orig_get_db
        self.mod._get_sqs = self._orig_get_sqs
        self.mod._cfg = self._orig_cfg
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

        mock_sqs = mock.Mock()
        self.mod._get_sqs = mock.Mock(return_value=mock_sqs)
        self.mod._cfg = mock.Mock(action_queue_url="https://sqs.us-east-1.amazonaws.com/123/ActionQueue")

        r = self.client.post("/api/actions/action-1/approve")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Action approved")
        self.assertEqual(data["status"], "approved")
        # Verify action was queued to SQS
        mock_sqs.send_message.assert_called_once()
        call_kwargs = mock_sqs.send_message.call_args
        self.assertIn("action-1", call_kwargs.kwargs.get("MessageBody", call_kwargs[1].get("MessageBody", "")))

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

    def test_actions_guide_redirects_to_login_when_unauthenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/actions/guide", follow_redirects=False)

        self.assertIn(r.status_code, [302, 307])
        self.assertIn("/login", r.headers.get("location", ""))

    def test_actions_guide_renders_when_authenticated(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )

        r = self.client.get("/actions/guide")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Actions Guide", r.text)
        self.assertIn("send_message", r.text)
        self.assertIn("device_command", r.text)

    def test_approve_action_queues_to_sqs(self) -> None:
        """Verify approved actions are queued to SQS for Tool Runner execution."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"action_id": "act-42", "agent_id": "agent-7", "status": "proposed"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        mock_sqs = mock.Mock()
        self.mod._get_sqs = mock.Mock(return_value=mock_sqs)
        self.mod._cfg = mock.Mock(action_queue_url="https://sqs.example.com/ActionQueue")

        r = self.client.post("/api/actions/act-42/approve")

        self.assertEqual(r.status_code, 200)
        mock_sqs.send_message.assert_called_once()
        body = mock_sqs.send_message.call_args.kwargs.get(
            "MessageBody", mock_sqs.send_message.call_args[1].get("MessageBody", "")
        )
        import json as _json

        parsed = _json.loads(body)
        self.assertEqual(parsed["action_id"], "act-42")
        self.assertEqual(parsed["agent_id"], "agent-7")

    def test_approve_action_skips_sqs_when_no_queue_url(self) -> None:
        """When action_queue_url is not set, approval should succeed without SQS."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"action_id": "act-1", "agent_id": "agent-1", "status": "proposed"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        mock_sqs = mock.Mock()
        self.mod._get_sqs = mock.Mock(return_value=mock_sqs)
        self.mod._cfg = mock.Mock(action_queue_url=None)

        r = self.client.post("/api/actions/act-1/approve")

        self.assertEqual(r.status_code, 200)
        mock_sqs.send_message.assert_not_called()

    def test_diagnostics_requires_authentication(self) -> None:
        """Diagnostics endpoint should reject unauthenticated requests."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/api/actions/diagnostics")

        self.assertEqual(r.status_code, 401)

    def test_diagnostics_returns_queue_health(self) -> None:
        """Diagnostics endpoint should return queue health and action timeline."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])

        mock_sqs = mock.Mock()
        mock_sqs.get_queue_attributes = mock.Mock(
            return_value={
                "Attributes": {
                    "ApproximateNumberOfMessages": "3",
                    "ApproximateNumberOfMessagesNotVisible": "1",
                    "ApproximateNumberOfMessagesDelayed": "0",
                }
            }
        )
        self.mod._get_sqs = mock.Mock(return_value=mock_sqs)
        self.mod._cfg = mock.Mock(
            action_queue_url="https://sqs.example.com/ActionQueue",
            cognito_region="us-east-1",
        )

        # Patch boto3.client to avoid real CloudWatch calls
        with mock.patch.object(self.mod, "_read_marvain_config", return_value={}):
            import boto3

            with mock.patch.object(boto3, "client") as mock_boto_client:
                mock_logs = mock.Mock()
                mock_logs.filter_log_events = mock.Mock(return_value={"events": []})
                mock_boto_client.return_value = mock_logs

                r = self.client.get("/api/actions/diagnostics")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("queue_health", data)
        self.assertEqual(data["queue_health"]["messages_available"], 3)
        self.assertEqual(data["queue_health"]["messages_in_flight"], 1)
        self.assertIn("action_timeline", data)
        self.assertIn("recent_executions", data)


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
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[mock.Mock(agent_id="agent-1", name="Agent 1", role="owner")]
        )

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

    def test_upload_artifact_recognition_uses_recognition_prefix_and_returns_uri(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod._get_db = mock.Mock(return_value=mock.Mock())

        mock_s3 = mock.Mock()
        self.mod._get_s3 = mock.Mock(return_value=mock_s3)
        self.mod._cfg = mock.Mock(artifact_bucket="test-bucket", stage="dev")

        r = self.client.post(
            "/api/artifacts/upload",
            data={"agent_id": "agent-1", "purpose": "recognition"},
            files={"file": ("voice.webm", b"sample", "audio/webm")},
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["bucket"], "test-bucket")
        self.assertEqual(data["purpose"], "recognition")
        self.assertTrue(data["key"].startswith("recognition/agent_id=agent-1/"))
        self.assertEqual(data["uri"], f"s3://test-bucket/{data['key']}")
        mock_s3.put_object.assert_called_once()
        self.assertEqual(mock_s3.put_object.call_args.kwargs["ContentType"], "audio/webm")


class TestLocationsGui(unittest.TestCase):
    """Tests for greenfield location topology GUI routes."""

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

    def tearDown(self):
        self.mod._gui_get_user = self._orig_gui_get_user
        self.mod._get_db = self._orig_get_db
        self.mod.list_agents_for_user = self._orig_list_agents_for_user
        self.mod._cfg = self._orig_cfg

    def test_locations_query_matches_greenfield_schema(self):
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[mock.Mock(agent_id="agent-1", name="Agent One", role="owner")]
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "location_id": "location-1",
                    "agent_id": "agent-1",
                    "agent_name": "Agent One",
                    "name": "Lab",
                    "description": None,
                    "address": "Bench 1",
                    "metadata": "{}",
                    "tapdb_euid": "MVN-location-1",
                    "space_count": 1,
                    "device_count": 2,
                }
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/locations")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Lab", r.text)
        self.assertIn("Bench 1", r.text)
        query_sql = mock_db.query.call_args.args[0]
        self.assertIn("l.address_label AS address", query_sql)
        self.assertIn("l.tapdb_euid", query_sql)
        self.assertNotIn("l.description", query_sql)
        self.assertNotIn("l.address,", query_sql)


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
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[mock.Mock(agent_id="agent-1", name="Agent 1", role="owner")]
        )

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
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[mock.Mock(agent_id="agent-1", name="Agent 1", role="guest")]
        )

        r = self.client.post("/api/audit/verify")
        self.assertEqual(r.status_code, 403)

    def test_verify_success_with_empty_chain(self):
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))

        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        # Mock list_agents_for_user with admin role
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[mock.Mock(agent_id="agent-1", name="Agent 1", role="admin")]
        )

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
        self.mod.list_spaces_for_user = mock.Mock(
            return_value=[
                mock.Mock(space_id="space-1", name="Test Space", agent_name="Test Agent"),
                mock.Mock(space_id="space-2", name="Another Space", agent_name="Another Agent"),
            ]
        )
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
        self.mod.list_spaces_for_user = mock.Mock(
            return_value=[
                mock.Mock(space_id="space-1", name="Test Space", agent_name="Test Agent"),
                mock.Mock(space_id="space-2", name="Another Space", agent_name="Another Agent"),
            ]
        )
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
        self.assertIn("Realtime unavailable", r.text)
        self.assertIn("Browser real-time updates are not configured", r.text)

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
        self.assertIn("Realtime connecting", r.text)
        self.assertIn("Connected to browser real-time updates", r.text)
        # Access token must not be rendered into HTML.
        self.assertNotIn("test-token", r.text)

    def test_ws_auth_token_api_returns_session_token(self):
        """WS auth token endpoint should mint a Marvain session token, not return OAuth cookies."""
        from agent_hub.session_tokens import verify_ws_session_token

        self.mod._gui_get_user = mock.Mock(
            return_value=mock.Mock(user_id="user-1", cognito_sub="sub-1", email="test@example.com")
        )
        r = self.client.get("/api/ws-auth-token", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["token_type"], "marvain_session")
        self.assertNotEqual(data["access_token"], "test-token")
        payload = verify_ws_session_token(secret_key=self.mod._session_secret, token=data["access_token"])
        self.assertEqual(payload["user_id"], "user-1")
        self.assertEqual(payload["cognito_sub"], "sub-1")
        self.assertEqual(r.headers.get("cache-control"), "no-store")

    def test_ws_auth_token_api_requires_auth(self):
        """WS auth token endpoint should require GUI authentication."""
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/ws-auth-token", cookies={"marvain_access_token": "test-token"})
        self.assertEqual(r.status_code, 401)

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
        self.assertIn("Realtime connecting", r.text)

    def test_ws_indicator_script_connects_when_dom_already_loaded(self):
        """WebSocket startup should not depend on catching DOMContentLoaded."""
        self.mod._gui_get_user = mock.Mock(return_value=mock.Mock(user_id="user-1", email="test@example.com"))
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url="wss://test-ws.example.com")

        r = self.client.get("/", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("document.readyState === 'loading'", r.text)
        self.assertIn("connectWhenReady()", r.text)


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
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                mock.Mock(agent_id="agent-1", name="Test Agent", role="owner", relationship_label="self"),
            ]
        )
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/profile", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("Profile", r.text)
        self.assertIn("u1", r.text)
        self.assertIn("user@example.com", r.text)
        self.assertIn("Test Agent", r.text)

    def test_profile_shows_agent_memberships(self) -> None:
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                mock.Mock(agent_id="agent-1", name="Agent One", role="owner", relationship_label="self"),
                mock.Mock(agent_id="agent-2", name="Agent Two", role="member", relationship_label="friend"),
            ]
        )
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
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
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
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
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

    def test_livekit_test_visual_observation_requires_worker_analysis(self) -> None:
        """Camera frames should not become visual claims until the worker analyzes them."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="user@example.com")
        )
        self.mod._get_db = mock.Mock(return_value=mock.Mock())
        self.mod.list_spaces_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/livekit-test", cookies={"marvain_access_token": "test-token"})

        self.assertEqual(r.status_code, 200)
        self.assertIn("type: 'visual_observation'", r.text)
        self.assertIn("description: ''", r.text)
        self.assertIn("The worker must analyze it before making visual claims", r.text)
        self.assertNotIn("Its contents have not been analyzed by a vision model", r.text)
