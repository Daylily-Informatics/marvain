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


def _load_hub_api_app_module():
    """Load functions/hub_api/app.py as a module without requiring it be a package."""
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests_gui", app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


class TestGuiApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient

    def setUp(self) -> None:
        # Fresh client per test to avoid cookie persistence across tests.
        self.client = self.__class__._TestClient(self.mod.app)

        # Provide Cognito config for GUI routes.
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            cognito_domain="marvain-dev",
            cognito_user_pool_client_id="client-123",
        )

    def test_login_redirect_sets_state_and_verifier_cookies(self) -> None:
        r = self.client.get("/login", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        loc = r.headers.get("location") or ""
        self.assertIn("https://marvain-dev.auth.us-west-2.amazoncognito.com/oauth2/authorize?", loc)
        self.assertIn("response_type=code", loc)
        self.assertIn("client_id=client-123", loc)
        self.assertIn("redirect_uri=http%3A%2F%2Ftestserver%2Fauth%2Fcallback", loc)
        self.assertIn("code_challenge_method=S256", loc)

        # Starlette TestClient uses httpx; headers API varies slightly by version.
        if hasattr(r.headers, "get_list"):
            set_cookie_headers = r.headers.get_list("set-cookie")
        elif hasattr(r.headers, "getlist"):
            set_cookie_headers = r.headers.getlist("set-cookie")
        else:
            v = r.headers.get("set-cookie")
            set_cookie_headers = [v] if v else []

        set_cookie = "\n".join(set_cookie_headers)
        self.assertIn("marvain_oauth_state=", set_cookie)
        self.assertIn("marvain_oauth_verifier=", set_cookie)
        self.assertIn("marvain_oauth_next=", set_cookie)

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
        with mock.patch.object(
            self.mod,
            "_cognito_exchange_code_for_tokens",
            return_value={"access_token": "atok"},
        ):
            # set oauth cookies on the client (avoid per-request cookies deprecation)
            self.client.cookies.set("marvain_oauth_state", "s1")
            self.client.cookies.set("marvain_oauth_verifier", "v1")
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
        self.assertIn("marvain_access_token=atok", set_cookie)

    def test_home_renders_agents_when_authenticated(self) -> None:
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                types.SimpleNamespace(agent_id="a1", name="Agent One", role="owner", relationship_label=None, disabled=False),
                types.SimpleNamespace(agent_id="a2", name="Agent Two", role="member", relationship_label=None, disabled=True),
            ]
        )

        self.client.cookies.set("marvain_access_token", "atok")
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Your agents", r.text)
        self.assertIn("Agent One", r.text)
        self.assertIn("Agent Two", r.text)

    def test_home_redirects_to_login_and_clears_invalid_access_cookie(self) -> None:
        # If an access_token cookie exists but fails validation, we should clear it
        # to avoid redirect loops.
        self.mod.authenticate_user_access_token = mock.Mock(side_effect=PermissionError("bad token"))
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
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.client.cookies.set("marvain_access_token", "atok")

        r = self.client.get("/livekit-test")
        self.assertEqual(r.status_code, 200)
        self.assertIn("LiveKit test", r.text)
        self.assertIn("livekit-client.umd.min.js", r.text)

    def test_livekit_test_escapes_space_id_in_html(self) -> None:
        # Regression test for reflected XSS: user-controlled `space_id` must not be
        # injected into <script> blocks.
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.client.cookies.set("marvain_access_token", "atok")

        space_id = "</script><img src=x onerror=alert(1)>"
        r = self.client.get("/livekit-test", params={"space_id": space_id})
        self.assertEqual(r.status_code, 200)

        escaped = html.escape(space_id, quote=True)
        self.assertIn(f'value="{escaped}"', r.text)
        self.assertNotIn(space_id, r.text)

    def test_gui_livekit_token_mints_token(self) -> None:
        # Configure LiveKit in module config.
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            livekit_url="wss://livekit.example",
            livekit_secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:lk",
        )

        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.get_secret_json = mock.Mock(return_value={"api_key": "k", "api_secret": "s"})
        self.mod.mint_livekit_join_token = mock.Mock(return_value="jwt")
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a1"}])
        self.mod._db = fake_db

        self.client.cookies.set("marvain_access_token", "atok")
        r = self.client.post("/livekit/token", json={"space_id": "space-1"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "wss://livekit.example")
        self.assertEqual(body["token"], "jwt")
        self.assertEqual(body["room"], "space-1")
        self.assertEqual(body["identity"], "user:u1")
