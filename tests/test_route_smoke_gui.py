from __future__ import annotations

import dataclasses
import importlib.util
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

_UUID0 = "00000000-0000-0000-0000-000000000000"
_PATH_PARAM_RE = re.compile(r"{[^}]+}")


def _render_path(path_template: str) -> str:
    return _PATH_PARAM_RE.sub(_UUID0, path_template)


_cached_hub_api_module = None


def _load_hub_api_gui_module():
    """Load functions/hub_api/app.py as a module without requiring it be a package."""
    global _cached_hub_api_module
    if _cached_hub_api_module is not None:
        return _cached_hub_api_module

    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    # Prevent route duplication when multiple test modules import app.py (which imports api_app and adds GUI routes
    # to the same FastAPI app object).
    for mod_name in ["api_app", "hub_api_app_for_route_smoke_gui"]:
        if mod_name in sys.modules:
            del sys.modules[mod_name]

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_route_smoke_gui", app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)

    _cached_hub_api_module = mod
    return mod


class TestRouteSmokeGui(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        cls.mod = _load_hub_api_gui_module()
        cls.client = TestClient(cls.mod.app, raise_server_exceptions=False)

    def setUp(self) -> None:
        # Provide Cognito config so /login and /logout can build redirect URLs without error.
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            cognito_domain="marvain-dev.auth.us-west-2.amazoncognito.com",
            cognito_user_pool_id="pool-123",
            cognito_user_pool_client_id="client-123",
            cognito_redirect_uri="http://testserver/auth/callback",
        )

    def test_gui_routes_reachable(self) -> None:
        from fastapi.routing import APIRoute

        public_assertions: dict[tuple[str, str], set[int]] = {
            ("GET", "/health"): {200},
            ("GET", "/logged-out"): {200},
            # /login is an external redirect; we must not follow redirects.
            ("GET", "/login"): {302, 307},
        }

        routes: list[tuple[str, str]] = []
        for route in self.mod.app.routes:
            if not isinstance(route, APIRoute):
                continue
            if route.path.startswith("/v1/"):
                continue
            for method in sorted(route.methods or set()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                routes.append((method, route.path))

        self.assertGreater(len(routes), 0, "No GUI routes discovered; test harness is broken")

        for method, path_template in routes:
            path = _render_path(path_template)
            r = self.client.request(method, path, follow_redirects=False)

            allowed = public_assertions.get((method, path_template))
            if allowed is not None:
                self.assertIn(
                    r.status_code,
                    allowed,
                    msg=f"Unexpected status for public route {method} {path_template}: {r.status_code}",
                )
                continue

            self.assertNotEqual(
                r.status_code,
                404,
                msg=f"Route not matched (404): {method} {path_template} (rendered {path})",
            )
            self.assertNotEqual(
                r.status_code,
                500,
                msg=f"Route crashed (500): {method} {path_template} (rendered {path})",
            )
