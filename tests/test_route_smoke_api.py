from __future__ import annotations

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
    # Replace all path params (including `{param:path}` style) with a stable placeholder.
    return _PATH_PARAM_RE.sub(_UUID0, path_template)


def _load_hub_api_app_module():
    """Load functions/hub_api/api_app.py as a module without requiring it be a package."""
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

    api_app_py = repo_root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_route_smoke", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules so Pydantic/FastAPI can resolve postponed annotations.
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


class TestRouteSmokeApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        cls.mod = _load_hub_api_app_module()
        # Keep exceptions as 500 responses so the smoke test can report method/path.
        cls.client = TestClient(cls.mod.api_app, raise_server_exceptions=False)

    def test_api_routes_reachable(self) -> None:
        from fastapi.routing import APIRoute

        public_200 = {
            ("GET", "/health"),
            ("GET", "/docs"),
            ("GET", "/openapi.json"),
            ("GET", "/redoc"),
            ("GET", "/v1/delegate/scopes"),
        }

        routes: list[tuple[str, str]] = []
        for route in self.mod.api_app.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in sorted(route.methods or set()):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                routes.append((method, route.path))

        self.assertGreater(len(routes), 0, "No API routes discovered; test harness is broken")

        for method, path_template in routes:
            path = _render_path(path_template)
            r = self.client.request(method, path, follow_redirects=False)

            if (method, path_template) in public_200:
                self.assertEqual(
                    r.status_code,
                    200,
                    msg=f"Expected 200 for public route {method} {path_template}, got {r.status_code}",
                )
            else:
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

