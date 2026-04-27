from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def _load_app_module():
    shared = ROOT / "layers" / "shared" / "python"
    hub_api_dir = ROOT / "functions" / "hub_api"
    for path in (shared, hub_api_dir):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    for mod_name in ["api_app", "hub_api_app_round2_routes"]:
        sys.modules.pop(mod_name, None)

    spec = importlib.util.spec_from_file_location(
        "hub_api_app_round2_routes", ROOT / "functions" / "hub_api" / "app.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def test_round2_pages_redirect_to_login_when_unauthenticated() -> None:
    mod = _load_app_module()
    mod._cfg = dataclasses.replace(
        mod._cfg,
        cognito_domain="marvain-dev.auth.us-west-2.amazoncognito.com",
        cognito_user_pool_id="pool-123",
        cognito_user_pool_client_id="client-123",
        cognito_redirect_uri="http://testserver/auth/callback",
    )
    client = TestClient(mod.app, raise_server_exceptions=False)
    for path in [
        "/capabilities",
        "/personas",
        "/locations",
        "/sessions",
        "/recognition",
        "/tapdb/graph",
        "/observability",
        "/live-session",
    ]:
        response = client.get(path, follow_redirects=False)
        assert response.status_code in {302, 307}, path
        assert "/login" in response.headers.get("location", "")


def test_capabilities_api_requires_authentication() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)
    response = client.get("/api/capabilities")
    assert response.status_code == 401


def test_new_round2_api_routes_require_authentication() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)

    assert (
        client.post(
            "/api/personas",
            json={"agent_id": "agent-1", "name": "Operator", "instructions": "Stay concise."},
        ).status_code
        == 401
    )
    assert client.post("/api/personas/00000000-0000-0000-0000-000000000000/make-default").status_code == 401
    assert client.post("/api/live-session/smoke", json={"transcript_text": "hello"}).status_code == 401
    assert (
        client.post(
            "/api/live-session/00000000-0000-0000-0000-000000000000/chat",
            json={"text": "hello"},
        ).status_code
        == 401
    )
    assert client.get("/api/live-session/00000000-0000-0000-0000-000000000000/events").status_code == 401
