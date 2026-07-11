from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from route_behavior_receipt import record_http_evidence

ROOT = Path(__file__).resolve().parents[1]
USER_ID = "33333333-3333-3333-3333-333333333333"


class EmptyDb:
    def query(self, _sql: str, _params: dict[str, object] | None = None) -> list[dict[str, object]]:
        return []

    def execute(self, _sql: str, _params: dict[str, object] | None = None) -> dict[str, object]:
        return {}


@dataclass(frozen=True)
class GuiHarness:
    mod: ModuleType
    client: TestClient


_cached_module: ModuleType | None = None


def _load_gui_module() -> ModuleType:
    global _cached_module
    if _cached_module is not None:
        return _cached_module
    shared = ROOT / "layers" / "shared" / "python"
    hub_api = ROOT / "functions" / "hub_api"
    for path in (shared, hub_api):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:route-behavior")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:route-behavior")
    os.environ.setdefault("DB_NAME", "route_behavior")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "route-behavior-session-secret")
    for module_name in ("api_app", "hub_api_app_for_route_behavior_gui"):
        sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(
        "hub_api_app_for_route_behavior_gui",
        ROOT / "functions" / "hub_api" / "app.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    _cached_module = module
    return module


@pytest.fixture
def gui_harness(monkeypatch: pytest.MonkeyPatch) -> GuiHarness:
    mod = _load_gui_module()
    user = mod.AuthenticatedUser(user_id=USER_ID, cognito_sub="route-sub", email="route@example.test")
    monkeypatch.setattr(mod, "_gui_get_user", lambda _request: user)
    monkeypatch.setattr(mod, "_get_db", lambda: EmptyDb())
    monkeypatch.setattr(mod, "list_agents_for_user", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(mod, "list_spaces_for_user", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        mod,
        "_cfg",
        dataclasses.replace(
            mod._cfg,
            cognito_domain="marvain-test.auth.us-west-2.amazoncognito.com",
            cognito_user_pool_id="pool-route-behavior",
            cognito_user_pool_client_id="client-route-behavior",
            cognito_redirect_uri="http://testserver/auth/callback",
        ),
    )
    return GuiHarness(mod=mod, client=TestClient(mod.app, raise_server_exceptions=False))


def _assert_html(response: object) -> None:
    assert getattr(response, "status_code", None) == 200
    assert str(getattr(response, "headers", {}).get("content-type", "")).startswith("text/html")
    assert "Marvain" in str(getattr(response, "text", ""))


def test_gui_service_manifest_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/obs_services")

    assert response.status_code == 200
    assert response.json()["schema"] == "marvain.observability.v1"
    record_http_evidence(request, surface="gui", method="GET", path="/obs_services", kind="success", response=response)


def test_gui_api_health_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/api_health")

    assert response.status_code == 200
    assert response.json()["schema"] == "marvain.observability.v1"
    assert isinstance(response.json()["families"], list)
    record_http_evidence(request, surface="gui", method="GET", path="/api_health", kind="success", response=response)


def test_gui_endpoint_health_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/endpoint_health")

    assert response.status_code == 200
    assert isinstance(response.json()["items"], list)
    record_http_evidence(
        request, surface="gui", method="GET", path="/endpoint_health", kind="success", response=response
    )


def test_gui_db_health_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/db_health")

    assert response.status_code == 200
    assert response.json()["database"]["config"]["rds_data_api_configured"] is True
    record_http_evidence(request, surface="gui", method="GET", path="/db_health", kind="success", response=response)


def test_gui_auth_health_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/auth_health")

    assert response.status_code == 200
    assert response.json()["auth"]["cognito_configured"] is True
    record_http_evidence(request, surface="gui", method="GET", path="/auth_health", kind="success", response=response)


def test_gui_my_health_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/my_health")

    assert response.status_code == 200
    assert response.json()["principal"]["authenticated"] is True
    record_http_evidence(request, surface="gui", method="GET", path="/my_health", kind="success", response=response)


def test_gui_login_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/login", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://marvain-test.auth.us-west-2.amazoncognito.com/")
    record_http_evidence(request, surface="gui", method="GET", path="/login", kind="success", response=response)


def test_gui_logged_out_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/logged-out")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Logged out" in response.text
    assert "href='/login'" in response.text
    record_http_evidence(request, surface="gui", method="GET", path="/logged-out", kind="success", response=response)


def test_gui_dashboard_kpi_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/dashboard/kpi-strip")

    assert response.status_code == 200
    assert "Agents Online" in response.text
    record_http_evidence(
        request, surface="gui", method="GET", path="/dashboard/kpi-strip", kind="success", response=response
    )


def test_gui_dashboard_kpi_denial(
    request: pytest.FixtureRequest,
    gui_harness: GuiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gui_harness.mod, "_gui_get_user", lambda _request: None)
    response = gui_harness.client.get("/dashboard/kpi-strip")

    assert response.status_code == 401
    record_http_evidence(
        request, surface="gui", method="GET", path="/dashboard/kpi-strip", kind="denial", response=response
    )


def test_gui_dashboard_activity_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/dashboard/activity-feed")

    assert response.status_code == 200
    assert "No recent events" in response.text
    record_http_evidence(
        request,
        surface="gui",
        method="GET",
        path="/dashboard/activity-feed",
        kind="success",
        response=response,
    )


def test_gui_dashboard_activity_denial(
    request: pytest.FixtureRequest,
    gui_harness: GuiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gui_harness.mod, "_gui_get_user", lambda _request: None)
    response = gui_harness.client.get("/dashboard/activity-feed")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="gui",
        method="GET",
        path="/dashboard/activity-feed",
        kind="denial",
        response=response,
    )


def test_gui_dashboard_actions_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/dashboard/recent-actions")

    assert response.status_code == 200
    assert "No recent actions" in response.text
    record_http_evidence(
        request,
        surface="gui",
        method="GET",
        path="/dashboard/recent-actions",
        kind="success",
        response=response,
    )


def test_gui_dashboard_actions_denial(
    request: pytest.FixtureRequest,
    gui_harness: GuiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gui_harness.mod, "_gui_get_user", lambda _request: None)
    response = gui_harness.client.get("/dashboard/recent-actions")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="gui",
        method="GET",
        path="/dashboard/recent-actions",
        kind="denial",
        response=response,
    )


def test_gui_dashboard_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/", kind="success", response=response)


def test_gui_agents_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/agents")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/agents", kind="success", response=response)


def test_gui_people_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/people")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/people", kind="success", response=response)


def test_gui_locations_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/locations")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/locations", kind="success", response=response)


def test_gui_spaces_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/spaces")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/spaces", kind="success", response=response)


def test_gui_devices_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/devices")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/devices", kind="success", response=response)


def test_gui_sessions_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/sessions")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/sessions", kind="success", response=response)


def test_gui_live_session_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/live-session")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/live-session", kind="success", response=response)


def test_gui_memories_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/memories")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/memories", kind="success", response=response)


def test_gui_recognition_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/recognition")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/recognition", kind="success", response=response)


def test_gui_actions_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/actions")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/actions", kind="success", response=response)


def test_gui_action_guide_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/actions/guide")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/actions/guide", kind="success", response=response)


def test_gui_tools_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/tools")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/tools", kind="success", response=response)


def test_gui_personas_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/personas")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/personas", kind="success", response=response)


def test_gui_audit_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/audit")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/audit", kind="success", response=response)


def test_gui_observability_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/observability")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/observability", kind="success", response=response)


def test_gui_capabilities_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/capabilities")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/capabilities", kind="success", response=response)


def test_gui_artifacts_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/artifacts")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/artifacts", kind="success", response=response)


def test_gui_profile_success(request: pytest.FixtureRequest, gui_harness: GuiHarness) -> None:
    response = gui_harness.client.get("/profile")
    _assert_html(response)
    record_http_evidence(request, surface="gui", method="GET", path="/profile", kind="success", response=response)
