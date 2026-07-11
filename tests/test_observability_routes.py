from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agent_hub.auth import AuthenticatedUser
from agent_hub.observability import ComponentMeasurement, RuntimeMeasurementRegistry
from agent_hub.observability_routes import install_observability_routes
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def _app(*, database_state: str = "healthy") -> tuple[FastAPI, RuntimeMeasurementRegistry]:
    app = FastAPI()
    registry = RuntimeMeasurementRegistry()

    def resolve_principal(_request: Request) -> AuthenticatedUser:
        return AuthenticatedUser(
            user_id="user-1",
            cognito_sub="sub-1",
            email="user@example.test",
        )

    @app.get("/v1/example")
    def example():
        return {"ok": True}

    install_observability_routes(
        app,
        environment="test",
        registry=registry,
        resolve_principal=resolve_principal,
        probe_database=lambda request: ComponentMeasurement(
            component="database",
            state=database_state,
            observed_at=datetime.now(timezone.utc),
            latency_ms=1.25,
            evidence_id=f"database:{request.state.request_id}",
            detail_code="database_query_succeeded" if database_state == "healthy" else "database_probe_failed",
        ),
        dependency_configuration=lambda: {
            "authentication": True,
            "database": True,
            "tapdb": False,
        },
    )
    return app, registry


def test_observability_routes_measure_requests_and_do_not_advertise_absent_graphs() -> None:
    app, _registry = _app()
    client = TestClient(app)

    example = client.get("/v1/example", headers={"X-Correlation-Id": "corr-1"})
    assert example.status_code == 200
    assert example.headers["X-Correlation-Id"] == "corr-1"
    assert example.headers["X-Request-Id"]

    manifest = client.get("/obs_services").json()
    assert manifest["schema"] == "marvain.observability.v1"
    assert manifest["graph_endpoints"] == []
    assert {item["service"] for item in manifest["dependencies"]["configured_services"]} == {
        "authentication",
        "database",
        "tapdb",
    }

    routes = client.get("/endpoint_health?limit=200").json()
    example_route = next(item for item in routes["items"] if item["route_template"] == "/v1/example")
    assert example_route["status"] == "healthy"
    assert example_route["request_count"] == 1
    assert example_route["status_class_counts"] == {"2xx": 1}


def test_database_and_auth_health_never_infer_missing_measurements() -> None:
    app, registry = _app(database_state="failed")
    client = TestClient(app)

    auth = client.get("/auth_health").json()
    assert auth["status"] == "unavailable"
    assert auth["auth"]["measured"] is False
    assert auth["auth"]["missing_components"] == ["authentication"]

    database = client.get("/db_health").json()
    assert database["status"] == "failed"
    assert database["database"]["measured"] is True
    assert database["database"]["components"][0]["detail_code"] == "database_probe_failed"

    registry.record_component(
        ComponentMeasurement(
            component="authentication",
            state="healthy",
            observed_at=datetime.now(timezone.utc),
            latency_ms=None,
            evidence_id="auth:verified-request",
            detail_code="browser_session_verified",
        )
    )
    measured_auth = client.get("/auth_health").json()
    assert measured_auth["status"] == "healthy"
    assert measured_auth["auth"]["components"][0]["evidence_id"] == "auth:verified-request"


def test_my_health_uses_the_canonical_user_dependency_without_identity_values() -> None:
    app, _registry = _app()
    response = TestClient(app).get("/my_health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["principal"] == {
        "kind": "browser_session",
        "authenticated": True,
        "subject_present": True,
        "user_id_present": True,
        "email_present": True,
    }
    assert "user@example.test" not in response.text
    assert "sub-1" not in response.text
    assert "user-1" not in response.text


def test_local_gui_no_longer_declares_duplicate_health_routes() -> None:
    text = (ROOT / "functions/hub_api/app.py").read_text(encoding="utf-8")
    for path in ("/obs_services", "/api_health", "/endpoint_health", "/db_health", "/auth_health", "/my_health"):
        assert f'@app.get("{path}"' not in text
