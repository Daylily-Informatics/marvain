"""Marvain-native measured observability routes for FastAPI runtimes."""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from agent_hub.auth import AuthenticatedUser
from agent_hub.observability import (
    OBSERVABILITY_SCHEMA,
    ComponentMeasurement,
    RequestMeasurement,
    RuntimeMeasurementRegistry,
)

PrincipalResolver = Callable[[Request], AuthenticatedUser]
DatabaseProbe = Callable[[Request], ComponentMeasurement]
DependencyConfiguration = Callable[[], Mapping[str, bool]]


def _observed_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base(request: Request, *, environment: str, status: str) -> dict[str, Any]:
    return {
        "schema": OBSERVABILITY_SCHEMA,
        "service": "marvain",
        "environment": environment,
        "instance_id": str(os.getenv("MARVAIN_INSTANCE_ID") or "").strip() or None,
        "observed_at": _observed_at(),
        "status": status,
        "request_id": str(getattr(request.state, "request_id", "") or ""),
        "correlation_id": str(getattr(request.state, "correlation_id", "") or ""),
        "build": {
            "version": str(os.getenv("MARVAIN_BUILD_VERSION") or "").strip() or None,
            "sha": str(os.getenv("GIT_SHA") or "").strip() or None,
        },
    }


def _projection(status: str, *, detail: str) -> dict[str, Any]:
    return {
        "state": status,
        "stale": status in {"unavailable", "unmeasured"},
        "observed_at": _observed_at(),
        "last_synced_at": None,
        "detail": detail,
    }


def _graph_endpoints(app: FastAPI) -> list[dict[str, str]]:
    route_paths = {str(getattr(route, "path", "") or "") for route in app.routes}
    endpoints: list[dict[str, str]] = []
    if "/api/dag/{path:path}" in route_paths:
        endpoints.extend(
            [
                {
                    "path": "/api/dag/data",
                    "auth": "browser_session",
                    "kind": "graph_data",
                    "start_param": "start_euid",
                    "depth_param": "depth",
                    "format": "dag:v1",
                },
                {
                    "path": "/api/dag/object/{euid}",
                    "auth": "browser_session",
                    "kind": "graph_object",
                    "euid_param": "euid",
                    "format": "tapdb-object:v1",
                },
            ]
        )
    if "/tapdb" in route_paths:
        endpoints.append(
            {
                "path": "/tapdb/graph",
                "auth": "browser_session",
                "kind": "graph_ui",
                "start_param": "start_euid",
                "format": "html",
            }
        )
    return endpoints


def _manifest_endpoints(app: FastAPI) -> list[dict[str, str]]:
    endpoints = [
        {"path": "/obs_services", "auth": "none", "kind": "discovery"},
        {"path": "/api_health", "auth": "none", "kind": "api_rollup"},
        {"path": "/endpoint_health", "auth": "none", "kind": "endpoint_rollup"},
        {"path": "/db_health", "auth": "none", "kind": "database"},
        {"path": "/auth_health", "auth": "none", "kind": "auth"},
        {"path": "/my_health", "auth": "authenticated_self", "kind": "self"},
    ]
    endpoints.extend(
        {"path": item["path"], "auth": item["auth"], "kind": item["kind"]} for item in _graph_endpoints(app)
    )
    return endpoints


def _route_items(app: FastAPI, registry: RuntimeMeasurementRegistry) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    manifest_by_path = {item["path"]: item for item in _manifest_endpoints(app)}
    for route in app.routes:
        path = str(getattr(route, "path", "") or "")
        if not path or path.startswith("/static"):
            continue
        methods = sorted(str(method) for method in getattr(route, "methods", []) if method not in {"HEAD", "OPTIONS"})
        if not methods:
            continue
        manifest_item = manifest_by_path.get(path)
        if manifest_item is not None and manifest_item["kind"].startswith("graph_"):
            family = "tapdb_graph"
        elif manifest_item is not None:
            family = "observability"
        else:
            family = "v1_api" if path.startswith("/v1") else "gui_api" if path.startswith("/api") else "gui"
        for method in methods:
            items.append(
                {
                    "method": method,
                    "route_template": path,
                    "status": "unmeasured",
                    "kind": manifest_item["kind"] if manifest_item is not None else "route",
                    "auth": manifest_item["auth"] if manifest_item is not None else "mixed",
                    "family": family,
                    "request_count": None,
                    "status_class_counts": None,
                    "p50_ms": None,
                    "p95_ms": None,
                    "p99_ms": None,
                    "fingerprint_count": 0,
                    "observed_at": None,
                }
            )

    existing = {(item["method"], item["route_template"]) for item in items}
    for endpoint in manifest_by_path.values():
        if ("GET", endpoint["path"]) in existing:
            continue
        items.append(
            {
                "method": "GET",
                "route_template": endpoint["path"],
                "status": "unmeasured",
                "kind": endpoint["kind"],
                "auth": endpoint["auth"],
                "family": "tapdb_graph" if endpoint["kind"].startswith("graph_") else "observability",
                "request_count": None,
                "status_class_counts": None,
                "p50_ms": None,
                "p95_ms": None,
                "p99_ms": None,
                "fingerprint_count": 0,
                "observed_at": None,
            }
        )

    measured = {
        (str(item["method"]), str(item["route_template"])): item for item in registry.request_snapshot()["routes"]
    }
    for item in items:
        measurement = measured.get((item["method"], item["route_template"]))
        if measurement is None:
            continue
        status_counts = dict(measurement["status_class_counts"])
        item.update(
            {
                "status": "failed" if int(status_counts.get("5xx", 0)) else "healthy",
                "request_count": measurement["request_count"],
                "status_class_counts": status_counts,
                "p50_ms": measurement["p50_ms"],
                "p95_ms": measurement["p95_ms"],
                "p99_ms": measurement["p99_ms"],
                "fingerprint_count": len(measurement["error_code_counts"]),
                "observed_at": measurement["last_observed_at"],
            }
        )
    return sorted(items, key=lambda item: (item["route_template"], item["method"]))


def install_observability_routes(
    app: FastAPI,
    *,
    environment: str,
    registry: RuntimeMeasurementRegistry,
    resolve_principal: PrincipalResolver,
    probe_database: DatabaseProbe,
    dependency_configuration: DependencyConfiguration,
) -> None:
    """Install one measured observability contract on local and deployed apps."""

    @app.middleware("http")
    async def request_measurement_middleware(request: Request, call_next):
        request_id = str(request.headers.get("x-request-id") or "").strip() or str(uuid.uuid4())
        correlation_id = str(request.headers.get("x-correlation-id") or "").strip() or request_id
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        started = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        route_template = str(getattr(route, "path", "") or request.url.path)
        registry.record_request(
            RequestMeasurement(
                method=request.method,
                route_template=route_template,
                status_code=response.status_code,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
                observed_at=datetime.now(timezone.utc),
                request_id=request_id,
                correlation_id=correlation_id,
                error_code=f"http_{response.status_code}" if response.status_code >= 500 else None,
            )
        )
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Correlation-Id"] = correlation_id
        return response

    @app.get("/obs_services", name="marvain_service_manifest")
    def service_manifest(request: Request) -> JSONResponse:
        payload = _base(request, environment=environment, status="configured")
        payload["kind"] = "service_manifest"
        payload["projection"] = _projection("configured", detail="Marvain service manifest")
        payload["endpoints"] = _manifest_endpoints(request.app)
        payload["dependencies"] = {
            "configured_services": [
                {"service": name, "configured": bool(configured)}
                for name, configured in sorted(dependency_configuration().items())
            ]
        }
        payload["graph_endpoints"] = _graph_endpoints(request.app)
        return JSONResponse(payload)

    @app.get("/api_health", name="marvain_api_health")
    def api_health(request: Request) -> JSONResponse:
        items = _route_items(request.app, registry)
        families: list[dict[str, Any]] = []
        for family in ("gui", "gui_api", "observability", "tapdb_graph", "v1_api"):
            family_items = [item for item in items if item["family"] == family]
            measured_items = [item for item in family_items if item["request_count"] is not None]
            request_count = sum(int(item["request_count"]) for item in measured_items)
            error_count = sum(int((item["status_class_counts"] or {}).get("5xx", 0)) for item in measured_items)
            families.append(
                {
                    "family": family,
                    "request_count": request_count if measured_items else None,
                    "error_count": error_count if measured_items else None,
                    "route_count": len(family_items),
                    "status": "failed" if error_count else "healthy" if measured_items else "unmeasured",
                }
            )
        status = (
            "failed"
            if any(item["status"] == "failed" for item in items)
            else "healthy"
            if any(item["request_count"] is not None for item in items)
            else "unmeasured"
        )
        payload = _base(request, environment=environment, status=status)
        payload["projection"] = _projection(status, detail="Measured in-process request metrics")
        payload["families"] = families
        return JSONResponse(payload)

    @app.get("/endpoint_health", name="marvain_endpoint_health")
    def endpoint_health(request: Request, offset: int = 0, limit: int = 25) -> JSONResponse:
        items = _route_items(request.app, registry)
        offset = max(0, int(offset))
        limit = min(200, max(1, int(limit)))
        status = (
            "failed"
            if any(item["status"] == "failed" for item in items)
            else "healthy"
            if any(item["request_count"] is not None for item in items)
            else "unmeasured"
        )
        payload = _base(request, environment=environment, status=status)
        payload["projection"] = _projection(status, detail="Measured in-process route metrics")
        payload["page"] = {"total": len(items), "offset": offset, "limit": limit}
        payload["items"] = items[offset : offset + limit]
        return JSONResponse(payload)

    @app.get("/db_health", name="marvain_db_health")
    def db_health(request: Request) -> JSONResponse:
        measurement = probe_database(request).validated()
        registry.record_component(measurement)
        snapshot = registry.component_snapshot(required_components=(measurement.component,))
        status = snapshot["state"]
        payload = _base(request, environment=environment, status=status)
        payload["projection"] = _projection(status, detail="Measured database dependency state")
        payload["database"] = snapshot
        return JSONResponse(payload)

    @app.get("/auth_health", name="marvain_auth_health")
    def auth_health(request: Request) -> JSONResponse:
        snapshot = registry.component_snapshot(required_components=("authentication",))
        status = snapshot["state"]
        payload = _base(request, environment=environment, status=status)
        payload["projection"] = _projection(status, detail="Observed authentication request state")
        payload["auth"] = snapshot
        return JSONResponse(payload)

    @app.get("/my_health", name="marvain_my_health")
    def my_health(request: Request, user: AuthenticatedUser = Depends(resolve_principal)) -> JSONResponse:
        payload = _base(request, environment=environment, status="healthy")
        payload["principal"] = {
            "kind": "bearer" if request.headers.get("authorization") else "browser_session",
            "authenticated": True,
            "subject_present": bool(user.cognito_sub),
            "user_id_present": bool(user.user_id),
            "email_present": bool(user.email),
        }
        payload["requests"] = registry.request_snapshot()
        return JSONResponse(payload)


__all__ = ["install_observability_routes"]
