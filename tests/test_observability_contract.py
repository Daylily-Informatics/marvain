from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from agent_hub.observability import (
    ComponentMeasurement,
    ObservabilityContractError,
    RequestMeasurement,
    RuntimeMeasurementRegistry,
)

NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def _request(status: int, elapsed_ms: float, *, error_code: str | None = None) -> RequestMeasurement:
    return RequestMeasurement(
        method="get",
        route_template="/v1/memories/{memory_id}",
        status_code=status,
        elapsed_ms=elapsed_ms,
        observed_at=NOW + timedelta(milliseconds=elapsed_ms),
        request_id=f"request-{status}-{elapsed_ms}",
        correlation_id="correlation-1",
        error_code=error_code,
    )


def test_request_snapshot_reports_only_recorded_measurements() -> None:
    registry = RuntimeMeasurementRegistry(max_request_measurements=10)
    assert registry.request_snapshot() == {
        "schema": "marvain.observability.v1",
        "measurement_count": 0,
        "measured": False,
        "routes": [],
    }

    registry.record_request(_request(200, 5.0))
    registry.record_request(_request(200, 10.0))
    registry.record_request(_request(503, 20.0, error_code="tapdb_unavailable"))

    snapshot = registry.request_snapshot()
    route = snapshot["routes"][0]
    assert snapshot["measured"] is True
    assert route["request_count"] == 3
    assert route["status_class_counts"] == {"2xx": 2, "5xx": 1}
    assert route["error_code_counts"] == {"tapdb_unavailable": 1}
    assert (route["p50_ms"], route["p95_ms"], route["p99_ms"]) == (10.0, 20.0, 20.0)


def test_request_measurement_rejects_invalid_or_unattributed_evidence() -> None:
    registry = RuntimeMeasurementRegistry()
    with pytest.raises(ObservabilityContractError, match="request_id is required"):
        registry.record_request(
            RequestMeasurement(
                method="GET",
                route_template="/health",
                status_code=200,
                elapsed_ms=1,
                observed_at=NOW,
                request_id="",
                correlation_id="correlation-1",
            )
        )
    with pytest.raises(ObservabilityContractError, match="finite and non-negative"):
        registry.record_request(
            RequestMeasurement(
                method="GET",
                route_template="/health",
                status_code=200,
                elapsed_ms=float("nan"),
                observed_at=NOW,
                request_id="request-1",
                correlation_id="correlation-1",
            )
        )


def test_component_snapshot_fails_closed_when_required_measurement_is_missing() -> None:
    registry = RuntimeMeasurementRegistry()
    registry.record_component(
        ComponentMeasurement(
            component="database",
            state="healthy",
            observed_at=NOW,
            latency_ms=4.2,
            evidence_id="db-probe-1",
        )
    )

    snapshot = registry.component_snapshot(required_components=("database", "tapdb"))

    assert snapshot["state"] == "unavailable"
    assert snapshot["measured"] is False
    assert snapshot["missing_components"] == ["tapdb"]


def test_component_snapshot_uses_latest_measured_state_and_rejects_time_reversal() -> None:
    registry = RuntimeMeasurementRegistry()
    healthy = ComponentMeasurement(
        component="recognition_worker",
        state="healthy",
        observed_at=NOW,
        latency_ms=None,
        evidence_id="heartbeat-1",
    )
    failed = ComponentMeasurement(
        component="recognition_worker",
        state="failed",
        observed_at=NOW + timedelta(seconds=1),
        latency_ms=None,
        evidence_id="heartbeat-2",
        detail_code="model_unavailable",
    )
    registry.record_component(healthy)
    registry.record_component(failed)

    snapshot = registry.component_snapshot(required_components=("recognition_worker",))

    assert snapshot["state"] == "failed"
    assert snapshot["components"][0]["evidence_id"] == "heartbeat-2"
    with pytest.raises(ObservabilityContractError, match="older"):
        registry.record_component(healthy)
