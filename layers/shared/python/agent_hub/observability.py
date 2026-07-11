"""Measured Marvain request and component observability contracts."""

from __future__ import annotations

import math
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

OBSERVABILITY_SCHEMA = "marvain.observability.v1"


class ObservabilityContractError(ValueError):
    """Raised when a measurement would overstate or corrupt runtime evidence."""


def _required(value: str | None, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ObservabilityContractError(f"{field} is required")
    return normalized


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ObservabilityContractError(f"{field} must be timezone-aware")
    return value


@dataclass(frozen=True)
class RequestMeasurement:
    method: str
    route_template: str
    status_code: int
    elapsed_ms: float
    observed_at: datetime
    request_id: str
    correlation_id: str
    error_code: str | None = None

    def validated(self) -> RequestMeasurement:
        method = _required(self.method, "method").upper()
        route_template = _required(self.route_template, "route_template")
        if not route_template.startswith("/"):
            raise ObservabilityContractError("route_template must start with /")
        if not isinstance(self.status_code, int) or isinstance(self.status_code, bool):
            raise ObservabilityContractError("status_code must be an integer")
        if self.status_code < 100 or self.status_code > 599:
            raise ObservabilityContractError("status_code must be between 100 and 599")
        elapsed_ms = float(self.elapsed_ms)
        if not math.isfinite(elapsed_ms) or elapsed_ms < 0:
            raise ObservabilityContractError("elapsed_ms must be finite and non-negative")
        error_code = str(self.error_code).strip() if self.error_code is not None else None
        if error_code == "":
            raise ObservabilityContractError("error_code cannot be empty")
        return RequestMeasurement(
            method=method,
            route_template=route_template,
            status_code=self.status_code,
            elapsed_ms=elapsed_ms,
            observed_at=_aware(self.observed_at, "observed_at"),
            request_id=_required(self.request_id, "request_id"),
            correlation_id=_required(self.correlation_id, "correlation_id"),
            error_code=error_code,
        )


@dataclass(frozen=True)
class ComponentMeasurement:
    component: str
    state: str
    observed_at: datetime
    latency_ms: float | None
    evidence_id: str
    detail_code: str | None = None

    def validated(self) -> ComponentMeasurement:
        state = _required(self.state, "state")
        if state not in {"healthy", "degraded", "failed", "unavailable"}:
            raise ObservabilityContractError("unsupported component state")
        latency = None if self.latency_ms is None else float(self.latency_ms)
        if latency is not None and (not math.isfinite(latency) or latency < 0):
            raise ObservabilityContractError("latency_ms must be finite and non-negative")
        detail_code = str(self.detail_code).strip() if self.detail_code is not None else None
        if detail_code == "":
            raise ObservabilityContractError("detail_code cannot be empty")
        return ComponentMeasurement(
            component=_required(self.component, "component"),
            state=state,
            observed_at=_aware(self.observed_at, "observed_at"),
            latency_ms=latency,
            evidence_id=_required(self.evidence_id, "evidence_id"),
            detail_code=detail_code,
        )


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered)) - 1
    return round(ordered[max(0, min(rank, len(ordered) - 1))], 3)


class RuntimeMeasurementRegistry:
    """Bounded in-process measurements; snapshots never synthesize missing data."""

    def __init__(self, *, max_request_measurements: int = 10_000) -> None:
        if not isinstance(max_request_measurements, int) or isinstance(max_request_measurements, bool):
            raise ObservabilityContractError("max_request_measurements must be an integer")
        if max_request_measurements < 1:
            raise ObservabilityContractError("max_request_measurements must be positive")
        self._requests: deque[RequestMeasurement] = deque(maxlen=max_request_measurements)
        self._components: dict[str, ComponentMeasurement] = {}
        self._lock = threading.Lock()

    def record_request(self, measurement: RequestMeasurement) -> None:
        validated = measurement.validated()
        with self._lock:
            self._requests.append(validated)

    def record_component(self, measurement: ComponentMeasurement) -> None:
        validated = measurement.validated()
        with self._lock:
            current = self._components.get(validated.component)
            if current is not None and validated.observed_at < current.observed_at:
                raise ObservabilityContractError("component measurement is older than the current observation")
            self._components[validated.component] = validated

    def request_snapshot(self) -> dict:
        with self._lock:
            values = tuple(self._requests)
        by_route: dict[tuple[str, str], list[RequestMeasurement]] = defaultdict(list)
        for item in values:
            by_route[(item.method, item.route_template)].append(item)
        routes = []
        for (method, route_template), measurements in sorted(by_route.items()):
            latencies = [item.elapsed_ms for item in measurements]
            status_classes = Counter(f"{item.status_code // 100}xx" for item in measurements)
            error_codes = Counter(item.error_code for item in measurements if item.error_code)
            routes.append(
                {
                    "method": method,
                    "route_template": route_template,
                    "request_count": len(measurements),
                    "status_class_counts": dict(sorted(status_classes.items())),
                    "error_code_counts": dict(sorted(error_codes.items())),
                    "p50_ms": _percentile(latencies, 0.50),
                    "p95_ms": _percentile(latencies, 0.95),
                    "p99_ms": _percentile(latencies, 0.99),
                    "last_observed_at": max(item.observed_at for item in measurements).isoformat(),
                }
            )
        return {
            "schema": OBSERVABILITY_SCHEMA,
            "measurement_count": len(values),
            "measured": bool(values),
            "routes": routes,
        }

    def component_snapshot(self, *, required_components: Iterable[str]) -> dict:
        required = tuple(dict.fromkeys(_required(item, "required_component") for item in required_components))
        with self._lock:
            current = dict(self._components)
        components = []
        missing = []
        for name in required:
            measurement = current.get(name)
            if measurement is None:
                missing.append(name)
                continue
            components.append(
                {
                    "component": measurement.component,
                    "state": measurement.state,
                    "observed_at": measurement.observed_at.isoformat(),
                    "latency_ms": measurement.latency_ms,
                    "evidence_id": measurement.evidence_id,
                    "detail_code": measurement.detail_code,
                }
            )
        if missing:
            overall = "unavailable"
        elif any(item["state"] == "failed" for item in components):
            overall = "failed"
        elif any(item["state"] in {"degraded", "unavailable"} for item in components):
            overall = "degraded"
        else:
            overall = "healthy"
        return {
            "schema": OBSERVABILITY_SCHEMA,
            "state": overall,
            "measured": not missing,
            "missing_components": missing,
            "components": components,
        }


runtime_measurements = RuntimeMeasurementRegistry()


__all__ = [
    "ComponentMeasurement",
    "OBSERVABILITY_SCHEMA",
    "ObservabilityContractError",
    "RequestMeasurement",
    "RuntimeMeasurementRegistry",
    "runtime_measurements",
]
