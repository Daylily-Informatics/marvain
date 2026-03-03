from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger(__name__)


def emit_metric(
    *,
    name: str,
    value: float,
    unit: str = "Count",
    dimensions: dict[str, str] | None = None,
    namespace: str | None = None,
) -> None:
    """Emit an Embedded Metrics Format payload to CloudWatch Logs."""
    dims = dimensions or {}
    metric_ns = namespace or os.getenv("MARVAIN_METRICS_NAMESPACE", "Marvain")
    dim_keys = sorted(dims.keys())

    payload: dict[str, object] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": metric_ns,
                    "Dimensions": [dim_keys],
                    "Metrics": [{"Name": name, "Unit": unit}],
                }
            ],
        },
        name: value,
    }
    for key, val in dims.items():
        payload[key] = val

    logger.info(json.dumps(payload, sort_keys=True))


def emit_count(name: str, *, dimensions: dict[str, str] | None = None) -> None:
    emit_metric(name=name, value=1.0, unit="Count", dimensions=dimensions)


def emit_ms(name: str, *, value_ms: float, dimensions: dict[str, str] | None = None) -> None:
    emit_metric(name=name, value=value_ms, unit="Milliseconds", dimensions=dimensions)
