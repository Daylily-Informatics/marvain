from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cli_core_yo import output
from cli_core_yo.runtime import get_context
from click import ClickException
from typer import Argument, Option


@dataclass(frozen=True)
class FailureScenario:
    name: str
    component: str
    injected_signal: str
    expected_status: str
    user_visible_effect: str
    observability_surface: str
    recovery_signal: str


FAILURE_SCENARIOS: tuple[FailureScenario, ...] = (
    FailureScenario(
        name="openai-outage",
        component="planner",
        injected_signal="OpenAI API request raises upstream_unavailable",
        expected_status="planner_failed",
        user_visible_effect="session remains active and the failed turn is visible for retry",
        observability_surface="planner error metric and recent event failure detail",
        recovery_signal="next planner request succeeds with a new event id",
    ),
    FailureScenario(
        name="livekit-token-failure",
        component="livekit",
        injected_signal="LiveKit token minting raises credential_error",
        expected_status="join_blocked",
        user_visible_effect="voice join request is rejected before room admission",
        observability_surface="LiveKit token failure count and GUI toast detail",
        recovery_signal="token endpoint returns a signed join token",
    ),
    FailureScenario(
        name="tapdb-write-failure",
        component="tapdb",
        injected_signal="semantic projection write raises tapdb_write_failed",
        expected_status="semantic_sync_failed",
        user_visible_effect="canonical memory remains queryable while semantic projection is marked failed",
        observability_surface="semantic_sync_status failed row with last_error",
        recovery_signal="semantic_sync_status transitions to synced",
    ),
    FailureScenario(
        name="duplicate-action",
        component="actions",
        injected_signal="same idempotency key is submitted twice",
        expected_status="duplicate_suppressed",
        user_visible_effect="the original action is returned and no second command is dispatched",
        observability_surface="action idempotency decision in action diagnostics",
        recovery_signal="a new idempotency key creates one new action",
    ),
    FailureScenario(
        name="device-disconnect",
        component="devices",
        injected_signal="device heartbeat expires before action dispatch",
        expected_status="device_offline",
        user_visible_effect="command is held or failed with explicit offline device status",
        observability_surface="device freshness and awaiting-device action counts",
        recovery_signal="fresh heartbeat returns device to online routing",
    ),
    FailureScenario(
        name="missing-s3-artifact",
        component="artifacts",
        injected_signal="artifact lookup returns NoSuchKey",
        expected_status="artifact_missing",
        user_visible_effect="artifact preview/download reports missing object",
        observability_surface="artifact access failure detail and audit event",
        recovery_signal="object exists and presign succeeds",
    ),
    FailureScenario(
        name="expired-consent",
        component="consent",
        injected_signal="recognition or action request uses consent past expires_at",
        expected_status="consent_expired",
        user_visible_effect="biometric recognition or protected action is denied",
        observability_surface="consent denial count and person consent detail",
        recovery_signal="new active consent row authorizes the request",
    ),
)

_SCENARIOS_BY_NAME = {item.name: item for item in FAILURE_SCENARIOS}


def scenario_names() -> list[str]:
    return [item.name for item in FAILURE_SCENARIOS]


def failure_catalog() -> list[dict[str, str]]:
    return [
        {
            "name": item.name,
            "component": item.component,
            "expected_status": item.expected_status,
            "observability_surface": item.observability_surface,
        }
        for item in FAILURE_SCENARIOS
    ]


def build_failure_report(name: str, seed: str = "marvain-failure-inject-v1") -> dict[str, Any]:
    scenario = _SCENARIOS_BY_NAME.get(name)
    if scenario is None:
        allowed = ", ".join(scenario_names())
        raise ClickException(f"Unknown failure scenario {name!r}. Expected one of: {allowed}")

    injection_id = str(uuid5(NAMESPACE_URL, f"marvain:failure:{seed}:{scenario.name}"))
    return {
        "failure": scenario.name,
        "seed": seed,
        "deterministic": True,
        "injection_id": injection_id,
        "component": scenario.component,
        "injected_signal": scenario.injected_signal,
        "expected_status": scenario.expected_status,
        "user_visible_effect": scenario.user_visible_effect,
        "observability_surface": scenario.observability_surface,
        "recovery_signal": scenario.recovery_signal,
        "production_fallback": False,
        "mutates_runtime": False,
    }


def inject_cmd(
    scenario: str = Argument(..., help="Failure scenario name"),
    seed: str = Option("marvain-failure-inject-v1", "--seed", help="Deterministic injection seed"),
) -> None:
    """Return a deterministic local failure-injection report."""
    data = build_failure_report(name=scenario, seed=seed)
    if get_context().json_mode:
        output.emit_json(data)
        return
    output.print_text(json.dumps(data, indent=2, sort_keys=True))
