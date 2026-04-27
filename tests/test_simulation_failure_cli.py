from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest import mock

from cli_core_yo.conformance import assert_exit_code, invoke


def _json_output(result) -> dict:
    return json.loads(result.output)


def test_simulate_two_devices_is_deterministic() -> None:
    from marvain_cli import cli

    app = cli.build_app()
    first = invoke(app, ["--json", "simulate", "two-devices", "--seed", "case-1"], prog_name="marvain")
    second = invoke(app, ["--json", "simulate", "two-devices", "--seed", "case-1"], prog_name="marvain")

    assert_exit_code(first, 0)
    assert_exit_code(second, 0)
    first_body = _json_output(first)
    second_body = _json_output(second)
    assert first_body == second_body
    assert first_body["simulation"] == "two-devices"
    assert first_body["summary"] == {
        "device_count": 2,
        "command_count": 3,
        "routed_count": 3,
        "unroutable_count": 0,
    }
    assert {device["space"]["name"] for device in first_body["devices"]} == {"kitchen", "studio"}
    assert all(route["status"] == "routed" for route in first_body["routes"])


def test_simulate_two_devices_accepts_explicit_topology_options() -> None:
    from marvain_cli import cli

    app = cli.build_app()
    result = invoke(
        app,
        [
            "--json",
            "simulate",
            "two-devices",
            "--seed",
            "case-2",
            "--agent-id",
            "agent-round3",
            "--location-a",
            "house",
            "--space-a",
            "kitchen",
            "--location-b",
            "office",
            "--space-b",
            "studio",
        ],
        prog_name="marvain",
    )

    assert_exit_code(result, 0)
    body = _json_output(result)
    assert body["agent_id"] == "agent-round3"
    assert {item["name"] for item in body["locations"]} == {"house", "office"}
    assert {item["name"]: item["location"] for item in body["spaces"]} == {
        "kitchen": "house",
        "studio": "office",
    }
    assert all(route["status"] == "routed" for route in body["routes"])


def test_failure_inject_supports_requested_scenarios() -> None:
    from marvain_cli import cli
    from marvain_cli.failure import scenario_names

    app = cli.build_app()
    expected = {
        "openai-outage",
        "livekit-token-failure",
        "tapdb-write-failure",
        "duplicate-action",
        "device-disconnect",
        "missing-s3-artifact",
        "expired-consent",
    }
    assert set(scenario_names()) == expected

    for scenario in sorted(expected):
        result = invoke(app, ["--json", "failure", "inject", scenario, "--seed", "case-1"], prog_name="marvain")
        assert_exit_code(result, 0)
        body = _json_output(result)
        assert body["failure"] == scenario
        assert body["deterministic"] is True
        assert body["mutates_runtime"] is False
        assert body["production_fallback"] is False
        assert body["expected_status"]
        assert body["observability_surface"]


def test_failure_inject_unknown_scenario_fails_hard() -> None:
    from marvain_cli import cli

    app = cli.build_app()
    result = invoke(app, ["failure", "inject", "unknown-scenario"], prog_name="marvain")

    assert result.exit_code != 0
    assert "Unknown failure scenario" in result.output


def test_observability_failure_scenarios_api_requires_auth_and_returns_catalog() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    hub_api_dir = repo_root / "functions" / "hub_api"
    for path in (shared, hub_api_dir):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    for mod_name in ("api_app", "hub_api_app_for_observability_test"):
        sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(
        "hub_api_app_for_observability_test",
        repo_root / "functions" / "hub_api" / "app.py",
    )
    assert spec and spec.loader
    hub_app = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = hub_app
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(hub_app)

    request = mock.Mock()
    user = mock.Mock(user_id="user-1", cognito_sub="sub-1", email="user@example.com")
    with mock.patch.object(hub_app, "_gui_get_user", return_value=user):
        response = hub_app.api_observability_failure_scenarios(request)

    body = json.loads(response.body.decode("utf-8"))
    names = {item["name"] for item in body["failure_scenarios"]}
    assert "openai-outage" in names
    assert "expired-consent" in names
