from __future__ import annotations

import json
from uuid import UUID

from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES
from cli_core_yo.conformance import assert_exit_code, invoke

from marvain_cli import cli
from marvain_cli.smoke import LocalSmokeScenario, run_local_smoke

REQUIRED_REPORT_KEYS = {
    "session_id",
    "transcript_event_id",
    "memory_id",
    "memory_ids_by_kind",
    "recall_result",
    "recognition_observation_id",
    "action_id",
    "device_result",
    "completion_score",
}
REQUIRED_CLI_KEYS = REQUIRED_REPORT_KEYS | {"mode"}


def test_local_smoke_report_is_deterministic_and_complete() -> None:
    report_a = run_local_smoke().as_dict()
    report_b = run_local_smoke().as_dict()

    assert report_a == report_b
    assert set(report_a) == REQUIRED_REPORT_KEYS
    UUID(report_a["session_id"])
    UUID(report_a["transcript_event_id"])
    UUID(report_a["memory_id"])
    assert set(report_a["memory_ids_by_kind"]) == set(MEMORY_KIND_VALUES)
    for memory_id in report_a["memory_ids_by_kind"].values():
        UUID(memory_id)
    UUID(report_a["recognition_observation_id"])
    UUID(report_a["action_id"])
    assert report_a["recall_result"]["matched"] is True
    assert report_a["recall_result"]["memory_id"] == report_a["memory_id"]
    assert report_a["recall_result"]["source_event_id"] == report_a["transcript_event_id"]
    assert report_a["recall_result"]["source_excerpt"]
    assert report_a["recall_result"]["device_id"]
    assert report_a["recall_result"]["space_id"]
    assert report_a["recall_result"]["session_id"] == report_a["session_id"]
    assert report_a["recall_result"]["person_id"]
    assert report_a["recall_result"]["consent_filters"]["applied"] is True
    assert report_a["recall_result"]["ranking_features"]["embedding_distance"] == 0.0
    assert report_a["recall_result"]["ranking_features"]["keyword_match"]
    assert report_a["device_result"]["ok"] is True
    assert report_a["device_result"]["status"] == "completed"
    assert report_a["device_result"]["action_id"] == report_a["action_id"]
    assert report_a["completion_score"] == 1.0


def test_local_smoke_accepts_mocked_runtime() -> None:
    class ScriptedRuntime:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def start_session(self, scenario: LocalSmokeScenario) -> str:
            self.calls.append(f"start:{scenario.seed}")
            return "session-1"

        def record_transcript(self, session_id: str, scenario: LocalSmokeScenario) -> str:
            self.calls.append(f"transcript:{session_id}:{scenario.seed}")
            return "event-1"

        def commit_memory(
            self, *, transcript_event_id: str, session_id: str, scenario: LocalSmokeScenario
        ) -> tuple[str, dict[str, object]]:
            self.calls.append(f"memory:{transcript_event_id}:{session_id}:{scenario.seed}")
            return "memory-1", {"matched": True, "memory_id": "memory-1"}

        def record_recognition(self, session_id: str, scenario: LocalSmokeScenario) -> str:
            self.calls.append(f"recognition:{session_id}:{scenario.seed}")
            return "recognition-1"

        def dispatch_action(self, *, session_id: str, transcript_event_id: str, scenario: LocalSmokeScenario) -> str:
            self.calls.append(f"action:{session_id}:{transcript_event_id}:{scenario.seed}")
            return "action-1"

        def record_device_result(self, action_id: str, scenario: LocalSmokeScenario) -> dict[str, object]:
            self.calls.append(f"device:{action_id}:{scenario.seed}")
            return {"ok": True, "status": "completed", "action_id": action_id}

    runtime = ScriptedRuntime()
    report = run_local_smoke(runtime=runtime, scenario=LocalSmokeScenario(seed="mocked")).as_dict()

    assert runtime.calls == [
        "start:mocked",
        "transcript:session-1:mocked",
        "memory:event-1:session-1:mocked",
        "recognition:session-1:mocked",
        "action:session-1:event-1:mocked",
        "device:action-1:mocked",
    ]
    assert report == {
        "session_id": "session-1",
        "transcript_event_id": "event-1",
        "memory_id": "memory-1",
        "memory_ids_by_kind": {kind: "" for kind in MEMORY_KIND_VALUES},
        "recall_result": {"matched": True, "memory_id": "memory-1"},
        "recognition_observation_id": "recognition-1",
        "action_id": "action-1",
        "device_result": {"ok": True, "status": "completed", "action_id": "action-1"},
        "completion_score": 1.0,
    }


def test_cli_smoke_reports_required_fields_as_json(monkeypatch) -> None:
    monkeypatch.setenv("MARVAIN_ACTIVE", "1")
    monkeypatch.setenv("CONDA_DEFAULT_ENV", "marvain")
    monkeypatch.setenv("CONDA_PREFIX", "/tmp/marvain")
    app = cli.build_app()

    result = invoke(app, ["--json", "smoke", "v1-local", "--seed", "cli-smoke-test"], prog_name="marvain")

    assert_exit_code(result, 0)
    data = json.loads(result.output)
    assert set(data) == REQUIRED_CLI_KEYS
    assert data["recall_result"]["memory_id"] == data["memory_id"]
    assert data["device_result"]["action_id"] == data["action_id"]
    assert data["completion_score"] == 1.0
    assert data["mode"] == "v1-local"


def test_cli_smoke_v1_dev_runs_deployed_smoke_runner(monkeypatch) -> None:
    monkeypatch.setenv("MARVAIN_ACTIVE", "1")
    monkeypatch.setenv("CONDA_DEFAULT_ENV", "marvain")
    monkeypatch.setenv("CONDA_PREFIX", "/tmp/marvain")
    from marvain_cli import smoke as smoke_mod

    def fake_deployed_smoke(*, stack, include_two_device_proof):
        assert stack == "marvain-greenfield-tapdb-dev"
        assert include_two_device_proof is True
        return {
            "mode": "v1-dev-deployed",
            "dev_stack": stack,
            "mutates_runtime": True,
            "run_id": "unit",
            "proofs": {"two_device": {"left_device_id": "left", "right_device_id": "right"}},
        }

    monkeypatch.setattr(smoke_mod, "run_deployed_smoke", fake_deployed_smoke)
    app = cli.build_app()

    result = invoke(
        app,
        [
            "--json",
            "smoke",
            "v1-dev",
            "--stack",
            "marvain-greenfield-tapdb-dev",
            "--include-two-device-proof",
        ],
        prog_name="marvain",
    )

    assert_exit_code(result, 0)
    data = json.loads(result.output)
    assert data["mode"] == "v1-dev-deployed"
    assert data["dev_stack"] == "marvain-greenfield-tapdb-dev"
    assert data["mutates_runtime"] is True
    assert data["proofs"]["two_device"]["left_device_id"] == "left"


def test_cli_smoke_v1_dev_fails_without_deployed_smoke_requirements(monkeypatch) -> None:
    monkeypatch.setenv("MARVAIN_ACTIVE", "1")
    monkeypatch.setenv("CONDA_DEFAULT_ENV", "marvain")
    monkeypatch.setenv("CONDA_PREFIX", "/tmp/marvain")
    monkeypatch.delenv("MARVAIN_SMOKE_COGNITO_USERNAME", raising=False)
    monkeypatch.delenv("MARVAIN_SMOKE_COGNITO_PASSWORD", raising=False)
    app = cli.build_app()

    result = invoke(app, ["smoke", "v1-dev", "--stack", "marvain-greenfield-tapdb-dev"], prog_name="marvain")

    assert result.exit_code != 0
    assert "Missing required deployed smoke environment variables" in result.output


def test_cli_smoke_gui_guide_reports_generated_artifact(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MARVAIN_ACTIVE", "1")
    monkeypatch.setenv("CONDA_DEFAULT_ENV", "marvain")
    monkeypatch.setenv("CONDA_PREFIX", "/tmp/marvain")
    from marvain_cli import smoke as smoke_mod

    def fake_gui_guide(*, base_url, output_dir, headless):
        assert base_url == "http://127.0.0.1:9999"
        assert output_dir == tmp_path
        assert headless is True
        return {
            "run_id": "unit",
            "report_path": str(tmp_path / "unit" / "GUI_SMOKE_REPORT.md"),
            "output_dir": str(tmp_path / "unit"),
            "pages": 18,
            "failures": [],
            "ok": True,
        }

    monkeypatch.setattr(smoke_mod, "run_gui_smoke_guide", fake_gui_guide)
    app = cli.build_app()

    result = invoke(
        app,
        ["--json", "smoke", "gui-guide", "--base-url", "http://127.0.0.1:9999", "--output", str(tmp_path)],
        prog_name="marvain",
    )

    assert_exit_code(result, 0)
    data = json.loads(result.output)
    assert data["run_id"] == "unit"
    assert data["pages"] == 18
    assert data["ok"] is True
