from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import UUID

from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES
from cli_core_yo.conformance import assert_exit_code, invoke

from marvain_cli import cli
from marvain_cli.smoke import LocalInMemorySmokeRuntime, LocalSmokeScenario, run_local_smoke

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
    assert report_a["recall_result"]["source_evidence"]["event_id"] == report_a["transcript_event_id"]
    assert report_a["recall_result"]["source_evidence"]["event_type"] == "transcript_chunk"
    assert report_a["recall_result"]["source_excerpt"]
    assert report_a["recall_result"]["device_id"]
    assert report_a["recall_result"]["space_id"]
    assert report_a["recall_result"]["session_id"] == report_a["session_id"]
    assert report_a["recall_result"]["person_id"]
    assert report_a["recall_result"]["consent_filters"]["applied"] is True
    assert report_a["recall_result"]["consent_filters"]["space_id"] == report_a["recall_result"]["space_id"]
    assert report_a["recall_result"]["consent_filters"]["person_id"] == report_a["recall_result"]["person_id"]
    assert report_a["recall_result"]["ranking_features"]["embedding_distance"] == 0.0
    assert report_a["recall_result"]["ranking_features"]["keyword_match"]
    assert report_a["device_result"]["ok"] is True
    assert report_a["device_result"]["status"] == "completed"
    assert report_a["device_result"]["action_id"] == report_a["action_id"]
    assert report_a["completion_score"] == 1.0


def test_local_smoke_recall_proof_is_complete_for_every_memory_kind() -> None:
    scenario = LocalSmokeScenario(seed="all-memory-kinds")
    runtime = LocalInMemorySmokeRuntime()
    session_id = runtime.start_session(scenario)
    transcript_event_id = runtime.record_transcript(session_id, scenario)
    runtime.commit_memory(transcript_event_id=transcript_event_id, session_id=session_id, scenario=scenario)

    memory_ids_by_kind = {str(row["tier"]): memory_id for memory_id, row in runtime.memories.items()}
    assert set(memory_ids_by_kind) == set(MEMORY_KIND_VALUES)
    for kind in MEMORY_KIND_VALUES:
        proof = runtime.recall_memory(memory_id=memory_ids_by_kind[kind], query=scenario.recall_query)
        assert proof["matched"] is True
        assert proof["source_event_id"] == transcript_event_id
        assert proof["source_evidence"] == {
            "event_id": transcript_event_id,
            "event_type": "transcript_chunk",
            "excerpt": proof["source_excerpt"],
            "device_id": proof["device_id"],
            "space_id": proof["space_id"],
            "session_id": proof["session_id"],
            "person_id": proof["person_id"],
        }
        assert proof["ranking_features"]["embedding_distance"] == 0.0
        assert proof["ranking_features"]["keyword_match"]
        assert proof["device_id"] == scenario.device_id
        assert proof["space_id"] == scenario.space_id
        assert proof["session_id"] == session_id
        assert proof["person_id"] == scenario.person_id
        assert proof["consent_filters"]["applied"] is True
        assert proof["consent_filters"]["agent_id"] == scenario.agent_id
        assert proof["consent_filters"]["space_id"] == scenario.space_id
        assert proof["consent_filters"]["person_id"] == scenario.person_id
        assert proof["consent_filters"]["committed_only"] is True


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


def test_cli_smoke_v1_dev_surfaces_deployed_blockers(monkeypatch) -> None:
    monkeypatch.setenv("MARVAIN_ACTIVE", "1")
    monkeypatch.setenv("CONDA_DEFAULT_ENV", "marvain")
    monkeypatch.setenv("CONDA_PREFIX", "/tmp/marvain")
    from marvain_cli import smoke as smoke_mod

    def fake_deployed_smoke(*, stack, include_two_device_proof):
        del stack, include_two_device_proof
        raise smoke_mod.SmokeBlockersError(
            blockers=[
                "worker_join: No deployed LiveKit worker room-join evidence is collected by this CLI slice.",
                "speech_transcript: No deployed speech transcript event from LiveKit audio is collected by this CLI slice.",
            ],
            report={"ok": False, "blockers": []},
        )

    monkeypatch.setattr(smoke_mod, "run_deployed_smoke", fake_deployed_smoke)
    app = cli.build_app()

    result = invoke(app, ["smoke", "v1-dev", "--stack", "marvain-greenfield-tapdb-dev"], prog_name="marvain")

    assert result.exit_code != 0
    assert "Deployed smoke blocked by missing required evidence" in result.output
    assert "worker_join: No deployed LiveKit worker room-join evidence" in result.output
    assert "speech_transcript: No deployed speech transcript event" in result.output


def test_deployed_smoke_rejects_placeholder_runtime_evidence() -> None:
    from marvain_cli import smoke as smoke_mod

    proofs = {key: {"ok": True} for key in smoke_mod.DEPLOYED_SMOKE_REQUIRED_RUNTIME_EVIDENCE}
    proofs["worker_join"] = "requires deployed worker logs"

    blockers = smoke_mod._runtime_evidence_blockers(proofs)

    assert blockers == [
        "worker_join: placeholder string is not accepted; required evidence: "
        "LiveKit room join evidence from the deployed worker"
    ]


def test_deployed_smoke_collects_required_runtime_evidence_after_rest_proofs(monkeypatch) -> None:
    from marvain_cli import smoke as smoke_mod

    ctx = SimpleNamespace(
        cfg={},
        env=SimpleNamespace(stack_name="marvain-greenfield-tapdb-dev", aws_region="us-east-1", aws_profile="daylily"),
    )
    outputs = {
        "HubRestApiBase": "https://hub.example.test",
        "HubWebSocketUrl": "wss://ws.example.test",
        "CognitoUserPoolId": "pool-1",
        "CognitoAppClientId": "client-1",
        "AdminApiKeySecretArn": "arn:admin",
        "LiveKitUrl": "wss://livekit.example.test",
        "LiveKitSecretArn": "arn:livekit",
        "OpenAISecretArn": "arn:openai",
    }
    calls: list[tuple[str, str, dict[str, object] | None, str | None, str | None]] = []

    monkeypatch.setattr(
        smoke_mod,
        "_require_env",
        lambda names: {
            "MARVAIN_SMOKE_COGNITO_USERNAME": "smoke@example.test",
            "MARVAIN_SMOKE_COGNITO_PASSWORD": "redacted",
        },
    )
    monkeypatch.setattr(smoke_mod, "_load_smoke_ctx", lambda *, stack: ctx)
    monkeypatch.setattr(smoke_mod, "_stack_outputs", lambda smoke_ctx: outputs)
    monkeypatch.setattr(smoke_mod, "_admin_key", lambda **kwargs: "admin-key")
    monkeypatch.setattr(smoke_mod, "_cognito_access_token", lambda **kwargs: "access-token")

    def fake_http_json(
        *,
        method: str,
        url: str,
        payload: dict[str, object] | None = None,
        bearer_token: str | None = None,
        admin_key: str | None = None,
        timeout_s: int = 30,
    ) -> dict[str, object]:
        del timeout_s
        path = url.removeprefix("https://hub.example.test")
        calls.append((method, path, payload, bearer_token, admin_key))
        if path == "/health":
            return {"ok": True}
        if path == "/v1/admin/bootstrap":
            assert admin_key == "admin-key"
            return {"agent_id": "agent-1", "space_id": "space-1", "device_token": "device-token-1"}
        if path == "/v1/admin/devices/register":
            assert admin_key == "admin-key"
            assert payload is not None
            name = str(payload["name"])
            return {"device_id": f"device-{name}", "device_token": f"token-{name}"}
        if path == "/v1/events":
            assert bearer_token is not None
            return {"event_id": f"event-{len([call for call in calls if call[1] == '/v1/events'])}"}
        if path.startswith("/v1/spaces/space-1/events"):
            assert bearer_token == "device-token-1"
            return {"events": [{"event_id": "event-1"}, {"event_id": "event-2"}, {"event_id": "event-3"}]}
        if path == "/v1/memories":
            assert bearer_token == "device-token-1"
            assert payload is not None
            return {"memory_id": f"memory-{payload['tier']}"}
        if path == "/v1/recall":
            assert bearer_token == "device-token-1"
            return {
                "memories": [
                    {
                        "memory_id": "memory-episodic",
                        "explanation": {
                            "source_evidence": {
                                "event_id": "event-1",
                                "event_type": "memory.evidence",
                                "excerpt": "Round 6 deployed smoke",
                                "device_id": "device-1",
                                "space_id": "space-1",
                                "session_id": "session-1",
                                "person_id": "person-1",
                            },
                            "source_excerpt": "Round 6 deployed smoke",
                            "source_event_id": "event-1",
                            "device_id": "device-1",
                            "space_id": "space-1",
                            "session_id": "session-1",
                            "person_id": "person-1",
                            "consent_filters": {"applied": True},
                            "ranking": {"embedding_distance": 0.1, "keyword_match": ["round6"], "rank": 1},
                            "tapdb_euid": "MVN-MEMORY-1",
                        },
                    }
                ]
            }
        if path.startswith("/api/dag/data?"):
            assert bearer_token == "access-token"
            return {"nodes": [{"id": "MVN-MEMORY-1"}], "edges": []}
        if path == "/api_health":
            return {"status": "ok", "service": "marvain"}
        if path.startswith("/endpoint_health?"):
            return {"status": "ok", "endpoints": []}
        raise AssertionError(f"unexpected HTTP call: {method} {path}")

    monkeypatch.setattr(smoke_mod, "_http_json", fake_http_json)

    report = smoke_mod.run_deployed_smoke(stack="marvain-greenfield-tapdb-dev", include_two_device_proof=True)

    assert report["ok"] is True
    assert report["mode"] == "v1-dev-deployed"
    assert str(report["run_id"]).startswith("round6-")
    assert report["proofs"]["chat_transcript_event_id"] == "event-1"
    assert report["proofs"]["speech_transcript"]["event_id"] == "event-2"
    assert report["proofs"]["recognition"]["event_id"] == "event-3"
    assert report["proofs"]["memory_ids_by_kind"] == {kind: f"memory-{kind}" for kind in MEMORY_KIND_VALUES}
    assert report["proofs"]["tapdb_graph_probe"] == {"nodes": [{"id": "MVN-MEMORY-1"}], "edges": []}
    assert report["proofs"]["two_device"]["routing_transport"] == "deployed-rest-device-token"
    for key in smoke_mod.DEPLOYED_SMOKE_REQUIRED_RUNTIME_EVIDENCE:
        assert isinstance(report["proofs"][key], dict)
        assert report["proofs"][key]["ok"] is True
    assert [call[1] for call in calls].count("/v1/admin/devices/register") == 2


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
