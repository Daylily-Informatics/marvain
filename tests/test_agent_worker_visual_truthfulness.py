from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_agent_worker_module():
    shared = REPO_ROOT / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    worker_py = REPO_ROOT / "apps" / "agent_worker" / "worker.py"
    os.environ.setdefault("AGENT_DISCONNECT_DELAY_SECONDS", "0")
    os.environ.setdefault("MARVAIN_AGENT_PERSONA_INSTRUCTIONS", "Test persona instructions.")
    spec = importlib.util.spec_from_file_location("agent_worker_for_visual_truthfulness_tests", worker_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_visual_guard_is_always_added_to_agent_instructions() -> None:
    worker = _load_agent_worker_module()
    captured: dict[str, str] = {}

    with mock.patch.object(
        worker.Agent, "__init__", lambda self, *, instructions: captured.setdefault("text", instructions)
    ):
        worker.ForgeAssistant(
            persona=worker.PersonaConfig(
                persona_id=None,
                name="Test",
                instructions="Base persona.",
                source="test",
            )
        )

    assert "Vision / Sensor Truthfulness" in captured["text"]
    assert "do not claim that you can see" in captured["text"]
    assert "Current Session Visual Observations" in captured["text"]


def test_context_block_omits_artifact_only_visual_events_without_observation_text() -> None:
    worker = _load_agent_worker_module()

    context = worker._build_context_block(
        [
            {
                "type": "face.snapshot",
                "session_id": "session-1",
                "payload": {
                    "artifact_bucket": "bucket",
                    "artifact_key": "recognition/frame.jpg",
                    "content_type": "image/jpeg",
                },
            }
        ],
        [],
        current_session_id="session-1",
    )

    assert "Current Session Visual Observations" not in context
    assert "frame.jpg" not in context


def test_worker_does_not_promote_artifact_only_visual_message_to_observation() -> None:
    worker_text = (REPO_ROOT / "apps" / "agent_worker" / "worker.py").read_text(encoding="utf-8")

    assert "visual.artifact_reference" in worker_text
    assert "artifact reference only; no visual observation text" in worker_text
    assert '"type": "visual_observation_ack"' in worker_text
    assert '"ok": False' in worker_text
    assert '"error": "camera_enabled_but_visual_analysis_unavailable"' in worker_text
    assert "A visual observation artifact was captured, but no description was available." not in worker_text


def test_visual_artifact_description_requires_openai_key() -> None:
    worker = _load_agent_worker_module()

    with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False):
        assert worker._describe_visual_artifact("s3://bucket/current-frame.jpg") is None


def test_openai_response_text_extractor_handles_output_content() -> None:
    worker = _load_agent_worker_module()

    text = worker._extract_openai_response_text(
        {
            "output": [
                {
                    "content": [
                        {"type": "output_text", "text": "A desk and monitor are visible."},
                        {"type": "refusal", "refusal": "ignored"},
                    ]
                }
            ]
        }
    )

    assert text == "A desk and monitor are visible."


def test_context_block_includes_current_session_visual_observation_text() -> None:
    worker = _load_agent_worker_module()

    context = worker._build_context_block(
        [
            {
                "type": "visual.observation",
                "session_id": "session-1",
                "payload": {
                    "description": "A user is standing by the kitchen counter.",
                    "artifact_key": "recognition/frame.jpg",
                },
            }
        ],
        [],
        current_session_id="session-1",
    )

    assert "## Current Session Visual Observations" in context
    assert "A user is standing by the kitchen counter." in context


def test_context_block_ignores_visual_observation_from_prior_session() -> None:
    worker = _load_agent_worker_module()

    context = worker._build_context_block(
        [
            {
                "type": "visual.observation",
                "session_id": "old-session",
                "payload": {"description": "A laptop screen shows a chart."},
            }
        ],
        [],
        current_session_id="session-1",
    )

    assert "Current Session Visual Observations" not in context
    assert "laptop screen" not in context
