from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest


def _load_worker():
    root = Path(__file__).resolve().parents[1]
    worker_py = root / "apps" / "recognition_worker" / "worker.py"
    spec = importlib.util.spec_from_file_location("recognition_worker_contract", worker_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _config(mod, tmp_path: Path):
    return mod.RecognitionWorkerConfig(
        hub_api_base="https://hub.example.test",
        hub_device_token="device-token",
        queue_url="https://sqs.example.test/queue",
        artifact_bucket="recognition-bucket",
        worker_id="recognition-worker-1",
        worker_version="1.2.3",
        host_id="recognition-host-1",
        model_manifest_path=tmp_path / "models.json",
        health_path=tmp_path / "health.json",
        poll_wait_seconds=10,
        max_messages=5,
        visibility_timeout=60,
        heartbeat_seconds=30,
        error_backoff_seconds=2,
        log_level="INFO",
    )


def _models(mod, tmp_path: Path):
    return mod.ModelManifest(
        voice=mod.ModelSpec("voice", "voice-model", "1.0.0", "resemblyzer", tmp_path / "voice.pt", "a" * 64, None),
        face=mod.ModelSpec("face", "face-model", "2.0.0", "insightface", tmp_path / "face", "b" * 64, "buffalo_l"),
    )


def _event(data: bytes, *, event_type: str = "voice.sample", enroll_person_id: str | None = None):
    payload = {
        "artifact_bucket": "recognition-bucket",
        "artifact_key": "recognition/sample.bin",
        "artifact_sha256": hashlib.sha256(data).hexdigest(),
        "content_type": "audio/wav" if event_type == "voice.sample" else "image/jpeg",
    }
    if enroll_person_id:
        payload["enroll_person_id"] = enroll_person_id
    return {
        "type": event_type,
        "event_id": "event-1",
        "agent_id": "agent-1",
        "space_id": "space-1",
        "location_id": "location-1",
        "session_id": "session-1",
        "device_id": "device-1",
        "payload": payload,
    }


class FakeS3:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.get_calls = []

    def get_object(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Body": io.BytesIO(self.data), "ContentType": "audio/wav"}


def test_recognition_worker_requires_all_explicit_runtime_config() -> None:
    mod = _load_worker()

    with pytest.raises(
        mod.RecognitionWorkerError, match="HUB_API_BASE.*HUB_DEVICE_TOKEN.*RECOGNITION_MODEL_MANIFEST_PATH"
    ):
        mod.load_config({})


def test_recognition_worker_rejects_non_tls_hub() -> None:
    mod = _load_worker()
    env = {name: "value" for name in mod._REQUIRED_ENV}
    env.update(
        {
            "HUB_API_BASE": "http://hub.example.test",
            "RECOGNITION_POLL_WAIT_SECONDS": "10",
            "RECOGNITION_MAX_MESSAGES": "5",
            "RECOGNITION_VISIBILITY_TIMEOUT": "60",
            "RECOGNITION_HEARTBEAT_SECONDS": "30",
            "RECOGNITION_ERROR_BACKOFF_SECONDS": "2",
        }
    )

    with pytest.raises(mod.RecognitionWorkerError, match="must use https"):
        mod.load_config(env)


def test_model_manifest_requires_pinned_asset_checksums(tmp_path: Path) -> None:
    mod = _load_worker()
    voice_asset = tmp_path / "voice.pt"
    voice_asset.write_bytes(b"voice-model")
    face_root = tmp_path / "face"
    face_root.mkdir()
    (face_root / "model.onnx").write_bytes(b"face-model")
    manifest_path = tmp_path / "models.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "marvain.recognition.models.v1",
                "voice": {
                    "id": "voice-model",
                    "version": "1.0.0",
                    "engine": "resemblyzer",
                    "asset_path": str(voice_asset),
                    "sha256": mod._sha256_path(voice_asset),
                },
                "face": {
                    "id": "face-model",
                    "version": "2.0.0",
                    "engine": "insightface",
                    "asset_path": str(face_root),
                    "sha256": mod._sha256_path(face_root),
                    "analysis_name": "buffalo_l",
                },
            }
        ),
        encoding="utf-8",
    )

    models = mod.load_model_manifest(manifest_path)

    assert models.voice.model_id == "voice-model"
    assert models.face.analysis_name == "buffalo_l"

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["voice"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(mod.RecognitionWorkerError, match="checksum mismatch for voice"):
        mod.load_model_manifest(manifest_path)


def test_recognition_worker_requires_real_voice_recognizer(tmp_path: Path) -> None:
    mod = _load_worker()
    models = _models(mod, tmp_path)
    mod._try_voice_embedding = mock.Mock(return_value=None)

    with pytest.raises(mod.RecognitionWorkerError, match="recognizer_unavailable:voice"):
        mod._embedding_or_raise(modality="voice", data=b"audio", models=models)


def test_recognition_worker_requires_real_face_recognizer(tmp_path: Path) -> None:
    mod = _load_worker()
    models = _models(mod, tmp_path)
    mod._try_face_embedding = mock.Mock(return_value=None)

    with pytest.raises(mod.RecognitionWorkerError, match="recognizer_unavailable:face"):
        mod._embedding_or_raise(modality="face", data=b"image", models=models)


def test_recognition_worker_persists_candidate_without_projection_or_presence(tmp_path: Path) -> None:
    mod = _load_worker()
    config = _config(mod, tmp_path)
    models = _models(mod, tmp_path)
    data = b"voice sample"
    s3 = FakeS3(data)
    mod._embedding_or_raise = mock.Mock(return_value=([0.1, 0.2], models.voice))
    calls: list[tuple[str, dict]] = []

    def post(_config, path, payload):
        calls.append((path, payload))
        if path == "/v1/recognition/observations":
            return {"observation_id": "observation-1"}
        if path == "/v1/identify/voice":
            return {
                "matched": True,
                "best": {"person_id": "person-1", "confidence": 0.94, "distance": 0.06},
            }
        return {"hypothesis_id": "hypothesis-1", "decision": "proposed"}

    receipt = mod.process_message(_event(data), s3=s3, config=config, models=models, post=post)

    assert receipt.hypothesis_kind == "candidate"
    assert [path for path, _payload in calls] == [
        "/v1/recognition/observations",
        "/v1/identify/voice",
        "/v1/recognition/observations/observation-1/hypotheses",
    ]
    assert calls[-1][1]["candidate_person_id"] == "person-1"
    assert calls[0][1]["idempotency_key"] == "recognition-observation:event-1"
    assert calls[-1][1]["idempotency_key"] == "recognition-hypothesis:event-1"
    assert not any("presence" in path or "voiceprints" in path for path, _payload in calls)
    assert not hasattr(s3, "delete_object")


def test_recognition_worker_persists_unknown_no_match(tmp_path: Path) -> None:
    mod = _load_worker()
    config = _config(mod, tmp_path)
    models = _models(mod, tmp_path)
    data = b"unknown face"
    s3 = FakeS3(data)
    mod._embedding_or_raise = mock.Mock(return_value=([0.1, 0.2], models.face))
    calls: list[tuple[str, dict]] = []

    def post(_config, path, payload):
        calls.append((path, payload))
        if path == "/v1/recognition/observations":
            return {"observation_id": "observation-2"}
        if path == "/v1/identify/face":
            return {"matched": False, "best": None}
        return {"hypothesis_id": "hypothesis-2", "decision": "proposed"}

    receipt = mod.process_message(
        _event(data, event_type="face.snapshot"),
        s3=s3,
        config=config,
        models=models,
        post=post,
    )

    assert receipt.hypothesis_kind == "no_match"
    assert calls[-1][1]["kind"] == "no_match"
    assert calls[-1][1]["candidate_person_id"] is None


def test_enrollment_requires_review_instead_of_direct_projection(tmp_path: Path) -> None:
    mod = _load_worker()
    config = _config(mod, tmp_path)
    models = _models(mod, tmp_path)
    data = b"enrollment voice"
    mod._embedding_or_raise = mock.Mock(return_value=([0.1, 0.2], models.voice))
    calls: list[tuple[str, dict]] = []

    def post(_config, path, payload):
        calls.append((path, payload))
        if path == "/v1/recognition/observations":
            return {"observation_id": "observation-3"}
        return {"hypothesis_id": "hypothesis-3", "decision": "proposed"}

    mod.process_message(
        _event(data, enroll_person_id="person-1"),
        s3=FakeS3(data),
        config=config,
        models=models,
        post=post,
    )

    assert [path for path, _payload in calls] == [
        "/v1/recognition/observations",
        "/v1/recognition/observations/observation-3/hypotheses",
    ]
    assert calls[-1][1]["requested_projection"] is True
    assert calls[-1][1]["candidate_person_id"] == "person-1"


def test_missing_artifact_provenance_is_retryable_failure(tmp_path: Path) -> None:
    mod = _load_worker()
    config = _config(mod, tmp_path)
    models = _models(mod, tmp_path)
    event = _event(b"sample")
    del event["payload"]["artifact_sha256"]

    with pytest.raises(mod.RecognitionWorkerError, match="payload.artifact_sha256 is required"):
        mod.process_message(event, s3=FakeS3(b"sample"), config=config, models=models)


def test_heartbeat_exposes_version_models_and_measured_state(tmp_path: Path) -> None:
    mod = _load_worker()
    config = _config(mod, tmp_path)
    models = _models(mod, tmp_path)
    state = mod.WorkerState(
        started_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
        processed_messages=7,
        failed_messages=2,
        last_event_id="event-7",
        last_error="model timeout",
    )

    payload = mod.publish_heartbeat(
        config,
        models,
        state,
        status="degraded",
        post=lambda _config, _path, _payload: {"ok": True},
    )

    assert payload["evidence_kind"] == "recognition_worker_heartbeat"
    assert payload["worker_version"] == "1.2.3"
    assert payload["models"]["voice"] == {"id": "voice-model", "version": "1.0.0"}
    assert payload["processed_messages"] == 7
    assert json.loads(config.health_path.read_text(encoding="utf-8"))["failed_messages"] == 2
