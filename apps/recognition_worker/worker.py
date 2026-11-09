#!/usr/bin/env python3
"""Supervised Marvain voice/face recognition worker.

The worker creates evidence-backed observations and proposed hypotheses.  It
never accepts a hypothesis, creates a biometric projection, or asserts
presence; those operations require an authenticated review in the Hub.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

import boto3
import requests
from agent_hub.recognition_service import RecognitionWorkerHeartbeat

logger = logging.getLogger("marvain.recognition_worker")


class RecognitionWorkerError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecognitionWorkerConfig:
    hub_api_base: str
    hub_device_token: str
    queue_url: str
    artifact_bucket: str
    worker_id: str
    worker_version: str
    host_id: str
    model_manifest_path: Path
    health_path: Path
    poll_wait_seconds: int
    max_messages: int
    visibility_timeout: int
    heartbeat_seconds: int
    error_backoff_seconds: int
    log_level: str


@dataclass(frozen=True)
class ModelSpec:
    modality: str
    model_id: str
    version: str
    engine: str
    asset_path: Path
    sha256: str
    analysis_name: str | None


@dataclass(frozen=True)
class ModelManifest:
    voice: ModelSpec
    face: ModelSpec


@dataclass(frozen=True)
class ProcessingReceipt:
    event_id: str
    observation_id: str
    hypothesis_id: str
    hypothesis_kind: str


@dataclass
class WorkerState:
    started_at: datetime
    processed_messages: int = 0
    failed_messages: int = 0
    last_event_id: str | None = None
    last_error: str | None = None


_REQUIRED_ENV = (
    "HUB_API_BASE",
    "HUB_DEVICE_TOKEN",
    "RECOGNITION_QUEUE_URL",
    "ARTIFACT_BUCKET",
    "RECOGNITION_WORKER_ID",
    "RECOGNITION_WORKER_VERSION",
    "RECOGNITION_HOST_ID",
    "RECOGNITION_MODEL_MANIFEST_PATH",
    "RECOGNITION_HEALTH_PATH",
    "RECOGNITION_POLL_WAIT_SECONDS",
    "RECOGNITION_MAX_MESSAGES",
    "RECOGNITION_VISIBILITY_TIMEOUT",
    "RECOGNITION_HEARTBEAT_SECONDS",
    "RECOGNITION_ERROR_BACKOFF_SECONDS",
    "LOG_LEVEL",
)


def _required_text(value: Any, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise RecognitionWorkerError(f"{field} is required")
    return normalized


def _positive_int(value: str, field: str, *, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RecognitionWorkerError(f"{field} must be an integer") from exc
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        bound = f" between 1 and {maximum}" if maximum else " positive"
        raise RecognitionWorkerError(f"{field} must be{bound}")
    return parsed


def load_config(env: Mapping[str, str] | None = None) -> RecognitionWorkerConfig:
    values = os.environ if env is None else env
    missing = [name for name in _REQUIRED_ENV if not str(values.get(name) or "").strip()]
    if missing:
        raise RecognitionWorkerError(f"Missing required env vars: {', '.join(missing)}")
    hub_api_base = _required_text(values["HUB_API_BASE"], "HUB_API_BASE").rstrip("/")
    if not hub_api_base.startswith("https://"):
        raise RecognitionWorkerError("HUB_API_BASE must use https")
    return RecognitionWorkerConfig(
        hub_api_base=hub_api_base,
        hub_device_token=_required_text(values["HUB_DEVICE_TOKEN"], "HUB_DEVICE_TOKEN"),
        queue_url=_required_text(values["RECOGNITION_QUEUE_URL"], "RECOGNITION_QUEUE_URL"),
        artifact_bucket=_required_text(values["ARTIFACT_BUCKET"], "ARTIFACT_BUCKET"),
        worker_id=_required_text(values["RECOGNITION_WORKER_ID"], "RECOGNITION_WORKER_ID"),
        worker_version=_required_text(values["RECOGNITION_WORKER_VERSION"], "RECOGNITION_WORKER_VERSION"),
        host_id=_required_text(values["RECOGNITION_HOST_ID"], "RECOGNITION_HOST_ID"),
        model_manifest_path=Path(values["RECOGNITION_MODEL_MANIFEST_PATH"]).expanduser().resolve(),
        health_path=Path(values["RECOGNITION_HEALTH_PATH"]).expanduser().resolve(),
        poll_wait_seconds=_positive_int(
            values["RECOGNITION_POLL_WAIT_SECONDS"], "RECOGNITION_POLL_WAIT_SECONDS", maximum=20
        ),
        max_messages=_positive_int(values["RECOGNITION_MAX_MESSAGES"], "RECOGNITION_MAX_MESSAGES", maximum=10),
        visibility_timeout=_positive_int(values["RECOGNITION_VISIBILITY_TIMEOUT"], "RECOGNITION_VISIBILITY_TIMEOUT"),
        heartbeat_seconds=_positive_int(values["RECOGNITION_HEARTBEAT_SECONDS"], "RECOGNITION_HEARTBEAT_SECONDS"),
        error_backoff_seconds=_positive_int(
            values["RECOGNITION_ERROR_BACKOFF_SECONDS"], "RECOGNITION_ERROR_BACKOFF_SECONDS"
        ),
        log_level=_required_text(values["LOG_LEVEL"], "LOG_LEVEL").upper(),
    )


def _sha256_path(path: Path) -> str:
    if not path.exists():
        raise RecognitionWorkerError(f"model asset does not exist: {path}")
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    files = sorted(item for item in path.rglob("*") if item.is_file())
    if not files:
        raise RecognitionWorkerError(f"model asset directory is empty: {path}")
    for file_path in files:
        digest.update(file_path.relative_to(path).as_posix().encode("utf-8"))
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _load_model_spec(payload: Any, *, modality: str) -> ModelSpec:
    if not isinstance(payload, dict):
        raise RecognitionWorkerError(f"model manifest {modality} entry must be an object")
    model_id = _required_text(payload.get("id"), f"models.{modality}.id")
    version = _required_text(payload.get("version"), f"models.{modality}.version")
    engine = _required_text(payload.get("engine"), f"models.{modality}.engine")
    supported_engine = "resemblyzer" if modality == "voice" else "insightface"
    if engine != supported_engine:
        raise RecognitionWorkerError(f"models.{modality}.engine must be {supported_engine}")
    asset_path = Path(_required_text(payload.get("asset_path"), f"models.{modality}.asset_path")).expanduser().resolve()
    expected_sha = _required_text(payload.get("sha256"), f"models.{modality}.sha256").lower()
    if len(expected_sha) != 64 or any(char not in "0123456789abcdef" for char in expected_sha):
        raise RecognitionWorkerError(f"models.{modality}.sha256 must be a lowercase SHA-256 digest")
    actual_sha = _sha256_path(asset_path)
    if actual_sha != expected_sha:
        raise RecognitionWorkerError(
            f"model asset checksum mismatch for {modality}: expected={expected_sha} actual={actual_sha}"
        )
    analysis_name = str(payload.get("analysis_name") or "").strip() or None
    if modality == "face" and not analysis_name:
        raise RecognitionWorkerError("models.face.analysis_name is required")
    if modality == "voice" and analysis_name:
        raise RecognitionWorkerError("models.voice.analysis_name is not supported")
    return ModelSpec(
        modality=modality,
        model_id=model_id,
        version=version,
        engine=engine,
        asset_path=asset_path,
        sha256=expected_sha,
        analysis_name=analysis_name,
    )


def load_model_manifest(path: Path) -> ModelManifest:
    if not path.is_file():
        raise RecognitionWorkerError(f"model manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecognitionWorkerError(f"model manifest is invalid: {path}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "marvain.recognition.models.v1":
        raise RecognitionWorkerError("model manifest schema must be marvain.recognition.models.v1")
    return ModelManifest(
        voice=_load_model_spec(payload.get("voice"), modality="voice"),
        face=_load_model_spec(payload.get("face"), modality="face"),
    )


def _try_voice_embedding(audio_bytes: bytes, model: ModelSpec) -> list[float] | None:
    try:
        import numpy as np  # type: ignore
        import soundfile as sf  # type: ignore
        from resemblyzer import VoiceEncoder, preprocess_wav  # type: ignore
    except Exception:
        return None
    try:
        data, sample_rate = sf.read(io.BytesIO(audio_bytes))
        wav = preprocess_wav(data, source_sr=sample_rate)
        encoder = VoiceEncoder(weights_fpath=model.asset_path)
        embedding = encoder.embed_utterance(wav)
        if isinstance(embedding, np.ndarray):
            return embedding.astype("float32").tolist()
    except Exception as exc:
        logger.error("Voice embedding failed: %s", exc)
    return None


def _try_face_embedding(image_bytes: bytes, model: ModelSpec) -> list[float] | None:
    try:
        import insightface  # type: ignore
        import numpy as np  # type: ignore
        from PIL import Image  # type: ignore
    except Exception:
        return None
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        array = np.asarray(image)[:, :, ::-1]
        analyzer = insightface.app.FaceAnalysis(
            name=model.analysis_name,
            root=str(model.asset_path),
            providers=["CPUExecutionProvider"],
        )
        analyzer.prepare(ctx_id=0, det_size=(640, 640))
        faces = analyzer.get(array)
        if not faces:
            return None
        embedding = faces[0].embedding
        if isinstance(embedding, np.ndarray):
            return embedding.astype("float32").tolist()
    except Exception as exc:
        logger.error("Face embedding failed: %s", exc)
    return None


def _embedding_or_raise(*, modality: str, data: bytes, models: ModelManifest) -> tuple[list[float], ModelSpec]:
    if modality == "voice":
        model = models.voice
        embedding = _try_voice_embedding(data, model)
    elif modality == "face":
        model = models.face
        embedding = _try_face_embedding(data, model)
    else:
        raise RecognitionWorkerError(f"unsupported modality: {modality}")
    if embedding is None:
        raise RecognitionWorkerError(
            f"recognizer_unavailable:{modality}. Verify the pinned dependency and model asset before starting the worker."
        )
    if not embedding:
        raise RecognitionWorkerError(f"recognizer_empty_embedding:{modality}")
    return embedding, model


def _hub_post(
    config: RecognitionWorkerConfig, path: str, payload: dict[str, Any], timeout_s: int = 15
) -> dict[str, Any]:
    response = requests.post(
        f"{config.hub_api_base}{path}",
        headers={"Authorization": f"Bearer {config.hub_device_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout_s,
    )
    if not response.ok:
        raise RecognitionWorkerError(
            f"Hub POST {path} failed: status={response.status_code} body={response.text[:300]}"
        )
    try:
        result = response.json()
    except ValueError as exc:
        raise RecognitionWorkerError(f"Hub POST {path} returned non-JSON success") from exc
    if not isinstance(result, dict):
        raise RecognitionWorkerError(f"Hub POST {path} returned an invalid JSON payload")
    return result


def _artifact_ref(payload: dict[str, Any], config: RecognitionWorkerConfig) -> tuple[str, str, str]:
    bucket = _required_text(payload.get("artifact_bucket"), "payload.artifact_bucket")
    key = _required_text(payload.get("artifact_key"), "payload.artifact_key")
    checksum = _required_text(payload.get("artifact_sha256"), "payload.artifact_sha256").lower()
    if bucket != config.artifact_bucket:
        raise RecognitionWorkerError("artifact bucket does not match configured ARTIFACT_BUCKET")
    if len(checksum) != 64 or any(char not in "0123456789abcdef" for char in checksum):
        raise RecognitionWorkerError("payload.artifact_sha256 must be a lowercase SHA-256 digest")
    return bucket, key, checksum


def _required_response_id(response: dict[str, Any], field: str) -> str:
    return _required_text(response.get(field), f"Hub response {field}")


def process_message(
    msg_body: dict[str, Any],
    *,
    s3: Any,
    config: RecognitionWorkerConfig,
    models: ModelManifest,
    post: Callable[[RecognitionWorkerConfig, str, dict[str, Any]], dict[str, Any]] = _hub_post,
) -> ProcessingReceipt:
    event_type = _required_text(msg_body.get("type"), "type")
    if event_type not in {"voice.sample", "face.snapshot"}:
        raise RecognitionWorkerError(f"unsupported recognition event type: {event_type}")
    event_id = _required_text(msg_body.get("event_id"), "event_id")
    agent_id = _required_text(msg_body.get("agent_id"), "agent_id")
    device_id = _required_text(msg_body.get("device_id"), "device_id")
    payload = msg_body.get("payload")
    if not isinstance(payload, dict):
        raise RecognitionWorkerError("payload must be an object")
    bucket, key, expected_checksum = _artifact_ref(payload, config)
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj["Body"].read()

    modality = "voice" if event_type == "voice.sample" else "face"
    embedding, model = _embedding_or_raise(modality=modality, data=data, models=models)
    observation_response = post(
        config,
        "/v1/recognition/observations",
        {
            "idempotency_key": f"recognition-observation:{event_id}",
            "source_event_id": event_id,
            "agent_id": agent_id,
            "space_id": str(msg_body.get("space_id") or "").strip() or None,
            "location_id": str(msg_body.get("location_id") or "").strip() or None,
            "session_id": str(msg_body.get("session_id") or "").strip() or None,
            "device_id": device_id,
            "artifact": {
                "bucket": bucket,
                "object_key": key,
                "uri": f"s3://{bucket}/{key}",
                "media_type": _required_text(
                    payload.get("content_type") or obj.get("ContentType"), "artifact content_type"
                ),
                "sha256": expected_checksum,
            },
            "modality": modality,
            "model_id": model.model_id,
            "model_version": model.version,
            "embedding": embedding,
        },
    )
    observation_id = _required_response_id(observation_response, "observation_id")

    enroll_person_id = str(payload.get("enroll_person_id") or "").strip() or None
    if enroll_person_id:
        hypothesis_kind = "candidate"
        hypothesis_payload = {
            "kind": hypothesis_kind,
            "candidate_person_id": enroll_person_id,
            "confidence": 1.0,
            "distance": 0.0,
            "rationale": "consented enrollment candidate requires authenticated review",
            "requested_projection": True,
            "idempotency_key": f"recognition-hypothesis:{event_id}",
        }
    else:
        identify = post(config, f"/v1/identify/{modality}", {"agent_id": agent_id, "embedding": embedding, "k": 1})
        best = identify.get("best") if isinstance(identify.get("best"), dict) else None
        if bool(identify.get("matched")) and best and str(best.get("person_id") or "").strip():
            hypothesis_kind = "candidate"
            hypothesis_payload = {
                "kind": hypothesis_kind,
                "candidate_person_id": _required_text(best.get("person_id"), "identify.best.person_id"),
                "confidence": float(best.get("confidence") or 0.0),
                "distance": float(best.get("distance") or 0.0),
                "rationale": "candidate selected by configured recognition model and server threshold",
                "requested_projection": False,
                "idempotency_key": f"recognition-hypothesis:{event_id}",
            }
        else:
            hypothesis_kind = "no_match"
            candidate_confidence = float(best.get("confidence") or 0.0) if best else 0.0
            hypothesis_payload = {
                "kind": hypothesis_kind,
                "candidate_person_id": None,
                "confidence": max(0.0, min(1.0, 1.0 - candidate_confidence)),
                "distance": None,
                "rationale": "no candidate satisfied the configured server threshold",
                "requested_projection": False,
                "idempotency_key": f"recognition-hypothesis:{event_id}",
            }
    hypothesis_response = post(
        config,
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        hypothesis_payload,
    )
    hypothesis_id = _required_response_id(hypothesis_response, "hypothesis_id")
    if str(hypothesis_response.get("decision") or "") != "proposed":
        raise RecognitionWorkerError("Hub must persist worker hypotheses with decision=proposed")
    return ProcessingReceipt(
        event_id=event_id,
        observation_id=observation_id,
        hypothesis_id=hypothesis_id,
        hypothesis_kind=hypothesis_kind,
    )


def _heartbeat(
    config: RecognitionWorkerConfig, models: ModelManifest, state: WorkerState, *, status: str
) -> dict[str, object]:
    if status not in {"ready", "degraded", "stopped"}:
        raise RecognitionWorkerError("heartbeat status must be ready, degraded, or stopped")
    return RecognitionWorkerHeartbeat(
        worker_id=config.worker_id,
        worker_version=config.worker_version,
        host_id=config.host_id,
        voice_model_id=models.voice.model_id,
        voice_model_version=models.voice.version,
        face_model_id=models.face.model_id,
        face_model_version=models.face.version,
        state=status,
        started_at=state.started_at,
        observed_at=datetime.now(timezone.utc),
        processed_messages=state.processed_messages,
        failed_messages=state.failed_messages,
        last_event_id=state.last_event_id,
        last_error=state.last_error,
    ).as_payload()


def _write_health(path: Path, payload: dict[str, object]) -> None:
    if not path.parent.is_dir():
        raise RecognitionWorkerError(f"health directory does not exist: {path.parent}")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def publish_heartbeat(
    config: RecognitionWorkerConfig,
    models: ModelManifest,
    state: WorkerState,
    *,
    status: str,
    post: Callable[[RecognitionWorkerConfig, str, dict[str, Any]], dict[str, Any]] = _hub_post,
) -> dict[str, object]:
    payload = _heartbeat(config, models, state, status=status)
    _write_health(config.health_path, payload)
    response = post(config, f"/v1/recognition/workers/{config.worker_id}/heartbeat", dict(payload))
    if response.get("ok") is not True:
        raise RecognitionWorkerError("Hub did not acknowledge recognition worker heartbeat")
    return payload


_running = True


def _handle_signal(sig: int, frame: Any) -> None:  # noqa: ARG001
    global _running
    _running = False
    logger.info("Stopping recognition worker (signal=%s)", sig)


def main() -> int:
    config = load_config()
    logging.basicConfig(level=config.log_level)
    models = load_model_manifest(config.model_manifest_path)
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    sqs = boto3.client("sqs")
    s3 = boto3.client("s3")
    state = WorkerState(started_at=datetime.now(timezone.utc))
    publish_heartbeat(config, models, state, status="ready")
    last_heartbeat = time.monotonic()

    while _running:
        try:
            response = sqs.receive_message(
                QueueUrl=config.queue_url,
                MaxNumberOfMessages=config.max_messages,
                WaitTimeSeconds=config.poll_wait_seconds,
                VisibilityTimeout=config.visibility_timeout,
            )
            for message in response.get("Messages") or []:
                receipt_handle = message.get("ReceiptHandle")
                try:
                    body = json.loads(_required_text(message.get("Body"), "SQS message body"))
                    if not isinstance(body, dict):
                        raise RecognitionWorkerError("SQS message body must be a JSON object")
                    receipt = process_message(body, s3=s3, config=config, models=models)
                    state.processed_messages += 1
                    state.last_event_id = receipt.event_id
                    state.last_error = None
                    publish_heartbeat(config, models, state, status="ready")
                    if not receipt_handle:
                        raise RecognitionWorkerError("SQS message is missing ReceiptHandle")
                    sqs.delete_message(QueueUrl=config.queue_url, ReceiptHandle=receipt_handle)
                except Exception as exc:
                    state.failed_messages += 1
                    state.last_error = str(exc)
                    logger.exception("Failed to process recognition message: %s", exc)
                    try:
                        publish_heartbeat(config, models, state, status="degraded")
                    except Exception:
                        logger.exception("Failed to publish degraded recognition heartbeat")
            if time.monotonic() - last_heartbeat >= config.heartbeat_seconds:
                publish_heartbeat(config, models, state, status="ready" if not state.last_error else "degraded")
                last_heartbeat = time.monotonic()
        except Exception as exc:
            state.last_error = str(exc)
            logger.exception("Recognition receive loop failed: %s", exc)
            try:
                publish_heartbeat(config, models, state, status="degraded")
            except Exception:
                logger.exception("Failed to publish receive-loop heartbeat")
            time.sleep(config.error_backoff_seconds)

    publish_heartbeat(config, models, state, status="stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
