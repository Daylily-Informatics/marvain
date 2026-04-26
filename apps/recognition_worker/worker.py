#!/usr/bin/env python3
"""Marvain Recognition Worker (home server).

Polls the RecognitionQueue (SQS) for `voice.sample` and `face.snapshot` events,
downloads referenced artifacts from S3, computes embeddings, and writes results
back to the Hub:
- enrollment -> /v1/people/{person_id}/voiceprints|faceprints
- identification -> /v1/identify/voice|face, then /v1/spaces/{space_id}/presence and `person.observed` events

This worker is designed to run outside AWS compute (your home server) while
still using the deployed Hub stack for persistence and realtime updates.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import os
import signal
import time
from typing import Any

import boto3
import requests

logger = logging.getLogger("marvain.recognition_worker")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))


HUB_API_BASE = str(os.getenv("HUB_API_BASE", "")).rstrip("/")
HUB_DEVICE_TOKEN = str(os.getenv("HUB_DEVICE_TOKEN", "")).strip()

RECOGNITION_QUEUE_URL = str(os.getenv("RECOGNITION_QUEUE_URL", "")).strip()
ARTIFACT_BUCKET = str(os.getenv("ARTIFACT_BUCKET", "")).strip()

POLL_WAIT_SECONDS = int(os.getenv("RECOGNITION_POLL_WAIT_SECONDS", "20"))
MAX_MESSAGES = int(os.getenv("RECOGNITION_MAX_MESSAGES", "5"))
VISIBILITY_TIMEOUT = int(os.getenv("RECOGNITION_VISIBILITY_TIMEOUT", "60"))

DELETE_ARTIFACTS = str(os.getenv("RECOGNITION_DELETE_ARTIFACTS", "true")).strip().lower() in ("true", "1", "yes")
ALLOW_DUMMY_EMBEDDINGS = str(os.getenv("RECOGNITION_ALLOW_DUMMY_EMBEDDINGS", "")).strip().lower() in (
    "true",
    "1",
    "yes",
)


def _require_env() -> None:
    missing: list[str] = []
    if not RECOGNITION_QUEUE_URL:
        missing.append("RECOGNITION_QUEUE_URL")
    if not HUB_API_BASE:
        missing.append("HUB_API_BASE")
    if not HUB_DEVICE_TOKEN:
        missing.append("HUB_DEVICE_TOKEN")
    if not ARTIFACT_BUCKET:
        missing.append("ARTIFACT_BUCKET")
    if missing:
        raise SystemExit(f"Missing required env vars: {', '.join(missing)}")


def _dummy_embedding(data: bytes, dim: int) -> list[float]:
    """Deterministic embedding for explicit local tests only."""
    seed = hashlib.sha256(data).digest()
    out: list[float] = []
    counter = 0
    while len(out) < dim:
        h = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        for i in range(0, len(h), 4):
            if len(out) >= dim:
                break
            chunk = h[i : i + 4]
            if len(chunk) < 4:
                continue
            v = int.from_bytes(chunk, "big", signed=False)
            out.append((v / 2**32) * 2.0 - 1.0)  # [-1, 1)
        counter += 1
    # Normalize to unit length so cosine distance behaves sensibly.
    norm = math.sqrt(sum(x * x for x in out)) or 1.0
    return [x / norm for x in out]


def _try_voice_embedding(audio_bytes: bytes) -> tuple[list[float], str] | None:
    """Return (embedding, model_name) or None if deps are unavailable."""
    try:
        import numpy as np  # type: ignore
        import soundfile as sf  # type: ignore
        from resemblyzer import VoiceEncoder, preprocess_wav  # type: ignore
    except Exception:
        return None

    try:
        data, sr = sf.read(io.BytesIO(audio_bytes))
        wav = preprocess_wav(data, source_sr=sr)
        enc = VoiceEncoder()
        emb = enc.embed_utterance(wav)
        if isinstance(emb, np.ndarray):
            emb = emb.astype("float32")
            return (emb.tolist(), "resemblyzer")
    except Exception as exc:
        logger.warning("Voice embedding failed: %s", exc)
    return None


def _try_face_embedding(image_bytes: bytes) -> tuple[list[float], str] | None:
    """Return (embedding, model_name) or None if deps are unavailable."""
    try:
        import insightface  # type: ignore
        import numpy as np  # type: ignore
        from PIL import Image  # type: ignore
    except Exception:
        return None

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        arr = np.asarray(img)[:, :, ::-1]  # RGB -> BGR for insightface
        app = insightface.app.FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"])
        app.prepare(ctx_id=0, det_size=(640, 640))
        faces = app.get(arr)
        if not faces:
            return None
        emb = faces[0].embedding
        if isinstance(emb, np.ndarray):
            emb = emb.astype("float32")
            return (emb.tolist(), "insightface-arcface")
    except Exception as exc:
        logger.warning("Face embedding failed: %s", exc)
    return None


def _embedding_or_raise(*, modality: str, data: bytes) -> tuple[list[float], str]:
    if modality == "voice":
        emb_and_model = _try_voice_embedding(data)
        dummy_dim = 256
        dummy_model = "dummy-voice"
    elif modality == "face":
        emb_and_model = _try_face_embedding(data)
        dummy_dim = 512
        dummy_model = "dummy-face"
    else:
        raise RuntimeError(f"unsupported modality: {modality}")
    if emb_and_model is not None:
        return emb_and_model
    if ALLOW_DUMMY_EMBEDDINGS:
        logger.warning("Using explicit dummy %s recognition embedding", modality)
        return _dummy_embedding(data, dummy_dim), dummy_model
    raise RuntimeError(
        f"recognizer_unavailable:{modality}. Install the production recognizer dependency "
        "or set RECOGNITION_ALLOW_DUMMY_EMBEDDINGS=true for local tests only."
    )


def _hub_post(path: str, payload: dict[str, Any], timeout_s: int = 15) -> dict[str, Any]:
    url = f"{HUB_API_BASE}{path}"
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout_s,
    )
    if not resp.ok:
        raise RuntimeError(f"Hub POST {path} failed: status={resp.status_code} body={resp.text[:300]}")
    try:
        return resp.json()
    except Exception:
        return {}


def _extract_artifact_ref(payload: dict[str, Any]) -> tuple[str, str]:
    bucket = str(payload.get("artifact_bucket") or payload.get("bucket") or "").strip() or ARTIFACT_BUCKET
    key = str(payload.get("artifact_key") or payload.get("key") or payload.get("s3_key") or "").strip()
    return bucket, key


def _process_message(msg_body: dict[str, Any], s3: Any) -> None:
    ev_type = str(msg_body.get("type") or "").strip()
    agent_id = str(msg_body.get("agent_id") or "").strip()
    space_id = str(msg_body.get("space_id") or "").strip()
    device_id = str(msg_body.get("device_id") or "").strip()
    event_id = str(msg_body.get("event_id") or "").strip()
    payload = msg_body.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}

    if ev_type not in {"voice.sample", "face.snapshot"}:
        logger.info("Skipping unsupported recognition event type=%r event_id=%s", ev_type, event_id)
        return

    bucket, key = _extract_artifact_ref(payload)
    if not bucket or not key:
        logger.warning("Recognition event missing artifact ref: type=%s event_id=%s", ev_type, event_id)
        return

    obj = s3.get_object(Bucket=bucket, Key=key)
    data = obj["Body"].read()

    enroll_person_id = str(payload.get("enroll_person_id") or "").strip() or None
    modality = "voice" if ev_type == "voice.sample" else "face"

    embedding, model_name = _embedding_or_raise(modality=modality, data=data)

    if enroll_person_id:
        logger.info("Enrollment: %s person_id=%s event_id=%s", modality, enroll_person_id, event_id)
        if modality == "voice":
            _hub_post(
                f"/v1/people/{enroll_person_id}/voiceprints",
                {
                    "embedding": embedding,
                    "model": model_name,
                    "metadata": {"event_id": event_id, "artifact_bucket": bucket, "artifact_key": key},
                },
            )
        else:
            _hub_post(
                f"/v1/people/{enroll_person_id}/faceprints",
                {
                    "embedding": embedding,
                    "model": model_name,
                    "metadata": {"event_id": event_id, "artifact_bucket": bucket, "artifact_key": key},
                },
            )
    else:
        logger.info("Identify: %s agent_id=%s space_id=%s event_id=%s", modality, agent_id, space_id, event_id)
        if not agent_id or not space_id:
            logger.warning("Recognition identify missing agent_id/space_id; event_id=%s", event_id)
            return

        if modality == "voice":
            identify = _hub_post("/v1/identify/voice", {"agent_id": agent_id, "embedding": embedding, "k": 1})
        else:
            identify = _hub_post("/v1/identify/face", {"agent_id": agent_id, "embedding": embedding, "k": 1})

        if not identify.get("matched") or not identify.get("best"):
            logger.info("No match for %s event_id=%s", modality, event_id)
        else:
            best = identify["best"] or {}
            person_id = str(best.get("person_id") or "").strip()
            confidence = float(best.get("confidence") or 0.0)
            if person_id:
                # Update presence.
                _hub_post(
                    f"/v1/spaces/{space_id}/presence",
                    {
                        "updates": [
                            {
                                "person_id": person_id,
                                "status": "present",
                                "confidence": confidence,
                                "modality": modality,
                                "source_device_id": device_id or None,
                            }
                        ]
                    },
                )
                # Emit timeline event for visibility.
                _hub_post(
                    "/v1/events",
                    {
                        "space_id": space_id,
                        "type": "person.observed",
                        "person_id": person_id,
                        "payload": {
                            "modality": modality,
                            "confidence": confidence,
                            "source_device_id": device_id or None,
                            "source_event_id": event_id,
                        },
                    },
                )

    if DELETE_ARTIFACTS:
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except Exception as exc:
            logger.warning("Failed to delete recognition artifact s3://%s/%s: %s", bucket, key, exc)


_running = True


def _handle_signal(sig: int, frame: Any) -> None:  # noqa: ARG001 - signature required by signal.signal
    global _running
    _running = False
    logger.info("Stopping (signal=%s)...", sig)


def main() -> int:
    _require_env()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    sqs = boto3.client("sqs")
    s3 = boto3.client("s3")

    logger.info("Recognition worker started")
    logger.info("Queue: %s", RECOGNITION_QUEUE_URL)
    logger.info("Hub: %s", HUB_API_BASE)
    logger.info("Delete artifacts: %s", DELETE_ARTIFACTS)
    logger.info("Dummy embeddings enabled: %s", ALLOW_DUMMY_EMBEDDINGS)

    while _running:
        try:
            resp = sqs.receive_message(
                QueueUrl=RECOGNITION_QUEUE_URL,
                MaxNumberOfMessages=MAX_MESSAGES,
                WaitTimeSeconds=POLL_WAIT_SECONDS,
                VisibilityTimeout=VISIBILITY_TIMEOUT,
            )
            msgs = resp.get("Messages") or []
            if not msgs:
                continue

            for m in msgs:
                receipt = m.get("ReceiptHandle")
                body_raw = m.get("Body") or ""
                try:
                    body = json.loads(body_raw)
                except Exception:
                    body = {}
                try:
                    _process_message(body, s3=s3)
                    if receipt:
                        sqs.delete_message(QueueUrl=RECOGNITION_QUEUE_URL, ReceiptHandle=receipt)
                except Exception as exc:
                    logger.exception("Failed to process recognition message: %s", exc)
                    # Leave the message for retry / DLQ (if configured).
        except Exception as exc:
            logger.exception("SQS receive loop error: %s", exc)
            time.sleep(2)

    logger.info("Recognition worker stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
