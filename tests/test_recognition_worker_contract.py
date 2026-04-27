from __future__ import annotations

import importlib.util
import sys
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


def test_recognition_worker_requires_real_voice_recognizer() -> None:
    mod = _load_worker()
    mod._try_voice_embedding = mock.Mock(return_value=None)

    with pytest.raises(RuntimeError, match="recognizer_unavailable:voice"):
        mod._embedding_or_raise(modality="voice", data=b"audio")


def test_recognition_worker_requires_real_face_recognizer() -> None:
    mod = _load_worker()
    mod._try_face_embedding = mock.Mock(return_value=None)

    with pytest.raises(RuntimeError, match="recognizer_unavailable:face"):
        mod._embedding_or_raise(modality="face", data=b"image")


def test_recognition_worker_accepts_injected_recognizer_result() -> None:
    mod = _load_worker()
    mod._try_face_embedding = mock.Mock(return_value=([0.1, 0.2, 0.3], "test-fixture-face"))

    embedding, model = mod._embedding_or_raise(modality="face", data=b"image")

    assert embedding == [0.1, 0.2, 0.3]
    assert model == "test-fixture-face"
