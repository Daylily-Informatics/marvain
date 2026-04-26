from __future__ import annotations

import importlib.util
import os
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


def test_recognition_worker_does_not_use_dummy_embedding_unless_explicitly_enabled(monkeypatch) -> None:
    monkeypatch.delenv("RECOGNITION_ALLOW_DUMMY_EMBEDDINGS", raising=False)
    mod = _load_worker()
    mod._try_voice_embedding = mock.Mock(return_value=None)

    with pytest.raises(RuntimeError, match="recognizer_unavailable:voice"):
        mod._embedding_or_raise(modality="voice", data=b"audio")


def test_recognition_worker_allows_dummy_embedding_only_with_explicit_local_flag(monkeypatch) -> None:
    monkeypatch.setenv("RECOGNITION_ALLOW_DUMMY_EMBEDDINGS", "true")
    mod = _load_worker()
    mod._try_face_embedding = mock.Mock(return_value=None)

    embedding, model = mod._embedding_or_raise(modality="face", data=b"image")

    assert model == "dummy-face"
    assert len(embedding) == 512
    assert os.environ["RECOGNITION_ALLOW_DUMMY_EMBEDDINGS"] == "true"
