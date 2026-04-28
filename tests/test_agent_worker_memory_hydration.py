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
    spec = importlib.util.spec_from_file_location("agent_worker_for_memory_hydration_tests", worker_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _memory(
    memory_id: str,
    *,
    distance: float,
    space_id: str | None = None,
    session_id: str | None = None,
    person_id: str | None = None,
    device_id: str | None = None,
    situation: str | None = None,
) -> dict:
    event_payload = {}
    if situation:
        event_payload["situation"] = situation
    return {
        "memory_id": memory_id,
        "tier": "semantic",
        "content": f"{memory_id} content",
        "distance": distance,
        "explanation": {
            "ranking": {"embedding_distance": distance},
            "source_event_id": f"event-{memory_id}",
            "device_id": device_id,
            "space_id": space_id,
            "session_id": session_id,
            "person_id": person_id,
            "source_evidence": {
                "event_id": f"event-{memory_id}",
                "event_payload": event_payload,
            },
        },
    }


def test_contextual_rank_weights_current_space_without_excluding_other_spaces() -> None:
    worker = _load_agent_worker_module()

    ranked = worker._rank_contextual_memories(
        [
            _memory("other-close", distance=0.04, space_id="space-2"),
            _memory("current-space", distance=0.20, space_id="space-1"),
            _memory("other-next", distance=0.05, space_id="space-3"),
        ],
        current_space_id="space-1",
        current_session_id=None,
        active_person_id=None,
    )

    assert [m["memory_id"] for m in ranked[:3]] == ["current-space", "other-close", "other-next"]


def test_contextual_recall_uses_current_space_as_query_context_not_filter() -> None:
    worker = _load_agent_worker_module()
    calls = []

    def fake_fetch_recall_memories(
        *, agent_id: str, space_id: str | None, query: str, k: int, person_id: str | None = None
    ) -> list[dict]:
        calls.append(
            {
                "agent_id": agent_id,
                "space_id": space_id,
                "person_id": person_id,
                "query": query,
                "k": k,
            }
        )
        if person_id:
            return [
                _memory(
                    "current-person-space",
                    distance=0.20,
                    space_id="space-1",
                    session_id="session-1",
                    person_id="person-1",
                )
            ]
        return [_memory("other-space", distance=0.01, space_id="space-2")]

    with mock.patch.object(worker, "_fetch_recall_memories", side_effect=fake_fetch_recall_memories):
        ranked = worker._fetch_contextual_recall_memories(
            agent_id="agent-1",
            current_space_id="space-1",
            current_session_id="session-1",
            active_person_id="person-1",
        )

    assert len(calls) == 2
    assert all(call["space_id"] is None for call in calls)
    assert calls[0]["person_id"] == "person-1"
    assert calls[1]["person_id"] is None
    assert all("current space space-1" in call["query"] for call in calls)
    assert [m["memory_id"] for m in ranked] == ["current-person-space", "other-space"]


def test_context_block_preserves_memory_source_context() -> None:
    worker = _load_agent_worker_module()

    context = worker._build_context_block(
        [],
        [
            _memory(
                "kitchen-preference",
                distance=0.12,
                space_id="space-kitchen",
                session_id="session-7",
                person_id="person-major",
                device_id="device-wall",
                situation="making coffee",
            )
        ],
    )

    assert "event event-kitchen-preference" in context
    assert "device device-wall" in context
    assert "space space-kitchen" in context
    assert "session session-7" in context
    assert "person person-major" in context
    assert "situation making coffee" in context
