"""Tests for agent rejoin behavior.

These tests verify that:
1. Ephemeral room names are generated (unique per session)
2. Agent worker properly disconnects when last human leaves
3. Metadata is passed correctly for space_id extraction

The ephemeral room approach (room name = "{space_id}:{session_id}") eliminates
the need for room deletion, ensuring reliable agent dispatch on every join.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load_hub_api_app_module():
    """Load functions/hub_api/api_app.py as a module without requiring it be a package."""
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    api_app_py = repo_root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests_rejoin", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def _load_agent_worker_module():
    """Load apps/agent_worker/worker.py as a module for unit-style tests."""
    repo_root = Path(__file__).resolve().parents[1]
    worker_py = repo_root / "apps" / "agent_worker" / "worker.py"

    # Speed up disconnect tests.
    os.environ["AGENT_DISCONNECT_DELAY_SECONDS"] = "0"

    spec = importlib.util.spec_from_file_location("agent_worker_for_tests_rejoin", worker_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    mod.AGENT_DISCONNECT_DELAY_SECONDS = 0.0
    return mod


class TestEphemeralRoomNames(unittest.TestCase):
    """Test that ephemeral room names are generated for reliable agent dispatch."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient
        cls.client = TestClient(cls.mod.api_app)

    def setUp(self) -> None:
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            livekit_url="wss://livekit.example",
            livekit_secret_arn="arn:aws:secretsmanager:us-west-2:123:secret:lk",
        )
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.get_secret_json = mock.Mock(return_value={"api_key": "k", "api_secret": "s"})
        self.mod.mint_livekit_join_token = mock.Mock(return_value="jwt")
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a1"}])
        self.mod._db = fake_db

    def test_token_returns_ephemeral_room_name(self) -> None:
        """Token endpoint should return room name in format {space_id}:{session_id}."""
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "space-uuid-123"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()

        # Room name should be ephemeral format
        room = body["room"]
        self.assertIn(":", room, f"Room should have ephemeral format, got: {room}")
        parts = room.split(":")
        self.assertEqual(parts[0], "space-uuid-123")
        self.assertEqual(len(parts[1]), 12)  # 12-char hex session ID

    def test_each_request_gets_unique_room_name(self) -> None:
        """Each token request should get a unique room name for reliable dispatch."""
        rooms = set()
        for _ in range(5):
            r = self.client.post(
                "/v1/livekit/token",
                headers={"Authorization": "Bearer tok"},
                json={"space_id": "space-1"},
            )
            self.assertEqual(r.status_code, 200)
            rooms.add(r.json()["room"])

        self.assertEqual(len(rooms), 5, "Each request should get unique room name")

    def test_space_id_passed_in_metadata(self) -> None:
        """Agent metadata should contain space_id for transcript storage."""
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "my-space-uuid"},
        )
        self.assertEqual(r.status_code, 200)

        # Verify metadata was passed to token minting
        self.mod.mint_livekit_join_token.assert_called()
        call_kwargs = self.mod.mint_livekit_join_token.call_args.kwargs
        self.assertIn("agent_metadata", call_kwargs)
        metadata = call_kwargs["agent_metadata"]
        self.assertEqual(metadata["space_id"], "my-space-uuid")
        self.assertIn("room_session_id", metadata)


class TestAgentWorkerDisconnect(unittest.TestCase):
    """Unit tests for worker-side behavior: disconnect when last human leaves."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.worker = _load_agent_worker_module()

    def test_agent_disconnects_when_last_human_leaves(self) -> None:
        worker = self.worker

        class FakeRoom:
            def __init__(self):
                self.name = "space-1"
                self.remote_participants = {}
                self._handlers = {}
                self.disconnected = False
                self._start_blocker = asyncio.Event()
                self._disconnected_event = asyncio.Event()

            def on(self, event: str, cb):
                self._handlers[event] = cb

            async def disconnect(self):
                self.disconnected = True
                self._disconnected_event.set()

        class FakeCtx:
            def __init__(self, room):
                self.room = room
                self.connect = mock.AsyncMock()
                # Worker extracts space_id from ctx.job.metadata
                self.job = mock.Mock()
                self.job.metadata = json.dumps({"space_id": "space-1"})

        class FakeSession:
            def __init__(self, **kwargs):
                self._handlers = {}

            def on(self, event: str, cb):
                self._handlers[event] = cb

            async def start(self, **kwargs):
                # Block until test allows forge_agent to continue.
                await kwargs["room"]._start_blocker.wait()

            async def generate_reply(self, **kwargs):
                return None

        room = FakeRoom()
        ctx = FakeCtx(room)

        # Patch out the real session + model construction.
        with mock.patch.object(worker, "AgentSession", FakeSession), mock.patch.object(
            worker.openai.realtime, "RealtimeModel", lambda **kwargs: object()
        ):

            async def _run():
                task = asyncio.create_task(worker.forge_agent(ctx))

                # Let forge_agent register the participant_disconnected handler.
                await asyncio.sleep(0)
                self.assertIn("participant_disconnected", room._handlers)

                # Simulate that a human disconnect event fires after the participant is removed.
                class FakeParticipant:
                    kind = worker.rtc.ParticipantKind.PARTICIPANT_KIND_STANDARD
                    identity = "user:u1"

                room.remote_participants = {}  # no humans remain
                room._handlers["participant_disconnected"](FakeParticipant())

                # Wait for scheduled disconnect task to run.
                await asyncio.wait_for(room._disconnected_event.wait(), timeout=0.25)
                self.assertTrue(room.disconnected)

                # Let forge_agent proceed/exit cleanly.
                room._start_blocker.set()
                await task

            asyncio.run(_run())

    def test_agent_can_handle_two_sequential_sessions_same_room_name(self) -> None:
        """A cheap proxy for 'rejoin': forge_agent can run twice with same room name."""
        worker = self.worker

        class FakeRoom:
            def __init__(self):
                self.name = "space-1"
                self.remote_participants = {}
                self._handlers = {}
                self._start_blocker = asyncio.Event()

            def on(self, event: str, cb):
                self._handlers[event] = cb

            async def disconnect(self):
                return None

        class FakeCtx:
            def __init__(self, room):
                self.room = room
                self.connect = mock.AsyncMock()
                # Worker extracts space_id from ctx.job.metadata
                self.job = mock.Mock()
                self.job.metadata = json.dumps({"space_id": "space-1"})

        class FakeSession:
            def __init__(self, **kwargs):
                self._handlers = {}

            def on(self, event: str, cb):
                self._handlers[event] = cb

            async def start(self, **kwargs):
                kwargs["room"]._start_blocker.set()

            async def generate_reply(self, **kwargs):
                return None

        with mock.patch.object(worker, "AgentSession", FakeSession), mock.patch.object(
            worker.openai.realtime, "RealtimeModel", lambda **kwargs: object()
        ):

            async def _run_two():
                ctx1 = FakeCtx(FakeRoom())
                await worker.forge_agent(ctx1)
                ctx2 = FakeCtx(FakeRoom())
                await worker.forge_agent(ctx2)

            asyncio.run(_run_two())


if __name__ == "__main__":
    unittest.main()

