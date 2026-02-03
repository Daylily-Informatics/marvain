from __future__ import annotations

import dataclasses
import importlib.util
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

    # Add hub_api directory to path so api_app imports work
    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    api_app_py = repo_root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests_livekit", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


class TestHubApiLiveKit(unittest.TestCase):
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

    def test_v1_livekit_token_mints_token(self) -> None:
        """Test that livekit token endpoint returns a token with ephemeral room name."""
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "space-1"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "wss://livekit.example")
        self.assertEqual(body["token"], "jwt")
        # Room name is now ephemeral: "{space_id}:{session_id}"
        self.assertTrue(body["room"].startswith("space-1:"), f"Expected ephemeral room name, got: {body['room']}")
        self.assertEqual(body["identity"], "user:u1")

    def test_v1_livekit_token_ephemeral_room_format(self) -> None:
        """Test that room name uses correct ephemeral format: {space_id}:{12-char-hex}."""
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "space-uuid-123"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        room = body["room"]

        # Should be "space_id:session_id" format
        self.assertIn(":", room)
        parts = room.split(":")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], "space-uuid-123")
        # Session ID should be 12-char hex
        self.assertEqual(len(parts[1]), 12)
        self.assertTrue(re.match(r"^[0-9a-f]+$", parts[1]), f"Session ID should be hex: {parts[1]}")

    def test_v1_livekit_token_unique_room_per_request(self) -> None:
        """Test that each token request gets a unique room name (for reliable agent dispatch)."""
        rooms = set()
        for _ in range(5):
            r = self.client.post(
                "/v1/livekit/token",
                headers={"Authorization": "Bearer tok"},
                json={"space_id": "space-1"},
            )
            self.assertEqual(r.status_code, 200)
            rooms.add(r.json()["room"])

        # All 5 requests should have different room names
        self.assertEqual(len(rooms), 5, "Each request should get a unique room name")

    def test_v1_livekit_token_passes_metadata(self) -> None:
        """Test that space_id is passed to agent via metadata."""
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "my-space-uuid"},
        )
        self.assertEqual(r.status_code, 200)

        # Verify mint_livekit_join_token was called with agent_metadata containing space_id
        self.mod.mint_livekit_join_token.assert_called()
        call_kwargs = self.mod.mint_livekit_join_token.call_args.kwargs
        self.assertIn("agent_metadata", call_kwargs)
        metadata = call_kwargs["agent_metadata"]
        self.assertEqual(metadata["space_id"], "my-space-uuid")
        self.assertIn("room_session_id", metadata)

    def test_v1_livekit_token_requires_auth(self) -> None:
        """Test that token endpoint requires authentication."""
        self.mod.authenticate_user_access_token = mock.Mock(
            side_effect=PermissionError("Invalid token")
        )

        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer invalid"},
            json={"space_id": "space-1"},
        )
        self.assertEqual(r.status_code, 401)

    def test_v1_livekit_token_requires_permission(self) -> None:
        """Test that token endpoint requires membership permission."""
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "space-1"},
        )
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
