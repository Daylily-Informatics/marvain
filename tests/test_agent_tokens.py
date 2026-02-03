"""Tests for agent-to-agent authentication and delegation.

Tests cover:
- Agent token creation and validation
- Scope-based access control
- Space-level restrictions
- Token revocation
- Delegation endpoints
"""

from __future__ import annotations

import importlib.util
import json
import os
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
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_agent_tokens", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


class TestAgentTokenAuth(unittest.TestCase):
    """Tests for agent token authentication functions."""

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        cls.mod = _load_hub_api_app_module()
        cls.client = TestClient(cls.mod.api_app)

    def setUp(self) -> None:
        # Mock database
        self.mock_db = mock.Mock()
        self.mod._db = self.mock_db
        # Mock user auth at module level
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(
                user_id="u1", cognito_sub="sub-1", email="user@example.com"
            )
        )

    def test_create_agent_token_requires_admin(self) -> None:
        """Creating an agent token requires admin role."""
        # Mock permission check to fail
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post(
            "/v1/agents/agent-1/tokens",
            headers={"Authorization": "Bearer test-token"},
            json={"name": "test-token", "scopes": ["read_memories"]},
        )

        self.assertEqual(r.status_code, 403)

    def test_create_agent_token_success(self) -> None:
        """Successfully create an agent token."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod.is_agent_disabled = mock.Mock(return_value=False)

        # Mock token creation
        self.mod.create_agent_token = mock.Mock(
            return_value=("token-id-123", "plaintext-token-abc")
        )

        r = self.client.post(
            "/v1/agents/agent-1/tokens",
            headers={"Authorization": "Bearer test-token"},
            json={"name": "my-token", "scopes": ["read_memories", "read_events"]},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["token_id"], "token-id-123")
        self.assertEqual(body["token"], "plaintext-token-abc")
        self.assertEqual(body["name"], "my-token")
        self.assertEqual(body["scopes"], ["read_memories", "read_events"])

    def test_list_agent_tokens(self) -> None:
        """List tokens for an agent."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod.list_agent_tokens = mock.Mock(
            return_value=[
                {
                    "token_id": "t1",
                    "target_agent_id": None,
                    "name": "token-1",
                    "scopes": ["read_memories"],
                    "allowed_spaces": None,
                    "expires_at": None,
                    "revoked_at": None,
                    "last_used_at": None,
                    "created_at": "2026-01-01T00:00:00Z",
                    "is_active": True,
                }
            ]
        )

        r = self.client.get(
            "/v1/agents/agent-1/tokens",
            headers={"Authorization": "Bearer test-token"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["token_id"], "t1")
        self.assertTrue(body[0]["is_active"])

    def test_revoke_agent_token(self) -> None:
        """Revoke an agent token."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod.revoke_agent_token = mock.Mock(return_value=True)

        r = self.client.delete(
            "/v1/agents/agent-1/tokens/token-123",
            headers={"Authorization": "Bearer test-token"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["revoked"])


class TestAgentDelegation(unittest.TestCase):
    """Tests for agent-to-agent delegation endpoints."""

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        # Import AuthenticatedAgent from agent_hub (already in sys.path from module load)
        from agent_hub.auth import AuthenticatedAgent

        cls.mod = _load_hub_api_app_module()
        cls.AuthenticatedAgent = AuthenticatedAgent
        cls.client = TestClient(cls.mod.api_app)

    def setUp(self) -> None:
        self.mock_db = mock.Mock()
        self.mod._db = self.mock_db

    def test_list_scopes_no_auth_required(self) -> None:
        """Listing available scopes doesn't require auth."""
        r = self.client.get("/v1/delegate/scopes")
        self.assertEqual(r.status_code, 200)
        scopes = r.json()
        self.assertIn("read_memories", scopes)
        self.assertIn("write_events", scopes)

    def test_delegate_read_memories_requires_scope(self) -> None:
        """Reading memories requires read_memories scope."""
        # Mock agent authentication without read_memories scope
        self.mod.authenticate_agent_token = mock.Mock(
            return_value=self.AuthenticatedAgent(
                token_id="t1",
                issuer_agent_id="agent-1",
                target_agent_id=None,
                scopes=["read_events"],  # Missing read_memories
                allowed_spaces=None,
            )
        )

        r = self.client.get(
            "/v1/delegate/memories",
            headers={"Authorization": "Bearer agent-token"},
        )

        self.assertEqual(r.status_code, 403)
        self.assertIn("read_memories", r.json()["detail"])

    def test_delegate_read_memories_success(self) -> None:
        """Successfully read memories with correct scope."""
        self.mod.authenticate_agent_token = mock.Mock(
            return_value=self.AuthenticatedAgent(
                token_id="t1",
                issuer_agent_id="agent-1",
                target_agent_id=None,
                scopes=["read_memories"],
                allowed_spaces=None,
            )
        )
        self.mock_db.query = mock.Mock(
            return_value=[
                {
                    "memory_id": "m1",
                    "space_id": "s1",
                    "tier": "short",
                    "content": "Test memory",
                    "participants": "[]",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        )

        r = self.client.get(
            "/v1/delegate/memories",
            headers={"Authorization": "Bearer agent-token"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["memory_id"], "m1")

    def test_delegate_space_restriction(self) -> None:
        """Token with space restrictions cannot access other spaces."""
        self.mod.authenticate_agent_token = mock.Mock(
            return_value=self.AuthenticatedAgent(
                token_id="t1",
                issuer_agent_id="agent-1",
                target_agent_id=None,
                scopes=["read_events"],
                allowed_spaces=["space-allowed"],  # Restricted to this space
            )
        )

        r = self.client.get(
            "/v1/delegate/events?space_id=space-forbidden",
            headers={"Authorization": "Bearer agent-token"},
        )

        self.assertEqual(r.status_code, 403)
        self.assertIn("space-forbidden", r.json()["detail"])

    def test_delegate_write_event_success(self) -> None:
        """Successfully write an event with correct scope."""
        self.mod.authenticate_agent_token = mock.Mock(
            return_value=self.AuthenticatedAgent(
                token_id="t1",
                issuer_agent_id="agent-1",
                target_agent_id=None,
                scopes=["write_events"],
                allowed_spaces=None,
            )
        )
        self.mock_db.execute = mock.Mock()

        r = self.client.post(
            "/v1/delegate/events",
            headers={"Authorization": "Bearer agent-token"},
            json={"space_id": "s1", "type": "test_event", "payload": {"key": "value"}},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["created"])
        self.assertIn("event_id", body)


if __name__ == "__main__":
    unittest.main()

