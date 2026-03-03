from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load_hub_api_app_module():
    """Load functions/hub_api/api_app.py as a module without requiring it be a package."""

    # Make the shared Lambda layer importable in local unit tests.
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    # Add hub_api directory to path so api_app imports work
    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    # Ensure boto3 client creation does not fail due to missing region/creds.
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    api_app_py = repo_root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules so Pydantic/FastAPI can resolve postponed annotations.
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


class TestHubApiMembershipEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls.client = TestClient(cls.mod.api_app)

    def setUp(self) -> None:
        # HubConfig is a frozen dataclass; replace the module-global config for tests.
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            audit_bucket=None,
            cognito_user_pool_id="pool",
        )

        # Default auth: always yields user u1.
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )

    def test_claim_owner_success(self) -> None:
        self.mod.claim_first_owner = mock.Mock(return_value=None)

        r = self.client.post(
            "/v1/agents/a1/claim_owner",
            headers={"Authorization": "Bearer tok"},
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["agent_id"], "a1")
        self.assertEqual(r.json()["user_id"], "u1")
        self.mod.claim_first_owner.assert_called_once()

    def test_claim_owner_conflict(self) -> None:
        self.mod.claim_first_owner = mock.Mock(side_effect=PermissionError("owner already exists"))

        r = self.client.post(
            "/v1/agents/a1/claim_owner",
            headers={"Authorization": "Bearer tok"},
        )

        self.assertEqual(r.status_code, 409)

    def test_update_agent_name(self) -> None:
        """PATCH /v1/agents/{id} should update the agent name."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        fake_db = mock.Mock()
        fake_db.query.return_value = [
            {"name": "New Name", "disabled": False, "role": "admin", "relationship_label": None}
        ]
        self.mod._db = fake_db

        r = self.client.patch(
            "/v1/agents/a1",
            headers={"Authorization": "Bearer tok"},
            json={"name": "New Name"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["agent_id"], "a1")
        self.assertEqual(body["name"], "New Name")
        self.assertFalse(body["disabled"])
        fake_db.execute.assert_called_once()

    def test_update_agent_empty_name_rejected(self) -> None:
        """PATCH /v1/agents/{id} with empty name should return 400."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.patch(
            "/v1/agents/a1",
            headers={"Authorization": "Bearer tok"},
            json={"name": "   "},
        )

        self.assertEqual(r.status_code, 400)

    def test_update_agent_no_fields_rejected(self) -> None:
        """PATCH /v1/agents/{id} with no fields should return 400."""
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.patch(
            "/v1/agents/a1",
            headers={"Authorization": "Bearer tok"},
            json={},
        )

        self.assertEqual(r.status_code, 400)

    def test_update_agent_requires_admin(self) -> None:
        """PATCH /v1/agents/{id} should reject non-admin users."""
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.patch(
            "/v1/agents/a1",
            headers={"Authorization": "Bearer tok"},
            json={"name": "Nope"},
        )

        self.assertEqual(r.status_code, 403)

    def test_list_memberships_forbidden_without_membership(self) -> None:
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.get(
            "/v1/agents/a1/memberships",
            headers={"Authorization": "Bearer tok"},
        )

        self.assertEqual(r.status_code, 403)

    def test_add_member_success(self) -> None:
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod.lookup_cognito_user_by_email = mock.Mock(return_value=("sub-2", "u2@example.com"))
        self.mod.ensure_user_row = mock.Mock(return_value="user-2")
        self.mod.grant_membership = mock.Mock(return_value=None)

        r = self.client.post(
            "/v1/agents/a1/memberships",
            headers={"Authorization": "Bearer tok"},
            json={"email": "u2@example.com", "role": "member", "relationship_label": "friend"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["user_id"], "user-2")
        self.assertEqual(body["cognito_sub"], "sub-2")
        self.assertEqual(body["email"], "u2@example.com")

    def test_register_device_success(self) -> None:
        self.mod.check_agent_permission = mock.Mock(return_value=True)
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.generate_device_token = mock.Mock(return_value="devtok")
        self.mod.hash_token = mock.Mock(return_value="hash")

        fake_db = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/devices/register",
            headers={"Authorization": "Bearer tok"},
            json={"agent_id": "a1"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["device_id"])
        self.assertEqual(body["device_token"], "devtok")
        self.assertTrue(fake_db.execute.called)

    def test_ingest_event_rejects_space_not_owned_by_device_agent(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(device_id="d1", agent_id="a1", scopes=["events:write"])
        )
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.broadcast_event = mock.Mock()
        self.mod._cfg = dataclasses.replace(self.mod._cfg, transcript_queue_url=None, audit_bucket=None)

        fake_db = mock.Mock()
        # _space_agent_id lookup returns a different agent_id than the device token.
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a2"}])
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/events",
            headers={"Authorization": "Bearer devtok"},
            json={"space_id": "space-1", "type": "transcript_chunk", "payload": {"text": "hello"}},
        )
        self.assertEqual(r.status_code, 404)
        self.assertIn("Space not found", r.text)
        fake_db.execute.assert_not_called()
        self.mod.broadcast_event.assert_not_called()

    def test_ingest_event_accepts_space_owned_by_device_agent(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(device_id="d1", agent_id="a1", scopes=["events:write"])
        )
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.is_privacy_mode = mock.Mock(return_value=False)
        self.mod.broadcast_event = mock.Mock()
        self.mod._cfg = dataclasses.replace(self.mod._cfg, transcript_queue_url=None, audit_bucket=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a1"}])
        fake_db.execute = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/events",
            headers={"Authorization": "Bearer devtok"},
            json={"space_id": "space-1", "type": "transcript_chunk", "payload": {"text": "hello"}},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("event_id"))
        fake_db.execute.assert_called_once()
        self.mod.broadcast_event.assert_called_once()

    def test_ingest_event_allows_admin_device_across_agents(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["events:write"],
                capabilities={"kind": "admin"},
            )
        )
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.is_privacy_mode = mock.Mock(return_value=False)
        self.mod.broadcast_event = mock.Mock()
        self.mod._cfg = dataclasses.replace(self.mod._cfg, transcript_queue_url=None, audit_bucket=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a2"}])
        fake_db.execute = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/events",
            headers={"Authorization": "Bearer devtok"},
            json={"space_id": "space-1", "type": "transcript_chunk", "payload": {"text": "hello"}},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get("event_id"))
        fake_db.execute.assert_called_once()
        _, params = fake_db.execute.call_args[0]
        self.assertEqual(params["agent_id"], "a2")
        self.mod.broadcast_event.assert_called_once()
        self.assertEqual(self.mod.broadcast_event.call_args.kwargs["agent_id"], "a2")

    def test_ingest_event_allows_worker_device_across_agents(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["events:write"],
                capabilities={"kind": "worker"},
            )
        )
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.is_privacy_mode = mock.Mock(return_value=False)
        self.mod.broadcast_event = mock.Mock()
        self.mod._cfg = dataclasses.replace(self.mod._cfg, transcript_queue_url=None, audit_bucket=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a2"}])
        fake_db.execute = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/events",
            headers={"Authorization": "Bearer devtok"},
            json={"space_id": "space-1", "type": "transcript_chunk", "payload": {"text": "hello"}},
        )
        self.assertEqual(r.status_code, 200)
        fake_db.execute.assert_called_once()
        _, params = fake_db.execute.call_args[0]
        self.assertEqual(params["agent_id"], "a2")

    def test_recall_memories_falls_back_to_recent_when_embeddings_unconfigured(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(device_id="d1", agent_id="a1", scopes=["memories:read"])
        )
        self.mod._cfg = dataclasses.replace(self.mod._cfg, openai_secret_arn=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(
            return_value=[
                {
                    "memory_id": "m1",
                    "tier": "episodic",
                    "content": "User said they are tired",
                    "created_at": "2026-03-03T10:00:00Z",
                }
            ]
        )
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/recall",
            headers={"Authorization": "Bearer devtok"},
            json={"agent_id": "a1", "query": "tired", "k": 3},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body["memories"]), 1)
        self.assertEqual(body["memories"][0]["memory_id"], "m1")
        self.assertEqual(body["memories"][0]["distance"], 1.0)
        fake_db.query.assert_called_once()

    def test_recall_memories_allows_admin_device_across_agents_with_space(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["memories:read"],
                capabilities={"kind": "admin"},
            )
        )
        self.mod._cfg = dataclasses.replace(self.mod._cfg, openai_secret_arn=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(
            side_effect=[
                [{"agent_id": "a2"}],
                [
                    {
                        "memory_id": "m1",
                        "tier": "episodic",
                        "content": "cross-agent memory",
                        "created_at": "2026-03-03T10:00:00Z",
                    }
                ],
            ]
        )
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/recall",
            headers={"Authorization": "Bearer devtok"},
            json={"agent_id": "a2", "space_id": "space-1", "query": "memory", "k": 3},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body["memories"]), 1)
        self.assertEqual(body["memories"][0]["memory_id"], "m1")

    def test_recall_memories_admin_cross_agent_requires_space_id(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["memories:read"],
                capabilities={"kind": "admin"},
            )
        )
        self.mod._cfg = dataclasses.replace(self.mod._cfg, openai_secret_arn=None)

        r = self.client.post(
            "/v1/recall",
            headers={"Authorization": "Bearer devtok"},
            json={"agent_id": "a2", "query": "memory", "k": 3},
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("requires space_id", r.text)

    def test_create_memory_generates_embedding_when_openai_configured(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(device_id="d1", agent_id="a1", scopes=["memories:write"])
        )
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            openai_secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:oai",
            audit_bucket=None,
        )
        self.mod.call_embeddings = mock.Mock(return_value=[0.125, -0.5, 0.25])

        fake_db = mock.Mock()
        fake_db.execute = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/memories",
            headers={"Authorization": "Bearer devtok"},
            json={"tier": "episodic", "content": "hello memory"},
        )
        self.assertEqual(r.status_code, 200)
        self.mod.call_embeddings.assert_called_once()
        self.assertTrue(fake_db.execute.called)
        _, params = fake_db.execute.call_args[0]
        self.assertIn("embedding", params)
        self.assertIsInstance(params["embedding"], str)
        self.assertTrue(params["embedding"].startswith("[0.125000,-0.500000,0.250000"))

    def test_create_memory_allows_admin_device_across_agents(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["memories:write"],
                capabilities={"kind": "admin"},
            )
        )
        self.mod._cfg = dataclasses.replace(self.mod._cfg, openai_secret_arn=None, audit_bucket=None)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(return_value=[{"agent_id": "a2"}])
        fake_db.execute = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/memories",
            headers={"Authorization": "Bearer devtok"},
            json={"space_id": "space-1", "tier": "episodic", "content": "hello memory"},
        )
        self.assertEqual(r.status_code, 200)
        fake_db.execute.assert_called_once()
        _, params = fake_db.execute.call_args[0]
        self.assertEqual(params["agent_id"], "a2")

    def test_get_space_events_allows_admin_device_across_agents(self) -> None:
        self.mod.authenticate_device = mock.Mock(
            return_value=self.mod.AuthenticatedDevice(
                device_id="d1",
                agent_id="a1",
                scopes=["events:read"],
                capabilities={"kind": "admin"},
            )
        )
        self.mod.is_privacy_mode = mock.Mock(return_value=False)

        fake_db = mock.Mock()
        fake_db.query = mock.Mock(
            side_effect=[
                [{"agent_id": "a2"}],
                [
                    {
                        "event_id": "e1",
                        "type": "transcript_chunk",
                        "person_id": None,
                        "payload_json": '{"text":"hi"}',
                        "created_at": "2026-03-03T10:00:00Z",
                    }
                ],
            ]
        )
        self.mod._db = fake_db

        r = self.client.get(
            "/v1/spaces/space-1/events?limit=10",
            headers={"Authorization": "Bearer devtok"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["event_id"], "e1")

    def test_create_agent_success(self) -> None:
        """Test POST /v1/agents creates an agent and makes user the owner."""
        fake_db = mock.Mock()
        fake_db.begin = mock.Mock(return_value="tx123")
        fake_db.execute = mock.Mock()
        fake_db.commit = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/agents",
            headers={"Authorization": "Bearer tok"},
            json={"name": "My New Agent", "relationship_label": "Assistant"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["agent_id"])
        self.assertEqual(body["name"], "My New Agent")
        self.assertEqual(body["role"], "owner")
        self.assertEqual(body["relationship_label"], "Assistant")
        self.assertFalse(body["disabled"])
        # Verify transaction was used
        fake_db.begin.assert_called_once()
        fake_db.commit.assert_called_once_with("tx123")
        # Two execute calls: one for agent insert, one for membership insert
        self.assertEqual(fake_db.execute.call_count, 2)

    def test_create_agent_without_relationship_label(self) -> None:
        """Test POST /v1/agents creates an agent without relationship_label."""
        fake_db = mock.Mock()
        fake_db.begin = mock.Mock(return_value="tx123")
        fake_db.execute = mock.Mock()
        fake_db.commit = mock.Mock()
        self.mod._db = fake_db

        r = self.client.post(
            "/v1/agents",
            headers={"Authorization": "Bearer tok"},
            json={"name": "Simple Agent"},
        )

        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["name"], "Simple Agent")
        self.assertIsNone(body["relationship_label"])

    def test_create_agent_requires_authentication(self) -> None:
        """Test POST /v1/agents returns 401 without auth."""
        self.mod.authenticate_user_access_token = mock.Mock(side_effect=PermissionError("Invalid token"))

        r = self.client.post(
            "/v1/agents",
            headers={"Authorization": "Bearer invalid"},
            json={"name": "Test"},
        )

        self.assertEqual(r.status_code, 401)

    def test_create_agent_requires_name(self) -> None:
        """Test POST /v1/agents requires name field."""
        r = self.client.post(
            "/v1/agents",
            headers={"Authorization": "Bearer tok"},
            json={},
        )

        self.assertEqual(r.status_code, 422)  # Validation error

    def test_create_agent_rollback_on_error(self) -> None:
        """Test POST /v1/agents rolls back transaction on error."""
        fake_db = mock.Mock()
        fake_db.begin = mock.Mock(return_value="tx123")
        fake_db.execute = mock.Mock(side_effect=Exception("DB error"))
        fake_db.rollback = mock.Mock()
        self.mod._db = fake_db

        # Use a client that doesn't raise server exceptions
        client = self._TestClient(self.mod.api_app, raise_server_exceptions=False)
        r = client.post(
            "/v1/agents",
            headers={"Authorization": "Bearer tok"},
            json={"name": "Test Agent"},
        )

        self.assertEqual(r.status_code, 500)
        fake_db.rollback.assert_called_once_with("tx123")


if __name__ == "__main__":
    unittest.main()
