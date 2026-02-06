"""Tests for GUI 'Coming Soon' features that have been implemented.

These tests verify the 7 features that replaced 'Coming Soon' toast stubs:
1. Action Details View - GET /api/actions/{action_id}
2. Edit Person - PATCH /api/people/{person_id}
3. Memory Details View - GET /api/memories/{memory_id}
4. Edit Agent - PATCH /api/agents/{agent_id}
5. Event Details View - GET /api/events/{event_id}
6. Space Editing Options - PATCH /api/spaces/{space_id}
7. Edit Remote - PATCH /api/remotes/{remote_id}
"""
from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

# Module-level cached module to ensure all test classes share the same module instance.
_cached_hub_api_module = None


def _load_hub_api_app_module():
    """Load functions/hub_api/app.py as a module."""
    global _cached_hub_api_module
    if _cached_hub_api_module is not None:
        return _cached_hub_api_module

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
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    for mod_name in ["api_app", "hub_api_app_for_tests_coming_soon"]:
        if mod_name in sys.modules:
            del sys.modules[mod_name]

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests_coming_soon", app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)

    _cached_hub_api_module = mod
    return mod


class TestComingSoonFeatures(unittest.TestCase):
    """Tests for the 7 Coming Soon features."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient
        cls._TestClient = TestClient
        # Store originals
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission
        self.mod._cfg = dataclasses.replace(
            self.mod._cfg,
            cognito_domain="marvain-dev.auth.us-west-2.amazoncognito.com",
            cognito_user_pool_id="pool-123",
            cognito_user_pool_client_id="client-123",
            cognito_redirect_uri="http://testserver/auth/callback",
        )

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission

    def _mock_authenticated_user(self):
        """Return a mock authenticated user."""
        return self.mod.AuthenticatedUser(
            user_id="u1", cognito_sub="sub-1", email="u1@example.com"
        )

    def _mock_db(self, query_results=None, execute_results=None):
        """Create a mock database object."""
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=query_results or [])
        mock_db.execute = mock.Mock(return_value=execute_results)
        return mock_db

    # -------------------------------------------------------------------------
    # Feature 1.1: Action Details View - GET /api/actions/{action_id}
    # -------------------------------------------------------------------------

    def test_get_action_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/actions/action-1")
        self.assertEqual(r.status_code, 401)

    def test_get_action_returns_not_found_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/actions/action-1")
        self.assertEqual(r.status_code, 404)

    def test_get_action_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "action_id": "action-1",
            "agent_id": "agent-1",
            "kind": "shell_command",
            "payload": '{"cmd": "echo hello"}',
            "required_scopes": '["shell_command:execute"]',
            "status": "completed",
            "result": '{"stdout": "hello"}',
            "error": None,
            "created_at": "2025-01-01T00:00:00",
            "approved_at": "2025-01-01T00:00:01",
            "completed_at": "2025-01-01T00:00:02",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/actions/action-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["action_id"], "action-1")
        self.assertEqual(data["kind"], "shell_command")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["payload"]["cmd"], "echo hello")

    # -------------------------------------------------------------------------
    # Feature 1.2: Edit Person - PATCH /api/people/{person_id}
    # -------------------------------------------------------------------------

    def test_update_person_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.patch("/api/people/person-1", json={"display_name": "New Name"})
        self.assertEqual(r.status_code, 401)

    def test_update_person_returns_not_found_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/people/person-1", json={"display_name": "New Name"})
        self.assertEqual(r.status_code, 404)

    def test_update_person_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{"person_id": "person-1"}])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/people/person-1", json={"display_name": "New Name"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Person updated")
        self.assertEqual(data["person_id"], "person-1")

    def test_get_person_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/people/person-1")
        self.assertEqual(r.status_code, 401)

    def test_get_person_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "person_id": "person-1",
            "agent_id": "agent-1",
            "agent_name": "Test Agent",
            "display_name": "John Doe",
            "metadata": "{}",
            "created_at": "2025-01-01T00:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/people/person-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["person_id"], "person-1")
        self.assertEqual(data["display_name"], "John Doe")

    # -------------------------------------------------------------------------
    # Feature 1.3: Memory Details View - GET /api/memories/{memory_id}
    # -------------------------------------------------------------------------

    def test_get_memory_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/memories/memory-1")
        self.assertEqual(r.status_code, 401)

    def test_get_memory_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "memory_id": "memory-1",
            "agent_id": "agent-1",
            "space_id": "space-1",
            "agent_name": "Test Agent",
            "space_name": "Living Room",
            "tier": "episodic",
            "content": "User discussed their project",
            "participants": "[]",
            "provenance": "{}",
            "retention": "{}",
            "created_at": "2025-01-01T00:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/memories/memory-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["memory_id"], "memory-1")
        self.assertEqual(data["tier"], "episodic")
        self.assertEqual(data["content"], "User discussed their project")

    # -------------------------------------------------------------------------
    # Feature 1.4: Edit Agent - PATCH /api/agents/{agent_id}
    # -------------------------------------------------------------------------

    def test_update_agent_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.patch("/api/agents/agent-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 401)

    def test_update_agent_returns_forbidden_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        # Mock check_agent_permission to return False (no permission)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.patch("/api/agents/agent-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 403)

    def test_update_agent_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{"agent_id": "agent-1", "name": "Old Name"}])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        # Mock check_agent_permission to return True
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.patch("/api/agents/agent-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Agent updated")
        self.assertEqual(data["agent_id"], "agent-1")

    def test_get_agent_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/agents/agent-1")
        self.assertEqual(r.status_code, 401)

    def test_get_agent_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "agent_id": "agent-1",
            "name": "Test Agent",
            "disabled": False,
            "role": "owner",
            "relationship_label": None,
            "created_at": "2025-01-01T00:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/agents/agent-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertEqual(data["name"], "Test Agent")
        self.assertEqual(data["disabled"], False)
        self.assertEqual(data["role"], "owner")

    # -------------------------------------------------------------------------
    # Feature 1.5: Event Details View - GET /api/events/{event_id}
    # -------------------------------------------------------------------------

    def test_get_event_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/events/event-1")
        self.assertEqual(r.status_code, 401)

    def test_get_event_returns_not_found_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/events/event-1")
        self.assertEqual(r.status_code, 404)

    def test_get_event_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "event_id": "event-1",
            "agent_id": "agent-1",
            "agent_name": "Test Agent",
            "space_id": "space-1",
            "space_name": "Living Room",
            "device_id": None,
            "device_name": None,
            "person_id": None,
            "person_name": None,
            "type": "conversation_started",
            "payload": '{"participants": 2}',
            "created_at": "2025-01-01T00:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/events/event-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["event_id"], "event-1")
        self.assertEqual(data["type"], "conversation_started")
        self.assertEqual(data["payload"]["participants"], 2)

    # -------------------------------------------------------------------------
    # Feature 1.6: Space Editing Options - PATCH /api/spaces/{space_id}
    # -------------------------------------------------------------------------

    def test_update_space_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.patch("/api/spaces/space-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 401)

    def test_update_space_returns_not_found_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/spaces/space-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 404)

    def test_update_space_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{"space_id": "space-1", "name": "Old Name"}])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/spaces/space-1", json={"name": "New Name", "privacy_mode": True})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Space updated")
        self.assertEqual(data["space_id"], "space-1")

    def test_update_space_rejects_empty_name(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{"space_id": "space-1", "name": "Old Name"}])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/spaces/space-1", json={"name": ""})
        self.assertEqual(r.status_code, 400)

    def test_get_space_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/spaces/space-1")
        self.assertEqual(r.status_code, 401)

    def test_get_space_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "space_id": "space-1",
            "agent_id": "agent-1",
            "agent_name": "Test Agent",
            "name": "Living Room",
            "privacy_mode": False,
            "created_at": "2025-01-01T00:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/spaces/space-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["space_id"], "space-1")
        self.assertEqual(data["name"], "Living Room")
        self.assertEqual(data["privacy_mode"], False)

    # -------------------------------------------------------------------------
    # Feature 1.7: Edit Remote - PATCH /api/remotes/{remote_id}
    # -------------------------------------------------------------------------

    def test_update_remote_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.patch("/api/remotes/remote-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 401)

    def test_update_remote_returns_not_found_without_permission(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/remotes/remote-1", json={"name": "New Name"})
        self.assertEqual(r.status_code, 404)

    def test_update_remote_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "device_id": "remote-1",
            "name": "Old Name",
            "metadata": '{"is_remote": true, "address": "192.168.1.1"}'
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/remotes/remote-1", json={"name": "New Name", "address": "192.168.1.100"})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["message"], "Remote updated")
        self.assertEqual(data["remote_id"], "remote-1")

    def test_update_remote_rejects_empty_name(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "device_id": "remote-1",
            "name": "Old Name",
            "metadata": '{"is_remote": true}'
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.patch("/api/remotes/remote-1", json={"name": ""})
        self.assertEqual(r.status_code, 400)

    def test_get_remote_requires_authentication(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=None)
        r = self.client.get("/api/remotes/remote-1")
        self.assertEqual(r.status_code, 401)

    def test_get_remote_success(self) -> None:
        self.mod._gui_get_user = mock.Mock(return_value=self._mock_authenticated_user())
        mock_db = self._mock_db(query_results=[{
            "remote_id": "remote-1",
            "agent_id": "agent-1",
            "agent_name": "Test Agent",
            "name": "Living Room Camera",
            "status": "online",
            "metadata": '{"is_remote": true, "address": "192.168.1.100", "connection_type": "network"}',
            "created_at": "2025-01-01T00:00:00",
            "last_seen_at": "2025-01-01T12:00:00",
        }])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.get("/api/remotes/remote-1")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["remote_id"], "remote-1")
        self.assertEqual(data["name"], "Living Room Camera")
        self.assertEqual(data["address"], "192.168.1.100")
        self.assertEqual(data["connection_type"], "network")


if __name__ == "__main__":
    unittest.main()

