"""Tests for device registration, management, and command functionality.

These tests cover:
- Device registration via GUI API
- Device revocation
- Device listing and filtering
- Device command tool
"""

from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

# Module-level cached module
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

    for mod_name in ["api_app", "hub_api_app_for_tests_devices"]:
        if mod_name in sys.modules:
            del sys.modules[mod_name]

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests_devices", app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)

    _cached_hub_api_module = mod
    return mod


class TestDeviceRegistration(unittest.TestCase):
    """Tests for device registration via GUI API."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission

    def test_register_device_requires_authentication(self) -> None:
        """Device registration should require authentication."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post(
            "/api/devices",
            json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:write"]},
        )

        self.assertEqual(r.status_code, 401)
        self.assertIn("Not authenticated", r.json()["detail"])

    def test_register_device_requires_admin_permission(self) -> None:
        """Device registration should require admin permission on agent."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=False)

        r = self.client.post(
            "/api/devices",
            json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:write"]},
        )

        self.assertEqual(r.status_code, 403)
        self.assertIn("admin permission", r.json()["detail"])

    def test_register_device_success(self) -> None:
        """Successful device registration should return device_id and token."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post(
            "/api/devices",
            json={"agent_id": "agent-1", "name": "Test Device", "scopes": ["events:write"]},
        )

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("device_id", data)
        self.assertIn("token", data)
        self.assertEqual(data["name"], "Test Device")
        self.assertEqual(data["scopes"], ["events:write"])
        # Token should be a non-empty string
        self.assertTrue(len(data["token"]) > 20)

    def test_register_device_stores_token_hash(self) -> None:
        """Device registration should store hashed token, not plaintext."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        captured_params = {}

        def capture_execute(sql, params):
            captured_params.update(params)

        mock_db.execute = capture_execute
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.check_agent_permission = mock.Mock(return_value=True)

        r = self.client.post(
            "/api/devices",
            json={"agent_id": "agent-1", "name": "Test Device", "scopes": []},
        )

        self.assertEqual(r.status_code, 200)
        # Verify token_hash was stored (should be hex string, 64 chars for SHA256)
        self.assertIn("token_hash", captured_params)
        self.assertEqual(len(captured_params["token_hash"]), 64)


class TestDeviceRevocation(unittest.TestCase):
    """Tests for device revocation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db

    def test_revoke_device_requires_authentication(self) -> None:
        """Device revocation should require authentication."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/devices/device-123/revoke")

        self.assertEqual(r.status_code, 401)

    def test_revoke_device_not_found_or_no_permission(self) -> None:
        """Revoking non-existent device or without permission should return 404."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        # Query returns empty when device not found OR user lacks admin/owner role
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/devices/device-123/revoke")

        self.assertEqual(r.status_code, 404)

    def test_revoke_device_success(self) -> None:
        """Successful device revocation should update revoked_at."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        # Query returns device when user has admin/owner permission
        mock_db.query = mock.Mock(return_value=[{"agent_id": "agent-1", "device_id": "device-123"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/devices/device-123/revoke")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("message", data)
        self.assertEqual(data["device_id"], "device-123")
        # Verify execute was called to update revoked_at
        mock_db.execute.assert_called_once()


class TestDeviceDeletion(unittest.TestCase):
    """Tests for device deletion."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db

    def test_delete_device_requires_authentication(self) -> None:
        """Device deletion should require authentication."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.post("/api/devices/device-123/delete")

        self.assertEqual(r.status_code, 401)

    def test_delete_device_not_found_or_no_permission(self) -> None:
        """Deleting non-existent device or without permission should return 404."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/devices/device-123/delete")

        self.assertEqual(r.status_code, 404)

    def test_delete_device_success(self) -> None:
        """Successful device deletion should remove the device."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[{"agent_id": "agent-1", "device_id": "device-123"}])
        mock_db.execute = mock.Mock()
        self.mod._get_db = mock.Mock(return_value=mock_db)

        r = self.client.post("/api/devices/device-123/delete")

        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("message", data)
        self.assertEqual(data["device_id"], "device-123")
        # Verify execute was called to delete the device
        mock_db.execute.assert_called_once()
        # Verify it was a DELETE statement
        call_args = mock_db.execute.call_args
        self.assertIn("DELETE FROM devices", call_args[0][0])


class TestDevicesPage(unittest.TestCase):
    """Tests for devices page rendering."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_gui_get_user = cls.mod._gui_get_user
        cls._orig_get_db = cls.mod._get_db
        cls._orig_list_agents_for_user = cls.mod.list_agents_for_user
        cls._orig_cfg = cls.mod._cfg

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.app)
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.list_agents_for_user = self.__class__._orig_list_agents_for_user
        self.mod._cfg = self.__class__._orig_cfg

    def tearDown(self) -> None:
        self.mod._gui_get_user = self.__class__._orig_gui_get_user
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.list_agents_for_user = self.__class__._orig_list_agents_for_user
        self.mod._cfg = self.__class__._orig_cfg

    def test_devices_page_requires_authentication(self) -> None:
        """Devices page should redirect to login if not authenticated."""
        self.mod._gui_get_user = mock.Mock(return_value=None)

        r = self.client.get("/devices", follow_redirects=False)

        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("location", ""))

    def test_devices_page_renders_with_devices(self) -> None:
        """Devices page should render device list."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "device_id": "dev-1",
                    "agent_id": "agent-1",
                    "agent_name": "Test Agent",
                    "name": "Kitchen Speaker",
                    "scopes": ["events:write", "presence:write"],
                    "last_seen": None,
                    "revoked_at": None,
                }
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[types.SimpleNamespace(agent_id="agent-1", name="Test Agent", role="owner")]
        )
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/devices")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Kitchen Speaker", r.text)
        self.assertIn("Test Agent", r.text)
        self.assertIn("events:write", r.text)

    def test_devices_page_shows_empty_state(self) -> None:
        """Devices page should show empty state when no devices."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(return_value=[])
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/devices")

        self.assertEqual(r.status_code, 200)
        self.assertIn("No Devices Registered", r.text)

    def test_devices_page_shows_revoked_badge(self) -> None:
        """Devices page should show revoked badge for revoked devices."""
        self.mod._gui_get_user = mock.Mock(
            return_value=self.mod.AuthenticatedUser(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        mock_db = mock.Mock()
        mock_db.query = mock.Mock(
            return_value=[
                {
                    "device_id": "dev-1",
                    "agent_id": "agent-1",
                    "agent_name": "Test Agent",
                    "name": "Old Device",
                    "scopes": [],
                    "last_seen": None,
                    "revoked_at": "2026-01-01T00:00:00Z",
                }
            ]
        )
        self.mod._get_db = mock.Mock(return_value=mock_db)
        self.mod.list_agents_for_user = mock.Mock(return_value=[])
        self.mod._cfg = mock.Mock(stage="dev", ws_api_url=None)

        r = self.client.get("/devices")

        self.assertEqual(r.status_code, 200)
        self.assertIn("Revoked", r.text)
