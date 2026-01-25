from __future__ import annotations

import importlib.util
import dataclasses
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load_hub_api_app_module():
    """Load functions/hub_api/app.py as a module without requiring it be a package."""

    # Make the shared Lambda layer importable in local unit tests.
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    # Ensure boto3 client creation does not fail due to missing region/creds.
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests", app_py)
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

        cls.client = TestClient(cls.mod.app)

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


if __name__ == "__main__":
    unittest.main()
