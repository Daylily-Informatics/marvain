from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


def _load_hub_api_app_module():
    """Load functions/hub_api/app.py as a module without requiring it be a package."""

    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    app_py = repo_root / "functions" / "hub_api" / "app.py"
    spec = importlib.util.spec_from_file_location("hub_api_app_for_tests_livekit", app_py)
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

        cls.client = TestClient(cls.mod.app)

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
        r = self.client.post(
            "/v1/livekit/token",
            headers={"Authorization": "Bearer tok"},
            json={"space_id": "space-1"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["url"], "wss://livekit.example")
        self.assertEqual(body["token"], "jwt")
        self.assertEqual(body["room"], "space-1")
        self.assertEqual(body["identity"], "user:u1")


if __name__ == "__main__":
    unittest.main()
