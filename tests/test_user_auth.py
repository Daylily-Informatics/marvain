from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.auth import AuthenticatedUser, authenticate_user_access_token  # noqa: E402


class _FakeDb:
    def __init__(self, *, user_id: str):
        self.user_id = user_id
        self.last_sql: str | None = None
        self.last_params: dict | None = None

    def query(self, sql: str, params: dict | None = None, **_kwargs):
        self.last_sql = sql
        self.last_params = params
        return [{"user_id": self.user_id}]


class _FakeCognito:
    def __init__(self, resp):
        self.resp = resp
        self.last_access_token: str | None = None

    def get_user(self, *, AccessToken: str):
        self.last_access_token = AccessToken
        return self.resp


class TestUserAuth(unittest.TestCase):
    def test_authenticate_user_access_token_uses_sub_and_email(self) -> None:
        fake_db = _FakeDb(user_id="u1")
        fake_cog = _FakeCognito(
            {
                "Username": "ignored",
                "UserAttributes": [
                    {"Name": "sub", "Value": "sub-123"},
                    {"Name": "email", "Value": "me@example.com"},
                ],
            }
        )

        with mock.patch("agent_hub.auth._boto3_client", return_value=fake_cog):
            u = authenticate_user_access_token(fake_db, "atk")

        self.assertIsInstance(u, AuthenticatedUser)
        self.assertEqual(u.user_id, "u1")
        self.assertEqual(u.cognito_sub, "sub-123")
        self.assertEqual(u.email, "me@example.com")
        self.assertEqual(fake_cog.last_access_token, "atk")
        self.assertIsNotNone(fake_db.last_sql)
        self.assertIn("INSERT INTO users", fake_db.last_sql or "")
        self.assertIn("ON CONFLICT", fake_db.last_sql or "")
        self.assertEqual((fake_db.last_params or {}).get("sub"), "sub-123")
        self.assertEqual((fake_db.last_params or {}).get("email"), "me@example.com")

    def test_authenticate_user_access_token_falls_back_to_username(self) -> None:
        fake_db = _FakeDb(user_id="u2")
        fake_cog = _FakeCognito({"Username": "userpool-username", "UserAttributes": []})

        with mock.patch("agent_hub.auth._boto3_client", return_value=fake_cog):
            u = authenticate_user_access_token(fake_db, "atk")

        self.assertEqual(u.user_id, "u2")
        self.assertEqual(u.cognito_sub, "userpool-username")
        self.assertIsNone(u.email)


if __name__ == "__main__":
    unittest.main()
