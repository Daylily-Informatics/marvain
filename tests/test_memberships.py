from __future__ import annotations

import sys
import unittest

from pathlib import Path

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.memberships import AgentMembership, check_agent_permission, list_agents_for_user


class _FakeDb:
    def __init__(self, *, rows):
        self.rows = rows
        self.last_sql: str | None = None
        self.last_params: dict | None = None

        self._begun: int = 0
        self._committed: list[str] = []
        self._rolled_back: list[str] = []

    def query(self, sql: str, params: dict | None = None, **_kwargs):
        self.last_sql = sql
        self.last_params = params
        return self.rows

    def execute(self, sql: str, params: dict | None = None, **_kwargs):
        self.last_sql = sql
        self.last_params = params
        return {}

    def begin(self) -> str:
        self._begun += 1
        return f"tx-{self._begun}"

    def commit(self, transaction_id: str) -> None:
        self._committed.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self._rolled_back.append(transaction_id)


class TestMemberships(unittest.TestCase):
    def test_list_agents_for_user_queries_memberships(self) -> None:
        db = _FakeDb(
            rows=[
                {
                    "agent_id": "a1",
                    "name": "agent",
                    "disabled": False,
                    "role": "owner",
                    "relationship_label": "close-friend",
                }
            ]
        )

        out = list_agents_for_user(db, user_id="u1")

        self.assertEqual(out, [AgentMembership(agent_id="a1", name="agent", disabled=False, role="owner", relationship_label="close-friend")])
        self.assertIsNotNone(db.last_sql)
        self.assertIn("FROM agent_memberships", db.last_sql or "")
        self.assertIn("JOIN agents", db.last_sql or "")
        self.assertEqual((db.last_params or {}).get("user_id"), "u1")

    def test_check_agent_permission_requires_active_membership(self) -> None:
        # active membership row (get_membership) shape
        db = _FakeDb(rows=[{"role": "member", "relationship_label": None, "active": True}])
        ok = check_agent_permission(db, agent_id="a", user_id="u", required_role="guest")
        self.assertTrue(ok)

        db2 = _FakeDb(rows=[{"role": "member", "relationship_label": None, "active": False}])
        ok2 = check_agent_permission(db2, agent_id="a", user_id="u", required_role="guest")
        self.assertFalse(ok2)

    def test_check_agent_permission_blocks_blocked_role(self) -> None:
        db = _FakeDb(rows=[{"role": "blocked", "relationship_label": None, "active": True}])
        self.assertFalse(check_agent_permission(db, agent_id="a", user_id="u", required_role="guest"))


if __name__ == "__main__":
    unittest.main()

