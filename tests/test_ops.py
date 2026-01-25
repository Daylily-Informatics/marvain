from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

from marvain_cli.config import ResolvedEnv
from marvain_cli.ops import Ctx, _split_sql, bootstrap, sam_logs


class TestOps(unittest.TestCase):
    def test_split_sql_ignores_comment_lines_and_splits(self) -> None:
        sql = """-- comment\nCREATE TABLE a(x int);\n\n-- another\nCREATE TABLE b(y int);"""
        stmts = _split_sql(sql)
        self.assertEqual(len(stmts), 2)
        self.assertTrue(stmts[0].startswith("CREATE TABLE a"))
        self.assertTrue(stmts[1].startswith("CREATE TABLE b"))

    def test_bootstrap_casts_uuid_params_for_rds_data_api(self) -> None:
        captured_sql: list[str] = []

        def fake_rds_execute(*_args, **kwargs):
            captured_sql.append(str(kwargs.get("sql")))
            idx = len(captured_sql)
            if idx == 1:
                v = "11111111-1111-1111-1111-111111111111"
            elif idx == 2:
                v = "22222222-2222-2222-2222-222222222222"
            else:
                v = "33333333-3333-3333-3333-333333333333"
            return {"records": [[{"stringValue": v}]]}

        cfg = {"envs": {"dev": {"bootstrap": {}}}}
        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg=cfg,
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with (
            mock.patch("marvain_cli.ops._conda_preflight", return_value=0),
            mock.patch("marvain_cli.ops._db_outputs", return_value=("db", "sec", "name")),
            mock.patch("marvain_cli.ops._rds_execute", side_effect=fake_rds_execute),
            mock.patch("marvain_cli.ops._eprint"),
            mock.patch("marvain_cli.ops.save_config_dict"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            rc = bootstrap(
                ctx,
                dry_run=False,
                agent_name="Forge",
                space_name="home",
                device_name="dev",
                force=False,
            )

        self.assertEqual(rc, 0)
        self.assertTrue(any("INSERT INTO spaces" in s and "CAST(:a AS uuid)" in s for s in captured_sql))
        self.assertTrue(any("INSERT INTO devices" in s and "CAST(:a AS uuid)" in s for s in captured_sql))

    def test_sam_logs_since_uses_start_time_flag(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._conda_preflight", return_value=0), mock.patch("marvain_cli.ops._eprint", side_effect=cap):
            rc = sam_logs(ctx, dry_run=True, functions=["HubApiFunction"], tail=False, since="10m")
        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn(" sam logs ", joined)
        self.assertIn(" -s ", joined)
        self.assertIn("10min ago", joined)
        self.assertNotIn("--since", joined)


    def test_sam_logs_default_dry_run_does_not_use_name_flag(self) -> None:
        emitted: list[str] = []

        def cap(msg: str) -> None:
            emitted.append(msg)

        ctx = Ctx(
            config_path=Path("/tmp/marvain.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

        with mock.patch("marvain_cli.ops._conda_preflight", return_value=0), mock.patch(
            "marvain_cli.ops._eprint", side_effect=cap
        ):
            rc = sam_logs(ctx, dry_run=True, functions=None, tail=False, since=None)
        self.assertEqual(rc, 0)
        joined = "\n".join(emitted)
        self.assertIn(" sam logs ", joined)
        self.assertNotIn("--name", joined)


if __name__ == "__main__":
    unittest.main()