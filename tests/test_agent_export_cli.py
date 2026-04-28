from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cli_core_yo.conformance import assert_exit_code, invoke

from marvain_cli.config import ResolvedEnv
from marvain_cli.ops import Ctx, agent_export


def _rds_value(value: object) -> dict[str, object]:
    if value is None:
        return {"isNull": True}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"longValue": value}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def _rds_result(rows: list[dict[str, object]]) -> dict[str, object]:
    names = list(rows[0].keys()) if rows else ["empty"]
    return {
        "columnMetadata": [{"name": name} for name in names],
        "records": [[_rds_value(row.get(name)) for name in names] for row in rows],
    }


class TestAgentExportOps(unittest.TestCase):
    def _ctx(self) -> Ctx:
        return Ctx(
            config_path=Path("/tmp/marvain-config.yaml"),
            cfg={"envs": {"dev": {}}},
            env=ResolvedEnv(env="dev", aws_profile="p", aws_region="r", stack_name="s", raw={}),
        )

    def test_agent_export_includes_defining_records_and_secret_references_only(self) -> None:
        agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        stack_outputs = {
            "DbClusterArn": "arn:aws:rds:us-east-1:123456789012:cluster:db",
            "DbSecretArn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db",
            "DbName": "marvain",
            "OpenAISecretArn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:openai",
        }

        def fake_rds_execute(*_args, **kwargs):
            sql = str(kwargs["sql"])
            if "FROM agents" in sql:
                return _rds_result(
                    [
                        {
                            "agent_id": agent_id,
                            "name": "Forge",
                            "disabled": False,
                            "lifecycle_state": "active",
                            "maturity_state": "mature",
                            "maturity_evidence_json": '{"checks":["constitution"]}',
                        }
                    ]
                )
            if "FROM personas" in sql:
                return _rds_result(
                    [
                        {
                            "persona_id": "persona-1",
                            "agent_id": agent_id,
                            "name": "Default",
                            "instructions": "Be useful.",
                            "is_default": True,
                            "lifecycle_state": "active",
                        }
                    ]
                )
            if "FROM devices" in sql:
                self.assertNotIn("token_hash", sql)
                return _rds_result(
                    [
                        {
                            "device_id": "device-1",
                            "agent_id": agent_id,
                            "name": "worker",
                            "capabilities_json": '{"kind":"worker"}',
                            "scopes_json": '["events:read"]',
                            "metadata_json": "{}",
                        }
                    ]
                )
            if "FROM integration_accounts" in sql:
                return _rds_result(
                    [
                        {
                            "integration_account_id": "integration-1",
                            "agent_id": agent_id,
                            "provider": "slack",
                            "display_name": "Slack",
                            "credentials_secret_arn": ("arn:aws:secretsmanager:us-east-1:123456789012:secret:slack"),
                            "scopes_json": '["chat:write"]',
                            "config_json": '{"channel":"ops"}',
                            "status": "active",
                        }
                    ]
                )
            if "FROM agent_tokens" in sql:
                self.assertNotIn("token_hash", sql)
                return _rds_result(
                    [
                        {
                            "token_id": "token-1",
                            "issuer_agent_id": agent_id,
                            "name": "delegate",
                            "scopes_json": '["read_memories"]',
                            "allowed_spaces_json": None,
                        }
                    ]
                )
            return _rds_result([])

        with (
            mock.patch("marvain_cli.ops.aws_stack_outputs", return_value=stack_outputs),
            mock.patch("marvain_cli.ops._rds_execute", side_effect=fake_rds_execute),
        ):
            data = agent_export(self._ctx(), agent_id=agent_id, dry_run=False)

        self.assertEqual(data["schema"], "marvain.agent_export.v1")
        self.assertEqual(data["records"]["agent"]["maturity_evidence"], {"checks": ["constitution"]})
        self.assertEqual(data["records"]["devices"][0]["capabilities"], {"kind": "worker"})
        self.assertEqual(data["records"]["agent_tokens"][0]["scopes"], ["read_memories"])
        self.assertEqual(
            data["secret_references"]["stack_outputs"]["OpenAISecretArn"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:openai",
        )
        self.assertEqual(
            data["secret_references"]["integration_accounts"][0]["credentials_secret_arn"],
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:slack",
        )
        encoded = json.dumps(data, sort_keys=True)
        self.assertNotIn('"device_token"', encoded)
        self.assertNotIn('"token_hash"', encoded)
        self.assertNotIn("secret-value", encoded)
        for required_section in (
            "actions",
            "artifact_references",
            "audit_state",
            "events",
            "memory_annotations",
            "memory_candidates",
            "memory_opinions",
            "memories",
            "people",
            "presence_assertions",
            "recognition_hypotheses",
            "recognition_observations",
            "sessions",
        ):
            self.assertIn(required_section, data["records"])
            self.assertIn(required_section, data["contract"]["includes"])
            self.assertNotIn(required_section, data["contract"]["excludes"])
        self.assertEqual(
            data["contract"]["tapdb_subgraph_manifest"]["dag_endpoint"], "/api/dag/data?start_euid={tapdb_euid}&depth=8"
        )


class TestAgentExportCli(unittest.TestCase):
    def test_agent_export_uses_root_json_mode(self) -> None:
        from marvain_cli import cli

        payload = {
            "schema": "marvain.agent_export.v1",
            "agent_id": "agent-1",
            "records": {"agent": {"agent_id": "agent-1"}},
            "checksum": "abc123",
        }
        app = cli.build_app()
        with (
            mock.patch("marvain_cli.commands._load", return_value=object()),
            mock.patch("marvain_cli.commands.agent_export", return_value=payload) as export_mock,
        ):
            result = invoke(app, ["--json", "agent", "export", "--agent-id", "agent-1"], prog_name="marvain")

        assert_exit_code(result, 0)
        self.assertEqual(json.loads(result.output), payload)
        export_mock.assert_called_once_with(mock.ANY, agent_id="agent-1", dry_run=False)

    def test_agent_export_help_has_no_command_json_option(self) -> None:
        from marvain_cli import cli

        result = invoke(cli.build_app(), ["agent", "export", "--help"], prog_name="marvain")
        assert_exit_code(result, 0)
        self.assertNotIn("--json", result.output)
        self.assertNotIn("--format", result.output)

    def test_agent_export_output_file_fails_when_target_exists(self) -> None:
        from marvain_cli import cli

        with tempfile.TemporaryDirectory() as td:
            output_path = Path(td) / "agent-export.json"
            output_path.write_text("existing\n", encoding="utf-8")
            with (
                mock.patch("marvain_cli.commands._load", return_value=object()),
                mock.patch("marvain_cli.commands.agent_export", return_value={"agent_id": "agent-1"}),
            ):
                result = invoke(
                    cli.build_app(),
                    ["agent", "export", "--agent-id", "agent-1", "--output", str(output_path)],
                    prog_name="marvain",
                )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Output path already exists", result.output)


if __name__ == "__main__":
    unittest.main()
