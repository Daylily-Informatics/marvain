from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from marvain_cli.config import ConfigError, load_config_dict, resolve_env
from marvain_cli.config import dump_simple_yaml


class TestConfigLoader(unittest.TestCase):
    def test_simple_yaml_parser_roundtrip(self) -> None:
        txt = (
            "version: 1\n"
            "default_env: dev\n"
            "envs:\n"
            "  dev:\n"
            "    aws_profile: \"p1\"\n"
            "    aws_region: us-west-2\n"
            "    stack_name: marvain-u-dev\n"
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "marvain-config.yaml"
            p.write_text(txt, encoding="utf-8")
            cfg = load_config_dict(p)
            self.assertEqual(cfg["version"], 1)
            resolved = resolve_env(cfg, env="dev", profile_override=None, region_override=None, stack_override=None)
            self.assertEqual(resolved.aws_profile, "p1")
            self.assertEqual(resolved.aws_region, "us-west-2")
            self.assertEqual(resolved.stack_name, "marvain-u-dev")

    def test_simple_yaml_dump_roundtrip_subset(self) -> None:
        cfg = {
            "version": 1,
            "default_env": "dev",
            "envs": {
                "dev": {
                    "aws_profile": "p1",
                    "aws_region": "us-west-2",
                    "stack_name": "marvain-u-dev",
                    "sam": {"template": "template.yaml", "capabilities": ["CAPABILITY_IAM"], "parameter_overrides": {}},
                    "resources": {},
                    "bootstrap": {"agent_id": None, "device_token": "tok"},
                }
            },
        }
        txt = dump_simple_yaml(cfg)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "marvain-config.yaml"
            p.write_text(txt, encoding="utf-8")
            cfg2 = load_config_dict(p)
            self.assertEqual(cfg2["version"], 1)
            self.assertEqual(cfg2["envs"]["dev"]["aws_profile"], "p1")

    def test_reject_default_profile(self) -> None:
        cfg = {
            "default_env": "dev",
            "envs": {"dev": {"aws_profile": "default", "aws_region": "us-west-2", "stack_name": "x"}},
        }
        with self.assertRaises(ConfigError):
            resolve_env(cfg, env="dev", profile_override=None, region_override=None, stack_override=None)

    def test_allow_profile_override(self) -> None:
        cfg = {
            "default_env": "dev",
            "envs": {"dev": {"aws_profile": "p1", "aws_region": "us-west-2", "stack_name": "x"}},
        }
        resolved = resolve_env(cfg, env="dev", profile_override="p2", region_override=None, stack_override=None)
        self.assertEqual(resolved.aws_profile, "p2")

    def test_env_var_override_documented(self) -> None:
        cfg = {
            "default_env": "dev",
            "envs": {"dev": {"aws_profile": "p1", "aws_region": "us-west-2", "stack_name": "x"}},
        }
        old = os.environ.get("AWS_PROFILE")
        try:
            os.environ["AWS_PROFILE"] = "p3"
            resolved = resolve_env(cfg, env="dev", profile_override=None, region_override=None, stack_override=None)
            self.assertEqual(resolved.aws_profile, "p1", "config should win over env var when set")
        finally:
            if old is None:
                os.environ.pop("AWS_PROFILE", None)
            else:
                os.environ["AWS_PROFILE"] = old


if __name__ == "__main__":
    unittest.main()
