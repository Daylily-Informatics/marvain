from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

from cli_core_yo.conformance import assert_exit_code, invoke


class TestCliCoreSmoke(unittest.TestCase):
    def test_help_version_and_build_dry_run_do_not_crash(self) -> None:
        from marvain_cli import cli

        with tempfile.TemporaryDirectory() as tmpdir:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = tmpdir
            os.environ["XDG_CONFIG_HOME"] = os.path.join(tmpdir, ".config")
            try:
                os.chdir(tmpdir)
                app = cli.build_app()

                assert_exit_code(invoke(app, ["--help"], prog_name="marvain"), 0)
                assert_exit_code(invoke(app, ["version"], prog_name="marvain"), 0)
                assert_exit_code(invoke(app, ["env", "status"], prog_name="marvain"), 0)
                assert_exit_code(invoke(app, ["runtime", "status"], prog_name="marvain"), 0)
                assert_exit_code(invoke(app, ["--dry-run", "build"], prog_name="marvain"), 0)
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_xdg is None:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                else:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg

    def test_missing_config_returns_nonzero_for_config_required_commands(self) -> None:
        from marvain_cli import cli

        with tempfile.TemporaryDirectory() as tmpdir:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = tmpdir
            os.environ["XDG_CONFIG_HOME"] = os.path.join(tmpdir, ".config")
            try:
                os.chdir(tmpdir)
                app = cli.build_app()

                assert_exit_code(invoke(app, ["gui", "--help"], prog_name="marvain"), 0)

                deploy = invoke(app, ["--dry-run", "deploy"], prog_name="marvain")
                bootstrap = invoke(
                    app,
                    ["--dry-run", "bootstrap", "--space-name", "home"],
                    prog_name="marvain",
                )

                self.assertNotEqual(deploy.exit_code, 0)
                self.assertNotEqual(bootstrap.exit_code, 0)
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_xdg is None:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                else:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg

    def test_test_command_invokes_pytest(self) -> None:
        from marvain_cli import cli

        with tempfile.TemporaryDirectory() as tmpdir:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = tmpdir
            os.environ["XDG_CONFIG_HOME"] = os.path.join(tmpdir, ".config")
            try:
                os.chdir(tmpdir)
                app = cli.build_app()
                with mock.patch("marvain_cli.commands.subprocess.call", return_value=0) as call_mock:
                    assert_exit_code(invoke(app, ["test"], prog_name="marvain"), 0)

                cmd = call_mock.call_args.args[0]
                cwd = call_mock.call_args.kwargs["cwd"]
                env = call_mock.call_args.kwargs["env"]
                self.assertEqual(cmd, [sys.executable, "-m", "pytest"])
                self.assertTrue(cwd.endswith("/marvain"))
                self.assertIn("layers/shared/python", env["PYTHONPATH"])
            finally:
                os.chdir(old_cwd)
                if old_home is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old_home
                if old_xdg is None:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                else:
                    os.environ["XDG_CONFIG_HOME"] = old_xdg

    def test_runtime_guard_requires_activation_marker(self) -> None:
        from marvain_cli import cli

        app = cli.build_app()
        with mock.patch.dict(os.environ, {"MARVAIN_ACTIVE": ""}, clear=False):
            result = invoke(app, ["--dry-run", "build"], prog_name="marvain")

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Runtime validation failed", result.output)

    def test_cli_uses_cli_core_pattern_without_local_typer_shim(self) -> None:
        from pathlib import Path

        from marvain_cli import cli

        repo_root = Path(__file__).resolve().parents[1]
        pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
        commands_text = (repo_root / "marvain_cli" / "commands.py").read_text(encoding="utf-8")

        self.assertNotIn('"typer",', pyproject_text)
        self.assertIn("from typer import Argument, Exit, Option, confirm", commands_text)
        self.assertIsNotNone(cli.spec.env)
        self.assertIsNotNone(cli.spec.runtime)
        self.assertEqual(cli.spec.runtime.guard_mode, "enforced")
        self.assertFalse(cli.spec.runtime.allow_skip_check)
        self.assertFalse((repo_root / "marvain_cli" / "cli_primitives.py").exists())

    def test_project_uses_scm_versioning(self) -> None:
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[1]
        pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('dynamic = ["version"]', pyproject_text)
        self.assertIn("[tool.setuptools_scm]", pyproject_text)
        self.assertNotIn('version = "0.3.11"', pyproject_text)


if __name__ == "__main__":
    unittest.main()
