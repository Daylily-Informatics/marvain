from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout


class TestTyperSmoke(unittest.TestCase):
    def test_typer_help_and_build_dry_run_do_not_crash(self) -> None:
        try:
            from marvain_cli import typer_app
        except ModuleNotFoundError:
            # Typer/Click not installed; that's an allowed mode (argparse fallback).
            self.skipTest("typer not installed")

        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = td
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, ".config")
            try:
                # Ensure repo-local marvain.yaml (if present) does not affect this test.
                os.chdir(td)
                out = io.StringIO()
                err = io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc_help = typer_app.run(["--help"])
                    rc_version = typer_app.run(["--version"])
                    rc_build = typer_app.run(["--dry-run", "build"])
                    rc_build2 = typer_app.run(["build", "--dry-run"])
                self.assertEqual(rc_help, 0)
                self.assertEqual(rc_version, 0)
                self.assertEqual(rc_build, 0)
                self.assertEqual(rc_build2, 0)
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
        try:
            from marvain_cli import typer_app
        except ModuleNotFoundError:
            # Typer/Click not installed; that's an allowed mode (argparse fallback).
            self.skipTest("typer not installed")

        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = td
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, ".config")
            try:
                # Ensure repo-local marvain.yaml (if present) does not affect this test.
                os.chdir(td)
                out = io.StringIO()
                err = io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    # Help should work without config.
                    rc_gui_help = typer_app.run(["gui", "--help"])

                    # These should require config (even if --dry-run is set).
                    rc_deploy_dry = typer_app.run(["deploy", "--dry-run"])
                    rc_bootstrap_dry = typer_app.run(["bootstrap", "--dry-run", "--space-name", "home"])

                self.assertEqual(rc_gui_help, 0)
                self.assertNotEqual(rc_deploy_dry, 0)
                self.assertNotEqual(rc_bootstrap_dry, 0)
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


if __name__ == "__main__":
    unittest.main()
