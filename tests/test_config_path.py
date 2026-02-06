from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from marvain_cli.config import find_config_path


class TestFindConfigPath(unittest.TestCase):
    def test_prefers_xdg_user_config(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = td
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, ".config")
            try:
                os.chdir(td)
                # Test the new canonical config path
                cfg = Path(os.environ["XDG_CONFIG_HOME"]) / "marvain" / "marvain-config.yaml"
                cfg.parent.mkdir(parents=True, exist_ok=True)
                cfg.write_text("version: 1\n", encoding="utf-8")
                p = find_config_path(None)
                self.assertIsNotNone(p)
                self.assertEqual(Path(p), cfg.resolve())
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

    def test_repo_local_overrides_xdg(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            old_home = os.environ.get("HOME")
            old_xdg = os.environ.get("XDG_CONFIG_HOME")
            old_cwd = os.getcwd()
            os.environ["HOME"] = td
            os.environ["XDG_CONFIG_HOME"] = os.path.join(td, ".config")
            try:
                os.chdir(td)
                # XDG config uses canonical path; repo-local marvain.yaml still overrides
                xdg_cfg = Path(os.environ["XDG_CONFIG_HOME"]) / "marvain" / "marvain-config.yaml"
                xdg_cfg.parent.mkdir(parents=True, exist_ok=True)
                xdg_cfg.write_text("version: 1\n", encoding="utf-8")
                repo_cfg = Path(td) / "marvain.yaml"
                repo_cfg.write_text("version: 1\n", encoding="utf-8")
                p = find_config_path(None)
                self.assertEqual(Path(p), repo_cfg.resolve())
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
