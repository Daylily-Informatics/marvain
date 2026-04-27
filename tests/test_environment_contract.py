from __future__ import annotations

import os
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_root_activation_contract_replaces_old_wrapper_files() -> None:
    activate = REPO_ROOT / "activate"

    assert activate.exists()
    assert os.access(activate, os.X_OK)
    assert (REPO_ROOT / "environment.yaml").exists()
    assert not (REPO_ROOT / "marvain_activate").exists()
    assert not (REPO_ROOT / "config" / "marvain_conda.yaml").exists()
    assert not (REPO_ROOT / "bin" / "marvain").exists()


def test_activate_stays_minimal_and_environment_owns_only_conda_dependencies() -> None:
    activate_text = (REPO_ROOT / "activate").read_text(encoding="utf-8")
    env_text = (REPO_ROOT / "environment.yaml").read_text(encoding="utf-8")

    assert "Usage: source ./activate" in activate_text
    assert "MARVAIN_REPO_ROOT" in activate_text
    assert "conda env create -n marvain -f" in activate_text
    assert "MARVAIN_REPO_CFG" not in activate_text
    assert "COMPLETE" not in activate_text
    assert "PATH=" not in activate_text
    assert "pip:" not in env_text
    assert "daylily-auth-cognito" not in env_text
    assert "daylily-tapdb" not in env_text
    assert "cli-core-yo" not in env_text


def test_pyproject_owns_python_dependencies_and_console_script() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    dependencies = set(pyproject["project"]["dependencies"])
    assert "cli-core-yo==2.1.1" in dependencies
    assert "daylily-auth-cognito==2.1.4" in dependencies
    assert "daylily-tapdb[admin]==6.0.7" in dependencies
    assert pyproject["project"]["scripts"]["marvain"] == "marvain_cli.__main__:main"
    assert pyproject["tool"]["marvain"]["conda_file"] == "environment.yaml"


def test_active_files_do_not_reference_obsolete_activation_or_bin_wrapper() -> None:
    active_paths = [
        REPO_ROOT / "AGENTS.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "QUICKSTART.md",
        REPO_ROOT / "QUICKSTART_GUI.md",
        REPO_ROOT / "bin" / "init_setup.sh",
        REPO_ROOT / "functions" / "hub_api" / "start_server.sh",
        REPO_ROOT / "functions" / "hub_api" / "templates" / "profile.html",
        REPO_ROOT / "functions" / "hub_api" / "templates" / "device_detail.html",
        REPO_ROOT / "scripts" / "nuke_dev.sh",
    ]
    obsolete = [
        "marvain_activate",
        "config/marvain_conda.yaml",
        "./bin/marvain",
        "MARVAIN_ALLOW_VENV",
    ]

    for path in active_paths:
        text = path.read_text(encoding="utf-8")
        for needle in obsolete:
            assert needle not in text, f"{needle!r} remains in {path.relative_to(REPO_ROOT)}"
