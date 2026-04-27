from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_status_generator():
    path = REPO_ROOT / "scripts" / "generate_design_objective_status.py"
    spec = importlib.util.spec_from_file_location("generate_design_objective_status_for_purity_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_no_obsolete_architecture_paths_remain() -> None:
    generator = _load_status_generator()

    assert generator.architecture_purity_issues(REPO_ROOT) == []


def test_tapdb_schema_is_not_copied_into_marvain() -> None:
    assert not (REPO_ROOT / "layers" / "shared" / "tapdb_schema").exists()


def test_obsolete_archive_tree_is_absent() -> None:
    assert not (REPO_ROOT / "archive").exists()
