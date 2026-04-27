from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    path = REPO_ROOT / "scripts" / "generate_capability_matrix.py"
    spec = importlib.util.spec_from_file_location("generate_capability_matrix_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_capability_inventory_uses_required_sources() -> None:
    generator = _load_generator()

    inventory = generator.collect_inventory(REPO_ROOT)

    assert inventory["routes"], "FastAPI route inventory is empty"
    assert inventory["templates"], "Template inventory is empty"
    assert inventory["cli"], "CLI command inventory is empty"
    assert inventory["tools"], "Tool module inventory is empty"
    assert inventory["workers"], "Worker directory inventory is empty"
    assert inventory["sql"], "SQL table inventory is empty"
    assert inventory["tapdb"], "TapDB template code inventory is empty"


def test_major_capability_pages_have_route_or_template_exposure() -> None:
    generator = _load_generator()

    missing = generator.missing_major_page_exposures(REPO_ROOT)

    assert not missing, "Major capability pages lack route/template exposure: " + ", ".join(missing)


def test_capability_matrix_generated_doc_is_current() -> None:
    generator = _load_generator()

    expected = generator.build_doc(REPO_ROOT)
    actual = (REPO_ROOT / "docs" / "CAPABILITY_MATRIX.generated.md").read_text(encoding="utf-8")

    assert actual == expected


def test_capability_matrix_check_fails_when_generated_doc_is_stale(tmp_path, monkeypatch) -> None:
    generator = _load_generator()
    stale_doc = tmp_path / "CAPABILITY_MATRIX.generated.md"
    stale_doc.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(generator, "OUT_FILE", stale_doc)
    monkeypatch.setattr(sys, "argv", ["generate_capability_matrix.py", "--check"])

    assert generator.main() == 1
