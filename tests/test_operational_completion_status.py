from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    path = REPO_ROOT / "scripts" / "generate_operational_completion_status.py"
    spec = importlib.util.spec_from_file_location("generate_operational_completion_status_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_ledger_tracks_exactly_85_unique_capabilities() -> None:
    generator = _load_generator()
    rows = generator.parse_capability_ledger()

    assert len(rows) == 85
    assert len({row.capability_id for row in rows}) == 85


def test_current_manifest_validates_and_scores_49() -> None:
    generator = _load_generator()
    rows = generator.parse_capability_ledger()
    manifest = generator.build_baseline_manifest(rows)

    assert generator.validate(rows, manifest) == []
    assert generator.operational_score(rows, manifest) == 49


def test_evidence_caps_prevent_unsupported_scores() -> None:
    generator = _load_generator()
    record = {"evidence": {key: [] for key in generator.EVIDENCE_CLASSES}}
    assert generator.evidence_cap(record) == 49

    record["evidence"]["implementation"] = ["tests/proof.py"]
    assert generator.evidence_cap(record) == 74
    record["evidence"]["local_workflow"] = ["output/local.json"]
    assert generator.evidence_cap(record) == 84
    record["evidence"]["integration"] = ["output/browser.json"]
    assert generator.evidence_cap(record) == 94
    record["evidence"]["deployed"] = ["docs/reports/acceptance.json"]
    assert generator.evidence_cap(record) == 99
    for key in ("failure_recovery", "observability", "documentation", "regression"):
        record["evidence"][key] = [f"evidence/{key}.json"]
    assert generator.evidence_cap(record) == 100


def test_generated_operational_status_is_current() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate_operational_completion_status.py"),
            "--check",
            "--require-score",
            "47",
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_all_100_gate_rejects_baseline() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate_operational_completion_status.py"),
            "--check",
            "--require-all-100",
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 1
    assert "Not all 85 capability rows" in result.stderr
