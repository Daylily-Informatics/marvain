from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    path = REPO_ROOT / "scripts" / "generate_design_objective_status.py"
    spec = importlib.util.spec_from_file_location("generate_design_objective_status_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_design_objective_inventory_covers_phase_0_and_phase_7_surfaces() -> None:
    generator = _load_generator()

    titles = {objective.title for objective in generator.OBJECTIVES}

    assert "Source-of-truth design docs stay checked in" in titles
    assert "Recognition observations, hypotheses, consent, and unknown handling" in titles
    assert "E2E and deployed acceptance surface is explicit" in titles


def test_each_design_objective_maps_to_code_gui_test_or_deployed_evidence() -> None:
    generator = _load_generator()

    for objective in generator.OBJECTIVES:
        kinds = {item.kind for item in objective.evidence}
        assert kinds & {"code", "gui", "test", "deployed"}, objective.objective_id
        assert len(objective.evidence) >= 4, objective.objective_id


def test_minimum_score_gate_passes_at_90() -> None:
    generator = _load_generator()

    status = generator.build_status(REPO_ROOT)

    assert status["score"] >= 90


def test_deployed_smoke_placeholder_cannot_satisfy_completion(tmp_path) -> None:
    generator = _load_generator()
    smoke_dir = tmp_path / "marvain_cli"
    smoke_dir.mkdir()
    (smoke_dir / "smoke.py").write_text(
        "def run_deployed_smoke(*, stack=None, include_two_device_proof=False):\n    return run_local_smoke()\n",
        encoding="utf-8",
    )

    issues = generator.deployed_smoke_placeholder_issues(tmp_path)

    assert any("delegates deployed smoke to local smoke" in issue for issue in issues)
    assert any("does not declare mutating deployed evidence" in issue for issue in issues)


def test_check_command_supports_min_score_gate() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "generate_design_objective_status.py"),
            "--check",
            "--min-score",
            "90",
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_generated_design_objective_status_doc_is_current() -> None:
    generator = _load_generator()

    expected = generator.build_doc(REPO_ROOT, min_score=90)
    actual = (REPO_ROOT / "docs" / "DESIGN_OBJECTIVE_STATUS.generated.md").read_text(encoding="utf-8")

    assert actual == expected
