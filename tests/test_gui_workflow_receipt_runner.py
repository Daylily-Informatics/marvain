from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts" / "run_gui_workflow_receipt.py"
PNG = b"\x89PNG\r\n\x1a\nfixture"


def _load_runner():
    spec = importlib.util.spec_from_file_location("marvain_gui_workflow_receipt_for_tests", RUNNER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_coverage_generator():
    path = ROOT / "scripts" / "generate_route_coverage.py"
    spec = importlib.util.spec_from_file_location("marvain_route_coverage_for_gui_receipt_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest() -> dict:
    return {
        "schema": "marvain.gui-workflows.v1",
        "screenshot_phases": ["before", "before_submit", "after_submit"],
        "workflows": [
            {
                "id": "widgets-create",
                "page": "widgets",
                "path": "/widgets",
                "heading": "Widgets",
                "command": "create a widget",
                "browser_steps": ["open create", "submit widget"],
                "persisted_postcondition": {
                    "owner": "widget-service",
                    "request": "GET /v1/widgets/{widget_id}",
                    "assert": ["stored name equals submitted name"],
                },
            }
        ],
    }


def _evidence(runner, tmp_path: Path, *, commit: str = "a" * 40) -> dict:
    runner.ROOT = tmp_path
    screenshots = {}
    for phase in ("before", "before_submit", "after_submit"):
        path = tmp_path / f"{phase}.png"
        path.write_bytes(PNG)
        screenshots[phase] = str(path.relative_to(runner.ROOT))
    return {
        "schema": runner.GUIDE_EVIDENCE_SCHEMA,
        "status": "passed",
        "runner": "playwright",
        "run_id": "gui-run-1",
        "environment": "local",
        "service_commit": commit,
        "report_path": "output/playwright/gui-run-1/GUI_SMOKE_REPORT.md",
        "workflows": [
            {
                "id": "widgets-create",
                "status": "passed",
                "test_nodeid": runner.PLAYWRIGHT_TEST_NODEID,
                "steps": [
                    {"name": "open create", "status": "passed"},
                    {"name": "submit widget", "status": "passed"},
                ],
                "persisted_postcondition": {
                    "status": "passed",
                    "owner": "widget-service",
                    "request": "GET /v1/widgets/{widget_id}",
                    "resolved_request": "GET /v1/widgets/widget-1",
                    "record_ids": {"widget_id": "widget-1"},
                    "assertions": [
                        {
                            "description": "stored name equals submitted name",
                            "status": "passed",
                            "evidence": "widget-1 persisted with the submitted name",
                        }
                    ],
                },
                "screenshots": screenshots,
            }
        ],
    }


def test_build_receipt_accepts_executed_same_commit_owner_proof(tmp_path: Path) -> None:
    runner = _load_runner()
    evidence = _evidence(runner, tmp_path)

    receipt = runner.build_receipt(
        manifest=_manifest(),
        evidence=evidence,
        source_commit="a" * 40,
        command="python -m pytest tests/e2e/test_gui_workflow_receipt_playwright.py",
        completed_at="2026-07-11T00:00:00Z",
    )

    assert receipt["schema"] == "marvain.gui-workflow-receipt.v1"
    assert receipt["source_commit"] == "a" * 40
    assert receipt["status"] == "passed"
    assert receipt["workflows"][0]["persisted_postcondition"]["record_ids"] == {"widget_id": "widget-1"}


def test_build_receipt_rejects_service_commit_mismatch(tmp_path: Path) -> None:
    runner = _load_runner()
    evidence = _evidence(runner, tmp_path, commit="b" * 40)

    with pytest.raises(runner.ReceiptError, match="same-commit Playwright proof"):
        runner.build_receipt(
            manifest=_manifest(),
            evidence=evidence,
            source_commit="a" * 40,
            command="python -m pytest tests/e2e/test_gui_workflow_receipt_playwright.py",
            completed_at="2026-07-11T00:00:00Z",
        )


def test_build_receipt_rejects_unproven_owner_assertion(tmp_path: Path) -> None:
    runner = _load_runner()
    evidence = _evidence(runner, tmp_path)
    evidence["workflows"][0]["persisted_postcondition"]["assertions"][0]["evidence"] = ""

    with pytest.raises(runner.ReceiptError, match="did not prove every manifest assertion"):
        runner.build_receipt(
            manifest=_manifest(),
            evidence=evidence,
            source_commit="a" * 40,
            command="python -m pytest tests/e2e/test_gui_workflow_receipt_playwright.py",
            completed_at="2026-07-11T00:00:00Z",
        )


def test_build_receipt_rejects_missing_screenshot(tmp_path: Path) -> None:
    runner = _load_runner()
    evidence = _evidence(runner, tmp_path)
    Path(runner.ROOT / evidence["workflows"][0]["screenshots"]["after_submit"]).unlink()

    with pytest.raises(runner.ReceiptError, match="missing valid after_submit screenshot"):
        runner.build_receipt(
            manifest=_manifest(),
            evidence=evidence,
            source_commit="a" * 40,
            command="python -m pytest tests/e2e/test_gui_workflow_receipt_playwright.py",
            completed_at="2026-07-11T00:00:00Z",
        )


def test_resolved_bindings_require_manifest_shaped_owner_request() -> None:
    runner = _load_runner()
    assert runner._resolved_bindings(
        "GET /v1/widgets/{widget_id}",
        "GET /v1/widgets/widget-1",
        run_id="gui-run-1",
    ) == {"widget_id": "widget-1"}

    with pytest.raises(runner.ReceiptError, match="does not match manifest request"):
        runner._resolved_bindings(
            "GET /v1/widgets/{widget_id}",
            "GET /v1/other/widget-1",
            run_id="gui-run-1",
        )


def test_receipt_is_accepted_by_route_coverage_collector(tmp_path: Path) -> None:
    runner = _load_runner()
    coverage = _load_coverage_generator()
    manifest = _manifest()
    evidence = _evidence(runner, tmp_path)
    receipt = runner.build_receipt(
        manifest=manifest,
        evidence=evidence,
        source_commit="a" * 40,
        command="python -m pytest tests/e2e/test_gui_workflow_receipt_playwright.py",
        completed_at="2026-07-11T00:00:00Z",
    )

    manifest_path = tmp_path / "tests" / "e2e" / "gui_workflow_manifest.json"
    test_path = tmp_path / "tests" / "e2e" / "test_gui_workflow_receipt_playwright.py"
    receipt_path = tmp_path / "output" / "playwright" / "workflow_receipt.json"
    manifest_path.parent.mkdir(parents=True)
    receipt_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    test_path.write_text(
        "def test_gui_workflow_receipt_against_configured_service():\n    run_gui_smoke_guide()\n",
        encoding="utf-8",
    )
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = coverage.collect_playwright_workflow_coverage(
        tmp_path,
        expected_commit="a" * 40,
        required_workflows=(("widgets-create", "/widgets"),),
    )

    assert result.percent == 100
    assert result.covered == 1
    assert result.missing == ()
    assert result.issues == ()


def test_smoke_guide_result_requires_owner_evidence_and_real_screenshots(tmp_path: Path) -> None:
    runner = _load_runner()
    runner.ROOT = tmp_path
    run_dir = tmp_path / "output" / "playwright" / "gui-run-1"
    workflow_dir = run_dir / "widgets-create"
    workflow_dir.mkdir(parents=True)
    for phase in ("before", "before_submit", "after_submit"):
        (workflow_dir / f"{phase}.png").write_bytes(PNG)
    report_path = run_dir / "GUI_SMOKE_REPORT.md"
    report_path.write_text(
        """# Marvain GUI Smoke Guide

- Run ID: `gui-run-1`
- Result: `PASS`

## Page Walkthrough

### 1. widgets-create on widgets `/widgets`

Status: `PASS`

Browser steps:
1. open create
2. submit widget

Persisted postcondition:
- Owner: `widget-service`
- Request: `GET /v1/widgets/{widget_id}`

Execution:
- Resolved owner request: `GET /v1/widgets/widget-1`
- Owner evidence: stored name equals submitted name: widget-1 persisted with the submitted name

Before: ![before](widgets-create/before.png)

Just before submit: ![before submit](widgets-create/before_submit.png)

After submit: ![after](widgets-create/after_submit.png)
""",
        encoding="utf-8",
    )
    result = {
        "run_id": "gui-run-1",
        "report_path": str(report_path),
        "output_dir": str(run_dir),
        "pages": 1,
        "status": "PASS",
        "passed": 1,
        "blocked": 0,
        "failed": 0,
        "failures": [],
        "blockers": [],
        "ok": True,
    }

    evidence = runner.build_smoke_guide_evidence(
        manifest=_manifest(),
        result=result,
        environment="local",
        service_commit="a" * 40,
    )

    workflow = evidence["workflows"][0]
    assert workflow["persisted_postcondition"]["record_ids"] == {"widget_id": "widget-1"}
    assert workflow["persisted_postcondition"]["assertions"][0]["evidence"] == (
        "widget-1 persisted with the submitted name"
    )
    assert workflow["screenshots"]["after_submit"].endswith("widgets-create/after_submit.png")
