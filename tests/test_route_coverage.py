from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_COMMIT = "0" * 40


def _load_generator():
    path = REPO_ROOT / "scripts" / "generate_route_coverage.py"
    spec = importlib.util.spec_from_file_location("generate_route_coverage_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_design_status_generator():
    path = REPO_ROOT / "scripts" / "generate_design_objective_status.py"
    spec = importlib.util.spec_from_file_location("generate_design_objective_status_for_route_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, content: dict) -> None:
    _write(path, json.dumps(content, indent=2) + "\n")


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _route_fixture(root: Path, *, include_receipt: bool = True) -> None:
    _write(
        root / "functions/hub_api/api_app.py",
        "@api_app.post('/v1/widgets')\ndef create_widget():\n    pass\n",
    )
    _write(
        root / "functions/hub_api/app.py",
        "@app.get('/widgets')\ndef widgets_page():\n    pass\n",
    )
    _write(
        root / "tests/test_route_smoke_api.py",
        "# api_app.routes APIRoute\ndef test_api_routes_reachable():\n    pass\n",
    )
    _write(
        root / "tests/test_route_smoke_gui.py",
        "# app.routes APIRoute\ndef test_gui_routes_reachable():\n    pass\n",
    )
    _write(
        root / "tests/test_widget_api.py",
        """
def test_create_widget_success():
    response = client.post("/v1/widgets")
    assert response.status_code == 201


def test_create_widget_denied():
    response = client.post("/v1/widgets")
    assert response.status_code == 403


def test_create_widget_validation():
    response = client.post("/v1/widgets")
    assert response.status_code == 422


def test_create_widget_persisted():
    response = client.post("/v1/widgets")
    assert response.status_code == 201
    readback = client.get("/v1/widgets/{widget_id}")
    assert readback.json()["name"] == "submitted"
""".lstrip(),
    )
    nodeids = {
        "success": "tests/test_widget_api.py::test_create_widget_success",
        "denial": "tests/test_widget_api.py::test_create_widget_denied",
        "validation": "tests/test_widget_api.py::test_create_widget_validation",
        "postcondition": "tests/test_widget_api.py::test_create_widget_persisted",
    }
    _write_json(
        root / "tests/route_behavior_manifest.json",
        {
            "schema": "marvain.route-behavior-manifest.v1",
            "routes": [
                {
                    "surface": "api",
                    "method": "POST",
                    "path": "/v1/widgets",
                    "requirements": {kind: "required" for kind in nodeids},
                    "tests": nodeids,
                }
            ],
        },
    )
    if not include_receipt:
        return
    _write_json(
        root / "output/coverage/route_behavior_receipt.json",
        {
            "schema": "marvain.route-behavior-receipt.v1",
            "source_commit": FIXTURE_COMMIT,
            "status": "passed",
            "runner": "pytest",
            "exit_code": 0,
            "run_id": "route-fixture-run",
            "completed_at": "2026-07-10T12:00:00Z",
            "command": "python -m pytest tests/test_widget_api.py",
            "results": [
                {
                    "surface": "api",
                    "method": "POST",
                    "path": "/v1/widgets",
                    "status": "passed",
                    "evidence": {
                        "success": {
                            "status": "passed",
                            "test_nodeid": nodeids["success"],
                            "http_status": 201,
                        },
                        "denial": {
                            "status": "passed",
                            "test_nodeid": nodeids["denial"],
                            "http_status": 403,
                        },
                        "validation": {
                            "status": "passed",
                            "test_nodeid": nodeids["validation"],
                            "http_status": 422,
                        },
                        "postcondition": {
                            "status": "passed",
                            "test_nodeid": nodeids["postcondition"],
                            "owner": "widget-service",
                            "query": "GET /v1/widgets/{widget_id}",
                            "record_ids": {"widget_id": "fixture-widget"},
                            "assertions": [{"description": "stored name equals submitted name", "status": "passed"}],
                        },
                    },
                }
            ],
        },
    )


def _workflow_fixture(root: Path, *, include_receipt: bool = True, source_commit: str = FIXTURE_COMMIT) -> None:
    _write(
        root / "tests/e2e/test_widget_playwright.py",
        "def test_widget_workflow():\n    run_gui_smoke_guide()\n",
    )
    _write_json(
        root / "tests/e2e/gui_workflow_manifest.json",
        {
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
        },
    )
    if not include_receipt:
        return
    screenshots: dict[str, str] = {}
    for phase in ("before", "before_submit", "after_submit"):
        rel_path = f"output/playwright/fixture/widgets/{phase}.png"
        _write_bytes(root / rel_path, b"\x89PNG\r\n\x1a\nfixture")
        screenshots[phase] = rel_path
    _write_json(
        root / "output/playwright/workflow_receipt.json",
        {
            "schema": "marvain.gui-workflow-receipt.v1",
            "source_commit": source_commit,
            "status": "passed",
            "runner": "playwright",
            "exit_code": 0,
            "run_id": "playwright-fixture-run",
            "environment": "local",
            "completed_at": "2026-07-10T12:00:00Z",
            "command": "python -m pytest tests/e2e/test_widget_playwright.py",
            "workflows": [
                {
                    "id": "widgets-create",
                    "status": "passed",
                    "test_nodeid": "tests/e2e/test_widget_playwright.py::test_widget_workflow",
                    "steps": [
                        {"name": "open create", "status": "passed"},
                        {"name": "submit widget", "status": "passed"},
                    ],
                    "persisted_postcondition": {
                        "status": "passed",
                        "owner": "widget-service",
                        "request": "GET /v1/widgets/{widget_id}",
                        "record_ids": {"widget_id": "fixture-widget"},
                        "assertions": [{"description": "stored name equals submitted name", "status": "passed"}],
                    },
                    "screenshots": screenshots,
                }
            ],
        },
    )


def test_current_metrics_separate_reachability_from_same_commit_behavioral_proof() -> None:
    generator = _load_generator()

    coverage = generator.build_coverage(REPO_ROOT)

    assert coverage.api.total >= 64
    assert coverage.gui.total >= 108
    assert 0 <= coverage.api.covered < coverage.api.total
    assert 0 <= coverage.gui.covered < coverage.gui.total
    assert coverage.api_reachability.percent == 100
    assert coverage.gui_reachability.percent == 100
    assert (coverage.playwright.covered, coverage.playwright.total, coverage.playwright.percent) == (0, 22, 0)
    assert coverage.playwright_count >= 8
    assert "missing or invalid executed receipt" in " ".join(coverage.playwright.issues)
    assert "auth-hosted-ui-login" in coverage.playwright.missing
    if coverage.api.covered == 0 or coverage.gui.covered == 0:
        assert "same-commit" in " ".join((*coverage.api.issues, *coverage.gui.issues))


def test_current_round6_floor_fails_without_behavior_and_execution_receipts() -> None:
    generator = _load_generator()

    result = generator.main(["--check", "--min-api", "75", "--min-gui", "75", "--min-playwright", "75"])

    assert result == 1


def test_design_status_gate_uses_truthful_behavioral_metrics() -> None:
    design_status = _load_design_status_generator()
    coverage = _load_generator().build_coverage(REPO_ROOT)

    issues = design_status.round6_coverage_gate_issues(REPO_ROOT)

    assert any(f"API route coverage {coverage.api.percent}%" in issue for issue in issues)
    assert any(f"GUI route coverage {coverage.gui.percent}%" in issue for issue in issues)
    assert any("Playwright workflow coverage 0%" in issue for issue in issues)


def test_zero_floor_passes_while_metrics_are_unproven() -> None:
    generator = _load_generator()

    result = generator.main(["--check", "--min-api", "0", "--min-gui", "0", "--min-playwright", "0"])

    assert result == 0


def test_route_behavior_requires_manifest_and_executed_receipt(tmp_path: Path) -> None:
    generator = _load_generator()
    _route_fixture(tmp_path, include_receipt=False)

    without_receipt = generator.build_coverage(tmp_path)
    assert without_receipt.api.percent == 0
    assert without_receipt.api_reachability.percent == 100

    _route_fixture(tmp_path, include_receipt=True)
    with_receipt = generator.build_coverage(tmp_path)
    assert (with_receipt.api.covered, with_receipt.api.total, with_receipt.api.percent) == (1, 1, 100)
    assert with_receipt.gui.percent == 0


def test_route_behavior_rejects_incomplete_postcondition_receipt(tmp_path: Path) -> None:
    generator = _load_generator()
    _route_fixture(tmp_path)
    receipt_path = tmp_path / "output/coverage/route_behavior_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    del receipt["results"][0]["evidence"]["postcondition"]["record_ids"]
    _write_json(receipt_path, receipt)

    coverage = generator.build_coverage(tmp_path)

    assert coverage.api.percent == 0
    assert "persisted readback evidence" in " ".join(coverage.api.issues)


def test_route_behavior_rejects_test_that_does_not_exercise_declared_method_path(tmp_path: Path) -> None:
    generator = _load_generator()
    _route_fixture(tmp_path)
    test_path = tmp_path / "tests/test_widget_api.py"
    test_path.write_text(test_path.read_text(encoding="utf-8").replace("/v1/widgets", "/v1/other"), encoding="utf-8")

    coverage = generator.build_coverage(tmp_path)

    assert coverage.api.percent == 0
    assert "does not exercise POST /v1/widgets" in " ".join(coverage.api.issues)


def test_mutation_validation_and_postcondition_cannot_be_declared_not_applicable(tmp_path: Path) -> None:
    generator = _load_generator()
    _route_fixture(tmp_path)
    manifest_path = tmp_path / "tests/route_behavior_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["routes"][0]["requirements"]["postcondition"] = {
        "status": "not_applicable",
        "reason": "attempt to suppress durable mutation proof",
    }
    _write_json(manifest_path, manifest)

    coverage = generator.build_coverage(tmp_path)

    assert coverage.api.percent == 0
    assert "mutation postcondition proof cannot be not-applicable" in " ".join(coverage.api.issues)


def test_playwright_tokens_and_manifest_do_not_count_without_receipt(tmp_path: Path) -> None:
    generator = _load_generator()
    _workflow_fixture(tmp_path, include_receipt=False)

    coverage = generator.collect_playwright_workflow_coverage(
        tmp_path,
        expected_commit=FIXTURE_COMMIT,
        required_workflows=(("widgets-create", "/widgets"),),
    )

    assert (coverage.covered, coverage.total, coverage.percent) == (0, 1, 0)
    assert len(coverage.evidence) == 1


def test_playwright_receipt_requires_steps_postcondition_ids_and_screenshots(tmp_path: Path) -> None:
    generator = _load_generator()
    _workflow_fixture(tmp_path)

    coverage = generator.collect_playwright_workflow_coverage(
        tmp_path,
        expected_commit=FIXTURE_COMMIT,
        required_workflows=(("widgets-create", "/widgets"),),
    )

    assert (coverage.covered, coverage.total, coverage.percent) == (1, 1, 100)
    assert coverage.missing == ()


def test_playwright_receipt_must_match_the_reviewed_commit(tmp_path: Path) -> None:
    generator = _load_generator()
    _workflow_fixture(tmp_path)

    coverage = generator.collect_playwright_workflow_coverage(
        tmp_path,
        expected_commit="1" * 40,
        required_workflows=(("widgets-create", "/widgets"),),
    )

    assert coverage.percent == 0
    assert "same-commit" in " ".join(coverage.issues)
