from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

import pytest
from playwright.sync_api import sync_playwright

from marvain_cli.smoke import GUI_WORKFLOW_MANIFEST_PATH, run_gui_smoke_guide

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "scripts" / "run_gui_workflow_receipt.py"
pytestmark = pytest.mark.e2e


def _load_runner():
    spec = importlib.util.spec_from_file_location("marvain_gui_workflow_receipt_for_e2e", RUNNER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_gui_workflow_receipt_against_configured_service() -> None:
    """Execute the manifest against a commit-identifying Marvain service."""
    runner = _load_runner()
    required = {
        runner.BASE_URL_ENV: os.environ.get(runner.BASE_URL_ENV),
        runner.ENVIRONMENT_ENV: os.environ.get(runner.ENVIRONMENT_ENV),
        runner.EXPECTED_COMMIT_ENV: os.environ.get(runner.EXPECTED_COMMIT_ENV),
        runner.GUIDE_OUTPUT_ENV: os.environ.get(runner.GUIDE_OUTPUT_ENV),
        runner.EVENT_PATH_ENV: os.environ.get(runner.EVENT_PATH_ENV),
    }
    if not any(required.values()):
        pytest.skip("GUI workflow receipt test runs only through scripts/run_gui_workflow_receipt.py")
    missing = [name for name, value in required.items() if not value]
    assert not missing, f"receipt runner environment is incomplete: {', '.join(missing)}"

    base_url = str(required[runner.BASE_URL_ENV])
    environment = str(required[runner.ENVIRONMENT_ENV])
    expected_commit = str(required[runner.EXPECTED_COMMIT_ENV]).lower()
    guide_output = Path(str(required[runner.GUIDE_OUTPUT_ENV]))

    with sync_playwright() as playwright:
        request = playwright.request.new_context(ignore_https_errors=True)
        try:
            response = request.get(urljoin(f"{base_url.rstrip('/')}/", "obs_services"), timeout=10_000)
            assert response.status == 200, f"GET /obs_services returned HTTP {response.status}"
            service_manifest = response.json()
        finally:
            request.dispose()
    assert isinstance(service_manifest, dict)
    assert service_manifest.get("schema") == "marvain.observability.v1"
    assert service_manifest.get("service") == "marvain"
    build = service_manifest.get("build")
    assert isinstance(build, dict)
    assert build.get("sha") == expected_commit, (
        "Marvain /obs_services must report the exact tested Git SHA; "
        f"expected {expected_commit}, got {build.get('sha')!r}"
    )

    result = run_gui_smoke_guide(base_url=base_url, output_dir=guide_output, headless=True)
    manifest = json.loads(GUI_WORKFLOW_MANIFEST_PATH.read_text(encoding="utf-8"))
    evidence = runner.build_smoke_guide_evidence(
        manifest=manifest,
        result=result,
        environment=environment,
        service_commit=expected_commit,
    )
    runner.write_smoke_guide_event(evidence)
