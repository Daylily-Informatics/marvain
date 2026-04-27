from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_generator():
    path = REPO_ROOT / "scripts" / "generate_route_coverage.py"
    spec = importlib.util.spec_from_file_location("generate_route_coverage_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_route_coverage_discovers_api_gui_and_playwright_workflows() -> None:
    generator = _load_generator()

    coverage = generator.build_coverage(REPO_ROOT)

    assert coverage.api.total > 0
    assert coverage.gui.total > 0
    assert coverage.api.percent == 100
    assert coverage.gui.percent == 100
    assert coverage.playwright.percent >= 75
    assert coverage.playwright_count >= 4


def test_route_coverage_check_passes_current_round6_floor() -> None:
    generator = _load_generator()

    result = generator.main(["--check", "--min-api", "100", "--min-gui", "100", "--min-playwright", "75"])

    assert result == 0


def test_route_coverage_check_fails_when_threshold_is_too_high() -> None:
    generator = _load_generator()

    result = generator.main(["--check", "--min-api", "101", "--min-gui", "100", "--min-playwright", "75"])

    assert result == 1


def test_route_coverage_check_fails_when_playwright_threshold_is_too_high() -> None:
    generator = _load_generator()

    result = generator.main(["--check", "--min-api", "100", "--min-gui", "100", "--min-playwright", "101"])

    assert result == 1
