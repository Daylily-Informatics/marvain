#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
HTTP_METHODS = {"delete", "get", "patch", "post", "put"}
API_SMOKE_TEST = Path("tests/test_route_smoke_api.py")
GUI_SMOKE_TEST = Path("tests/test_route_smoke_gui.py")


@dataclass(frozen=True)
class RouteTarget:
    method: str
    path: str
    source: str


@dataclass(frozen=True)
class RouteSurfaceCoverage:
    label: str
    total: int
    covered: int
    percent: int
    missing: tuple[RouteTarget, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class PlaywrightWorkflow:
    name: str
    source: str


@dataclass(frozen=True)
class PlaywrightWorkflowCoverage:
    total: int
    covered: int
    percent: int
    missing: tuple[str, ...]
    evidence: tuple[PlaywrightWorkflow, ...]


@dataclass(frozen=True)
class CoverageReport:
    api: RouteSurfaceCoverage
    gui: RouteSurfaceCoverage
    playwright: PlaywrightWorkflowCoverage
    playwright_workflows: tuple[PlaywrightWorkflow, ...]

    @property
    def playwright_count(self) -> int:
        return len(self.playwright_workflows)

    @property
    def playwright_percent(self) -> int:
        return self.playwright.percent


REQUIRED_PLAYWRIGHT_WORKFLOWS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("auth", ("test_generated_email_user_can_login_through_cognito_hosted_ui", "/login")),
    ("dashboard", ("/", "Dashboard")),
    ("agents", ("/agents", "Agents")),
    ("people", ("/people", "People")),
    ("locations", ("/locations", "Locations")),
    ("spaces", ("/spaces", "Spaces")),
    ("devices", ("/devices", "Devices")),
    ("sessions", ("/sessions", "Sessions")),
    ("live-session", ("/live-session", "Live Session")),
    ("memories", ("/memories", "Memories")),
    ("recognition", ("/recognition", "Recognition")),
    ("actions", ("/actions", "Actions")),
    ("actions-guide", ("/actions/guide", "Actions Guide")),
    ("tools", ("/tools", "Tool Catalog")),
    ("personas", ("/personas", "Personas")),
    ("tapdb-graph", ("/tapdb/graph", "Graph")),
    ("tapdb-query", ("/tapdb/query", "Query")),
    ("audit", ("/audit", "Audit")),
    ("observability", ("/observability", "Observability")),
    ("capability-matrix", ("/capabilities", "Capability Matrix")),
    ("artifacts", ("/artifacts", "Artifacts")),
    ("settings-profile", ("/profile", "Profile")),
)


def _rel(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_ast(path: Path) -> ast.Module:
    return ast.parse(_read_text(path), filename=str(path))


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _call_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return ""


def _source(root: Path, path: Path, node: ast.AST) -> str:
    return f"{_rel(root, path)}:{getattr(node, 'lineno', 1)}"


def _dedupe_routes(routes: Iterable[RouteTarget]) -> tuple[RouteTarget, ...]:
    seen: set[tuple[str, str]] = set()
    out: list[RouteTarget] = []
    for route in routes:
        key = (route.method, route.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(route)
    return tuple(sorted(out, key=lambda route: (route.path, route.method)))


def collect_decorated_routes(root: Path, rel_path: str, owner_name: str) -> tuple[RouteTarget, ...]:
    path = root / rel_path
    if not path.exists():
        return ()
    routes: list[RouteTarget] = []
    tree = _read_ast(path)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            if not isinstance(dec.func, ast.Attribute) or dec.func.attr not in HTTP_METHODS:
                continue
            if _call_name(dec.func.value) != owner_name or not dec.args:
                continue
            route_path = _string_constant(dec.args[0])
            if route_path is None:
                continue
            routes.append(
                RouteTarget(
                    method=dec.func.attr.upper(),
                    path=route_path.split("?", 1)[0],
                    source=_source(root, path, dec),
                )
            )
    return _dedupe_routes(routes)


def collect_api_routes(root: Path = ROOT) -> tuple[RouteTarget, ...]:
    return collect_decorated_routes(root, "functions/hub_api/api_app.py", "api_app")


def collect_gui_routes(root: Path = ROOT) -> tuple[RouteTarget, ...]:
    return tuple(
        route
        for route in collect_decorated_routes(root, "functions/hub_api/app.py", "app")
        if not route.path.startswith("/v1/")
    )


def _has_dynamic_api_smoke(root: Path) -> bool:
    path = root / API_SMOKE_TEST
    if not path.exists():
        return False
    text = _read_text(path)
    return all(token in text for token in ("api_app.routes", "APIRoute", "test_api_routes_reachable"))


def _has_dynamic_gui_smoke(root: Path) -> bool:
    path = root / GUI_SMOKE_TEST
    if not path.exists():
        return False
    text = _read_text(path)
    return all(token in text for token in ("app.routes", "APIRoute", "test_gui_routes_reachable"))


def collect_explicit_test_paths(root: Path = ROOT) -> tuple[str, ...]:
    tests_root = root / "tests"
    if not tests_root.exists():
        return ()
    paths: set[str] = set()
    for path in sorted(tests_root.rglob("test*.py")):
        try:
            tree = _read_ast(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            value = _string_constant(node)
            if value is None or not value.startswith("/"):
                continue
            paths.add(value.split("?", 1)[0])
    return tuple(sorted(paths))


def _coverage_for_surface(
    *,
    label: str,
    targets: tuple[RouteTarget, ...],
    explicit_paths: tuple[str, ...],
    dynamic_smoke: bool,
    dynamic_source: str,
) -> RouteSurfaceCoverage:
    if dynamic_smoke:
        covered_targets = set(targets)
        evidence = (dynamic_source,)
    else:
        explicit_path_set = set(explicit_paths)
        covered_targets = {target for target in targets if target.path in explicit_path_set}
        evidence = tuple(f"explicit test path {path}" for path in explicit_paths)

    missing = tuple(target for target in targets if target not in covered_targets)
    covered = len(targets) - len(missing)
    percent = round((covered / len(targets)) * 100) if targets else 100
    return RouteSurfaceCoverage(
        label=label,
        total=len(targets),
        covered=covered,
        percent=percent,
        missing=missing,
        evidence=evidence,
    )


def collect_playwright_workflows(root: Path = ROOT) -> tuple[PlaywrightWorkflow, ...]:
    e2e_root = root / "tests" / "e2e"
    if not e2e_root.exists():
        return ()
    workflows: list[PlaywrightWorkflow] = []
    for path in sorted(e2e_root.glob("*playwright*.py")):
        text = _read_text(path)
        if "sync_playwright" not in text and "run_gui_smoke_guide" not in text and "browser_page" not in text:
            continue
        try:
            tree = _read_ast(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name.startswith("test_"):
                workflows.append(PlaywrightWorkflow(name=node.name, source=_source(root, path, node)))
    return tuple(sorted(workflows, key=lambda workflow: (workflow.source, workflow.name)))


def collect_playwright_workflow_coverage(root: Path = ROOT) -> PlaywrightWorkflowCoverage:
    e2e_root = root / "tests" / "e2e"
    smoke_path = root / "marvain_cli" / "smoke.py"
    texts: list[str] = []
    if e2e_root.exists():
        texts.extend(_read_text(path) for path in sorted(e2e_root.glob("*playwright*.py")))
    e2e_haystack = "\n".join(texts)
    if smoke_path.exists() and "run_gui_smoke_guide" in e2e_haystack and "GUI_SMOKE_PAGES" in e2e_haystack:
        texts.append(_read_text(smoke_path))
    haystack = "\n".join(texts)

    missing: list[str] = []
    for workflow_name, tokens in REQUIRED_PLAYWRIGHT_WORKFLOWS:
        if not any(token in haystack for token in tokens):
            missing.append(workflow_name)

    total = len(REQUIRED_PLAYWRIGHT_WORKFLOWS)
    covered = total - len(missing)
    percent = round((covered / total) * 100) if total else 100
    return PlaywrightWorkflowCoverage(
        total=total,
        covered=covered,
        percent=percent,
        missing=tuple(missing),
        evidence=collect_playwright_workflows(root),
    )


def build_coverage(root: Path = ROOT) -> CoverageReport:
    explicit_paths = collect_explicit_test_paths(root)
    api = _coverage_for_surface(
        label="API routes",
        targets=collect_api_routes(root),
        explicit_paths=explicit_paths,
        dynamic_smoke=_has_dynamic_api_smoke(root),
        dynamic_source=str(API_SMOKE_TEST),
    )
    gui = _coverage_for_surface(
        label="GUI routes",
        targets=collect_gui_routes(root),
        explicit_paths=explicit_paths,
        dynamic_smoke=_has_dynamic_gui_smoke(root),
        dynamic_source=str(GUI_SMOKE_TEST),
    )
    return CoverageReport(
        api=api,
        gui=gui,
        playwright=collect_playwright_workflow_coverage(root),
        playwright_workflows=collect_playwright_workflows(root),
    )


def build_report(root: Path = ROOT) -> str:
    coverage = build_coverage(root)
    lines = [
        "# Route And Workflow Coverage",
        "",
        f"- API route coverage: {coverage.api.covered}/{coverage.api.total} ({coverage.api.percent}%).",
        f"- GUI route coverage: {coverage.gui.covered}/{coverage.gui.total} ({coverage.gui.percent}%).",
        "- Playwright workflow coverage: "
        f"{coverage.playwright.covered}/{coverage.playwright.total} ({coverage.playwright.percent}%).",
        f"- Playwright workflow test functions: {coverage.playwright_count}.",
        "",
        "## Playwright Workflows",
        "",
    ]
    if coverage.playwright_workflows:
        lines.extend(f"- `{workflow.name}` ({workflow.source})" for workflow in coverage.playwright_workflows)
    else:
        lines.append("- none")
    lines.append("")

    for surface in (coverage.api, coverage.gui):
        lines.extend([f"## Missing {surface.label}", ""])
        if surface.missing:
            lines.extend(f"- `{route.method} {route.path}` ({route.source})" for route in surface.missing)
        else:
            lines.append("- none")
        lines.append("")
    lines.extend(["## Missing Playwright Workflows", ""])
    if coverage.playwright.missing:
        lines.extend(f"- `{workflow}`" for workflow in coverage.playwright.missing)
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def _gate_messages(coverage: CoverageReport, *, min_api: int, min_gui: int, min_playwright: int) -> tuple[str, ...]:
    messages: list[str] = []
    if coverage.api.percent < min_api:
        messages.append(f"API route coverage {coverage.api.percent}% is below required minimum {min_api}%.")
    if coverage.gui.percent < min_gui:
        messages.append(f"GUI route coverage {coverage.gui.percent}% is below required minimum {min_gui}%.")
    if coverage.playwright.percent < min_playwright:
        messages.append(
            f"Playwright workflow coverage {coverage.playwright.percent}% is below required minimum {min_playwright}%."
        )
    return tuple(messages)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail when coverage is below the requested minimums")
    parser.add_argument("--min-api", type=int, default=0, help="Minimum API route coverage percentage")
    parser.add_argument("--min-gui", type=int, default=0, help="Minimum GUI route coverage percentage")
    parser.add_argument("--min-playwright", type=int, default=0, help="Minimum Playwright workflow coverage percentage")
    args = parser.parse_args(argv)

    coverage = build_coverage(ROOT)
    messages = _gate_messages(
        coverage,
        min_api=args.min_api,
        min_gui=args.min_gui,
        min_playwright=args.min_playwright,
    )
    if args.check:
        if messages:
            print("\n".join(messages))
            return 1
        print(
            "Route coverage gate passed: "
            f"API {coverage.api.percent}% >= {args.min_api}%, "
            f"GUI {coverage.gui.percent}% >= {args.min_gui}%, "
            f"Playwright {coverage.playwright.percent}% >= {args.min_playwright}%."
        )
        return 0

    print(build_report(ROOT))
    if messages:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
