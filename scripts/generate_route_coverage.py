#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
HTTP_METHODS = {"delete", "get", "patch", "post", "put"}
MUTATION_METHODS = {"DELETE", "PATCH", "POST", "PUT"}
API_SMOKE_TEST = Path("tests/test_route_smoke_api.py")
GUI_SMOKE_TEST = Path("tests/test_route_smoke_gui.py")
ROUTE_BEHAVIOR_MANIFEST = Path("tests/route_behavior_manifest.json")
ROUTE_BEHAVIOR_RECEIPT = Path("output/coverage/route_behavior_receipt.json")
PLAYWRIGHT_WORKFLOW_MANIFEST = Path("tests/e2e/gui_workflow_manifest.json")
PLAYWRIGHT_WORKFLOW_RECEIPT = Path("output/playwright/workflow_receipt.json")
ROUTE_MANIFEST_SCHEMA = "marvain.route-behavior-manifest.v1"
ROUTE_RECEIPT_SCHEMA = "marvain.route-behavior-receipt.v1"
WORKFLOW_MANIFEST_SCHEMA = "marvain.gui-workflows.v1"
WORKFLOW_RECEIPT_SCHEMA = "marvain.gui-workflow-receipt.v1"
BEHAVIOR_CLASSES = ("success", "denial", "validation", "postcondition")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PLAYWRIGHT_WORKFLOWS: tuple[tuple[str, str], ...] = (
    ("auth-hosted-ui-login", "/login"),
    ("dashboard-agent-summary", "/"),
    ("agents-create", "/agents"),
    ("people-consent", "/people"),
    ("locations-create", "/locations"),
    ("spaces-create", "/spaces"),
    ("devices-register", "/devices"),
    ("sessions-inspect", "/sessions"),
    ("live-session-chat", "/live-session"),
    ("memories-annotate", "/memories"),
    ("recognition-decide", "/recognition"),
    ("actions-create", "/actions"),
    ("actions-guide-propose", "/actions/guide"),
    ("tools-inspect", "/tools"),
    ("personas-create", "/personas"),
    ("tapdb-graph-traverse", "/tapdb/graph"),
    ("tapdb-query-filter", "/tapdb/query"),
    ("audit-verify", "/audit"),
    ("observability-correlate", "/observability"),
    ("capability-matrix-evidence", "/capabilities"),
    ("artifacts-upload", "/artifacts"),
    ("settings-profile-auth", "/profile"),
)


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
    issues: tuple[str, ...] = ()


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
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageReport:
    # These are the truthful metrics used by threshold gates.
    api: RouteSurfaceCoverage
    gui: RouteSurfaceCoverage
    playwright: PlaywrightWorkflowCoverage
    # Reachability is useful diagnostic evidence, but it is not behavior coverage.
    api_reachability: RouteSurfaceCoverage
    gui_reachability: RouteSurfaceCoverage
    playwright_workflows: tuple[PlaywrightWorkflow, ...]

    @property
    def playwright_count(self) -> int:
        return len(self.playwright_workflows)

    @property
    def playwright_percent(self) -> int:
        return self.playwright.percent


def _rel(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _read_ast(path: Path) -> ast.Module:
    return ast.parse(_read_text(path), filename=str(path))


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


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
    return _dedupe_routes(
        (
            *collect_decorated_routes(root, "functions/hub_api/api_app.py", "api_app"),
            *collect_decorated_routes(
                root,
                "layers/shared/python/agent_hub/observability_routes.py",
                "app",
            ),
        )
    )


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


def _reachability_for_surface(
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
        evidence = tuple(f"explicit route reference {path}" for path in explicit_paths)

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


def _git_commit(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip().lower()
    return commit if result.returncode == 0 and COMMIT_RE.fullmatch(commit) else None


def _receipt_matches_commit(receipt: dict[str, Any], expected_commit: str | None) -> bool:
    source_commit = receipt.get("source_commit")
    if not isinstance(source_commit, str) or not COMMIT_RE.fullmatch(source_commit.lower()):
        return False
    return expected_commit is None or source_commit.lower() == expected_commit.lower()


def _test_node_exists(root: Path, nodeid: object, *, playwright: bool = False) -> bool:
    if not isinstance(nodeid, str) or "::" not in nodeid:
        return False
    rel_path, function_name = nodeid.split("::", 1)
    if not function_name.startswith("test_") or "::" in function_name:
        return False
    path = (root / rel_path).resolve()
    tests_root = (root / "tests").resolve()
    if tests_root not in path.parents or not path.is_file() or path.suffix != ".py":
        return False
    try:
        tree = _read_ast(path)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) or node.name != function_name:
            continue
        if not playwright:
            return True
        body = ast.get_source_segment(_read_text(path), node) or ""
        return any(token in body for token in ("sync_playwright", "browser_page", "run_gui_smoke_guide"))
    return False


def _path_shape(value: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", value.split("?", 1)[0])


def _call_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{}")
            else:
                return None
        return "".join(parts)
    return None


def _test_targets_route(root: Path, nodeid: object, *, method: str, route_path: str) -> bool:
    if not isinstance(nodeid, str) or "::" not in nodeid:
        return False
    rel_path, function_name = nodeid.split("::", 1)
    path = root / rel_path
    try:
        tree = _read_ast(path)
    except (OSError, SyntaxError):
        return False
    expected_shape = _path_shape(route_path)
    for function in ast.walk(tree):
        if not isinstance(function, (ast.AsyncFunctionDef, ast.FunctionDef)) or function.name != function_name:
            continue
        for call in ast.walk(function):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            call_method = _call_name(call.func).rsplit(".", 1)[-1].upper()
            path_arg = call.args[0]
            if call_method == "REQUEST" and len(call.args) >= 2:
                declared_method = _string_constant(call.args[0])
                if declared_method is None or declared_method.upper() != method:
                    continue
                path_arg = call.args[1]
            elif call_method != method:
                continue
            actual_path = _call_path(path_arg)
            if actual_path is not None and _path_shape(actual_path) == expected_shape:
                return True
    return False


def _manifest_requirement(value: object) -> tuple[str, str | None]:
    if value == "required":
        return "required", None
    if isinstance(value, dict) and value.get("status") == "not_applicable":
        reason = value.get("reason")
        if isinstance(reason, str) and len(reason.strip()) >= 12:
            return "not_applicable", reason.strip()
    return "invalid", None


def _valid_http_status(kind: str, value: object) -> bool:
    if not isinstance(value, int):
        return False
    if kind == "success":
        return 200 <= value < 400
    if kind == "denial":
        return value in {401, 403}
    if kind == "validation":
        return value in {400, 409, 415, 422}
    return False


def _valid_postcondition_evidence(value: object) -> bool:
    if not isinstance(value, dict) or value.get("status") != "passed":
        return False
    owner = value.get("owner")
    query = value.get("query")
    record_ids = value.get("record_ids")
    assertions = value.get("assertions")
    if not isinstance(owner, str) or not owner.strip():
        return False
    if not isinstance(query, str) or not query.strip():
        return False
    if not isinstance(record_ids, dict) or not record_ids:
        return False
    if not isinstance(assertions, list) or not assertions:
        return False
    return all(
        isinstance(assertion, dict)
        and assertion.get("status") == "passed"
        and isinstance(assertion.get("description"), str)
        and bool(assertion["description"].strip())
        for assertion in assertions
    )


def _route_behavior_key(value: dict[str, Any]) -> tuple[str, str, str] | None:
    surface = value.get("surface")
    method = value.get("method")
    path = value.get("path")
    if surface not in {"api", "gui"} or not isinstance(method, str) or not isinstance(path, str):
        return None
    return surface, method.upper(), path.split("?", 1)[0]


def _route_behavior_evidence(
    root: Path,
    *,
    expected_commit: str | None,
) -> tuple[set[tuple[str, str, str]], tuple[str, ...], tuple[str, ...]]:
    manifest_path = root / ROUTE_BEHAVIOR_MANIFEST
    receipt_path = root / ROUTE_BEHAVIOR_RECEIPT
    manifest = _read_json(manifest_path)
    receipt = _read_json(receipt_path)
    issues: list[str] = []
    evidence: list[str] = []

    if manifest is None:
        return set(), (f"missing or invalid {ROUTE_BEHAVIOR_MANIFEST}",), ()
    if manifest.get("schema") != ROUTE_MANIFEST_SCHEMA or not isinstance(manifest.get("routes"), list):
        return set(), (f"{ROUTE_BEHAVIOR_MANIFEST} does not satisfy {ROUTE_MANIFEST_SCHEMA}",), ()
    if receipt is None:
        return set(), (f"missing or invalid executed receipt {ROUTE_BEHAVIOR_RECEIPT}",), ()
    if (
        receipt.get("schema") != ROUTE_RECEIPT_SCHEMA
        or receipt.get("status") != "passed"
        or receipt.get("runner") != "pytest"
        or receipt.get("exit_code") != 0
        or not isinstance(receipt.get("run_id"), str)
        or not receipt["run_id"].strip()
        or not isinstance(receipt.get("completed_at"), str)
        or not receipt["completed_at"].endswith("Z")
        or not isinstance(receipt.get("command"), str)
        or "pytest" not in receipt["command"]
        or not isinstance(receipt.get("results"), list)
        or not _receipt_matches_commit(receipt, expected_commit)
    ):
        return set(), (f"{ROUTE_BEHAVIOR_RECEIPT} is not a passed same-commit pytest receipt",), ()

    manifest_entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in manifest["routes"]:
        if not isinstance(raw, dict) or (key := _route_behavior_key(raw)) is None or key in manifest_entries:
            issues.append(f"invalid or duplicate route behavior manifest entry: {raw!r}")
            continue
        manifest_entries[key] = raw
    receipt_entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in receipt["results"]:
        if not isinstance(raw, dict) or (key := _route_behavior_key(raw)) is None or key in receipt_entries:
            issues.append(f"invalid or duplicate route behavior receipt entry: {raw!r}")
            continue
        receipt_entries[key] = raw

    covered: set[tuple[str, str, str]] = set()
    for key, declared in manifest_entries.items():
        result = receipt_entries.get(key)
        requirements = declared.get("requirements")
        tests = declared.get("tests")
        outcomes = result.get("evidence") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or result.get("status") != "passed"
            or not isinstance(requirements, dict)
            or not isinstance(tests, dict)
            or not isinstance(outcomes, dict)
        ):
            issues.append(f"{key}: missing passed result, requirements, tests, or evidence")
            continue

        valid = True
        for kind in BEHAVIOR_CLASSES:
            requirement, _reason = _manifest_requirement(requirements.get(kind))
            if requirement == "invalid":
                issues.append(f"{key}: {kind} applicability is not explicitly valid")
                valid = False
                continue
            if kind == "success" and requirement != "required":
                issues.append(f"{key}: success proof is always required")
                valid = False
                continue
            if key[1] in MUTATION_METHODS and kind in {"validation", "postcondition"} and requirement != "required":
                issues.append(f"{key}: mutation {kind} proof cannot be not-applicable")
                valid = False
                continue
            if requirement == "not_applicable":
                continue
            nodeid = tests.get(kind)
            outcome = outcomes.get(kind)
            if not _test_node_exists(root, nodeid) or not _test_targets_route(
                root,
                nodeid,
                method=key[1],
                route_path=key[2],
            ):
                issues.append(f"{key}: {kind} test does not exist or does not exercise {key[1]} {key[2]}: {nodeid!r}")
                valid = False
                continue
            if (
                not isinstance(outcome, dict)
                or outcome.get("status") != "passed"
                or outcome.get("test_nodeid") != nodeid
            ):
                issues.append(f"{key}: {kind} has no matching passed test outcome")
                valid = False
                continue
            if kind == "postcondition":
                if not _valid_postcondition_evidence(outcome):
                    issues.append(f"{key}: postcondition lacks owner-backed persisted readback evidence")
                    valid = False
            elif not _valid_http_status(kind, outcome.get("http_status")):
                issues.append(f"{key}: {kind} has an invalid HTTP status proof")
                valid = False

        if valid:
            covered.add(key)
            evidence.append(f"{ROUTE_BEHAVIOR_RECEIPT}: {key[0]} {key[1]} {key[2]}")

    return covered, tuple(issues), tuple(evidence)


def _behavior_coverage_for_surface(
    *,
    surface: str,
    label: str,
    targets: tuple[RouteTarget, ...],
    covered_keys: set[tuple[str, str, str]],
    issues: tuple[str, ...],
    evidence: tuple[str, ...],
) -> RouteSurfaceCoverage:
    covered_targets = {target for target in targets if (surface, target.method, target.path) in covered_keys}
    missing = tuple(target for target in targets if target not in covered_targets)
    covered = len(covered_targets)
    percent = round((covered / len(targets)) * 100) if targets else 100
    return RouteSurfaceCoverage(
        label=label,
        total=len(targets),
        covered=covered,
        percent=percent,
        missing=missing,
        evidence=evidence,
        issues=issues,
    )


def collect_playwright_workflows(root: Path = ROOT) -> tuple[PlaywrightWorkflow, ...]:
    e2e_root = root / "tests" / "e2e"
    if not e2e_root.exists():
        return ()
    workflows: list[PlaywrightWorkflow] = []
    for path in sorted(e2e_root.glob("*playwright*.py")):
        try:
            tree = _read_ast(path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name.startswith("test_"):
                workflows.append(PlaywrightWorkflow(name=node.name, source=_source(root, path, node)))
    return tuple(sorted(workflows, key=lambda workflow: (workflow.source, workflow.name)))


def _valid_screenshot(root: Path, value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = (root / value).resolve()
    if root.resolve() not in path.parents or not path.is_file() or path.suffix.lower() != ".png":
        return False
    try:
        return path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    except OSError:
        return False


def _valid_workflow_result(root: Path, declared: dict[str, Any], result: object) -> bool:
    if not isinstance(result, dict) or result.get("status") != "passed":
        return False
    nodeid = result.get("test_nodeid")
    if not _test_node_exists(root, nodeid, playwright=True):
        return False

    expected_steps = declared.get("browser_steps")
    actual_steps = result.get("steps")
    if not isinstance(expected_steps, list) or not expected_steps or not isinstance(actual_steps, list):
        return False
    passed_steps = {
        step.get("name")
        for step in actual_steps
        if isinstance(step, dict) and step.get("status") == "passed" and isinstance(step.get("name"), str)
    }
    if any(step not in passed_steps for step in expected_steps):
        return False

    expected_postcondition = declared.get("persisted_postcondition")
    actual_postcondition = result.get("persisted_postcondition")
    if not isinstance(expected_postcondition, dict) or not isinstance(actual_postcondition, dict):
        return False
    if actual_postcondition.get("status") != "passed":
        return False
    if actual_postcondition.get("owner") != expected_postcondition.get("owner"):
        return False
    if actual_postcondition.get("request") != expected_postcondition.get("request"):
        return False
    if not isinstance(actual_postcondition.get("record_ids"), dict) or not actual_postcondition["record_ids"]:
        return False
    expected_assertions = expected_postcondition.get("assert")
    actual_assertions = actual_postcondition.get("assertions")
    if not isinstance(expected_assertions, list) or not expected_assertions or not isinstance(actual_assertions, list):
        return False
    passed_assertions = {
        assertion.get("description")
        for assertion in actual_assertions
        if isinstance(assertion, dict)
        and assertion.get("status") == "passed"
        and isinstance(assertion.get("description"), str)
    }
    if any(assertion not in passed_assertions for assertion in expected_assertions):
        return False

    screenshots = result.get("screenshots")
    return isinstance(screenshots, dict) and all(
        _valid_screenshot(root, screenshots.get(phase)) for phase in ("before", "before_submit", "after_submit")
    )


def collect_playwright_workflow_coverage(
    root: Path = ROOT,
    *,
    expected_commit: str | None = None,
    required_workflows: tuple[tuple[str, str], ...] = REQUIRED_PLAYWRIGHT_WORKFLOWS,
) -> PlaywrightWorkflowCoverage:
    manifest = _read_json(root / PLAYWRIGHT_WORKFLOW_MANIFEST)
    receipt = _read_json(root / PLAYWRIGHT_WORKFLOW_RECEIPT)
    source_workflows = collect_playwright_workflows(root)
    issues: list[str] = []

    if (
        manifest is None
        or manifest.get("schema") != WORKFLOW_MANIFEST_SCHEMA
        or not isinstance(manifest.get("workflows"), list)
    ):
        return PlaywrightWorkflowCoverage(
            total=len(required_workflows),
            covered=0,
            percent=0,
            missing=tuple(workflow_id for workflow_id, _path in required_workflows),
            evidence=source_workflows,
            issues=(f"missing or invalid {PLAYWRIGHT_WORKFLOW_MANIFEST}",),
        )

    declared: dict[str, dict[str, Any]] = {}
    for raw in manifest["workflows"]:
        workflow_id = raw.get("id") if isinstance(raw, dict) else None
        if not isinstance(workflow_id, str) or not workflow_id or workflow_id in declared:
            issues.append(f"invalid or duplicate declared workflow: {raw!r}")
            continue
        declared[workflow_id] = raw

    required: dict[str, dict[str, Any] | None] = {}
    for workflow_id, expected_path in required_workflows:
        workflow = declared.get(workflow_id)
        declared_path = workflow.get("path") if workflow is not None else None
        if not isinstance(declared_path, str) or declared_path.split("?", 1)[0] != expected_path:
            issues.append(f"{workflow_id}: required workflow path {expected_path!r} is not declared")
            required[workflow_id] = None
        else:
            required[workflow_id] = workflow

    if receipt is None:
        return PlaywrightWorkflowCoverage(
            total=len(required),
            covered=0,
            percent=0,
            missing=tuple(required),
            evidence=source_workflows,
            issues=tuple(issues + [f"missing or invalid executed receipt {PLAYWRIGHT_WORKFLOW_RECEIPT}"]),
        )

    expected = expected_commit if expected_commit is not None else _git_commit(root)
    if (
        receipt.get("schema") != WORKFLOW_RECEIPT_SCHEMA
        or receipt.get("status") != "passed"
        or receipt.get("runner") != "playwright"
        or receipt.get("exit_code") != 0
        or not isinstance(receipt.get("run_id"), str)
        or not receipt["run_id"].strip()
        or receipt.get("environment") not in {"local", "cleanroom", "deployed"}
        or not isinstance(receipt.get("completed_at"), str)
        or not receipt["completed_at"].endswith("Z")
        or not isinstance(receipt.get("command"), str)
        or "playwright" not in receipt["command"].lower()
        or not isinstance(receipt.get("workflows"), list)
        or not _receipt_matches_commit(receipt, expected)
    ):
        return PlaywrightWorkflowCoverage(
            total=len(required),
            covered=0,
            percent=0,
            missing=tuple(required),
            evidence=source_workflows,
            issues=tuple(issues + [f"{PLAYWRIGHT_WORKFLOW_RECEIPT} is not a passed same-commit Playwright receipt"]),
        )

    results: dict[str, dict[str, Any]] = {}
    for raw in receipt["workflows"]:
        workflow_id = raw.get("id") if isinstance(raw, dict) else None
        if not isinstance(workflow_id, str) or workflow_id in results:
            issues.append(f"invalid or duplicate workflow receipt result: {raw!r}")
            continue
        results[workflow_id] = raw

    covered_ids: set[str] = set()
    for workflow_id, workflow in required.items():
        if workflow is not None and _valid_workflow_result(root, workflow, results.get(workflow_id)):
            covered_ids.add(workflow_id)
        else:
            issues.append(f"{workflow_id}: no complete executed browser and persisted-postcondition proof")

    total = len(required)
    covered = len(covered_ids)
    percent = round((covered / total) * 100) if total else 0
    return PlaywrightWorkflowCoverage(
        total=total,
        covered=covered,
        percent=percent,
        missing=tuple(workflow_id for workflow_id in required if workflow_id not in covered_ids),
        evidence=source_workflows,
        issues=tuple(issues),
    )


def build_coverage(root: Path = ROOT) -> CoverageReport:
    api_targets = collect_api_routes(root)
    gui_targets = collect_gui_routes(root)
    explicit_paths = collect_explicit_test_paths(root)
    expected_commit = _git_commit(root)
    behavior_keys, behavior_issues, behavior_evidence = _route_behavior_evidence(
        root,
        expected_commit=expected_commit,
    )
    return CoverageReport(
        api=_behavior_coverage_for_surface(
            surface="api",
            label="API behavioral routes",
            targets=api_targets,
            covered_keys=behavior_keys,
            issues=behavior_issues,
            evidence=behavior_evidence,
        ),
        gui=_behavior_coverage_for_surface(
            surface="gui",
            label="GUI behavioral routes",
            targets=gui_targets,
            covered_keys=behavior_keys,
            issues=behavior_issues,
            evidence=behavior_evidence,
        ),
        api_reachability=_reachability_for_surface(
            label="API route reachability",
            targets=api_targets,
            explicit_paths=explicit_paths,
            dynamic_smoke=_has_dynamic_api_smoke(root),
            dynamic_source=str(API_SMOKE_TEST),
        ),
        gui_reachability=_reachability_for_surface(
            label="GUI route reachability",
            targets=gui_targets,
            explicit_paths=explicit_paths,
            dynamic_smoke=_has_dynamic_gui_smoke(root),
            dynamic_source=str(GUI_SMOKE_TEST),
        ),
        playwright=collect_playwright_workflow_coverage(root, expected_commit=expected_commit),
        playwright_workflows=collect_playwright_workflows(root),
    )


def _append_surface(lines: list[str], surface: RouteSurfaceCoverage) -> None:
    lines.extend([f"## Missing {surface.label}", ""])
    if surface.missing:
        lines.extend(f"- `{route.method} {route.path}` ({route.source})" for route in surface.missing)
    else:
        lines.append("- none")
    lines.append("")
    if surface.issues:
        lines.extend([f"## {surface.label} Evidence Issues", ""])
        lines.extend(f"- {issue}" for issue in surface.issues)
        lines.append("")


def build_report(root: Path = ROOT) -> str:
    coverage = build_coverage(root)
    lines = [
        "# Route And Workflow Coverage",
        "",
        "Thresholds use behavioral and executed-workflow evidence. Reachability is diagnostic only.",
        "",
        f"- API behavioral coverage: {coverage.api.covered}/{coverage.api.total} ({coverage.api.percent}%).",
        f"- API reachability: {coverage.api_reachability.covered}/{coverage.api_reachability.total} "
        f"({coverage.api_reachability.percent}%).",
        f"- GUI behavioral coverage: {coverage.gui.covered}/{coverage.gui.total} ({coverage.gui.percent}%).",
        f"- GUI reachability: {coverage.gui_reachability.covered}/{coverage.gui_reachability.total} "
        f"({coverage.gui_reachability.percent}%).",
        "- Executed Playwright workflow coverage: "
        f"{coverage.playwright.covered}/{coverage.playwright.total} ({coverage.playwright.percent}%).",
        f"- Playwright test functions discovered (not coverage credit): {coverage.playwright_count}.",
        "",
        "## Discovered Playwright Tests",
        "",
    ]
    if coverage.playwright_workflows:
        lines.extend(f"- `{workflow.name}` ({workflow.source})" for workflow in coverage.playwright_workflows)
    else:
        lines.append("- none")
    lines.append("")

    _append_surface(lines, coverage.api)
    _append_surface(lines, coverage.gui)
    lines.extend(["## Missing Executed Playwright Workflows", ""])
    if coverage.playwright.missing:
        lines.extend(f"- `{workflow}`" for workflow in coverage.playwright.missing)
    else:
        lines.append("- none")
    lines.append("")
    if coverage.playwright.issues:
        lines.extend(["## Playwright Evidence Issues", ""])
        lines.extend(f"- {issue}" for issue in coverage.playwright.issues)
        lines.append("")
    return "\n".join(lines)


def _gate_messages(coverage: CoverageReport, *, min_api: int, min_gui: int, min_playwright: int) -> tuple[str, ...]:
    messages: list[str] = []
    if coverage.api.percent < min_api:
        messages.append(f"API behavioral coverage {coverage.api.percent}% is below required minimum {min_api}%.")
    if coverage.gui.percent < min_gui:
        messages.append(f"GUI behavioral coverage {coverage.gui.percent}% is below required minimum {min_gui}%.")
    if coverage.playwright.percent < min_playwright:
        messages.append(
            f"Executed Playwright workflow coverage {coverage.playwright.percent}% "
            f"is below required minimum {min_playwright}%."
        )
    return tuple(messages)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail when behavioral coverage is below the minimums")
    parser.add_argument("--min-api", type=int, default=0, help="Minimum API behavioral coverage percentage")
    parser.add_argument("--min-gui", type=int, default=0, help="Minimum GUI behavioral coverage percentage")
    parser.add_argument(
        "--min-playwright",
        type=int,
        default=0,
        help="Minimum executed Playwright workflow coverage percentage",
    )
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
            "Behavioral coverage gate passed: "
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
