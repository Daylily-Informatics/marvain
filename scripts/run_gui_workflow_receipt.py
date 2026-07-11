#!/usr/bin/env python3
"""Run the real GUI workflow guide and emit same-commit Playwright evidence.

This runner deliberately does not infer coverage from test discovery. It invokes
one dedicated Playwright test against the configured Marvain service and writes
the ignored coverage receipt only when every manifest workflow has browser
steps, owning-service postcondition proof, and three valid screenshots.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "e2e" / "gui_workflow_manifest.json"
DEFAULT_OUTPUT = ROOT / "output" / "playwright" / "workflow_receipt.json"
DEFAULT_GUIDE_OUTPUT = ROOT / "output" / "playwright" / "gui-workflow-runs"
PLAYWRIGHT_TEST_NODEID = (
    "tests/e2e/test_gui_workflow_receipt_playwright.py::test_gui_workflow_receipt_against_configured_service"
)
MANIFEST_SCHEMA = "marvain.gui-workflows.v1"
GUIDE_EVIDENCE_SCHEMA = "marvain.gui-smoke-guide-evidence.v1"
RECEIPT_SCHEMA = "marvain.gui-workflow-receipt.v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ENVIRONMENTS = {"local", "cleanroom", "deployed"}

EVENT_PATH_ENV = "MARVAIN_GUI_WORKFLOW_EVENT_PATH"
BASE_URL_ENV = "MARVAIN_GUI_WORKFLOW_BASE_URL"
ENVIRONMENT_ENV = "MARVAIN_GUI_WORKFLOW_ENVIRONMENT"
EXPECTED_COMMIT_ENV = "MARVAIN_GUI_WORKFLOW_EXPECTED_COMMIT"
GUIDE_OUTPUT_ENV = "MARVAIN_GUI_WORKFLOW_GUIDE_OUTPUT"

SAME_COMMIT_PATHS = (
    "apps",
    "functions",
    "layers",
    "marvain_cli",
    "scripts",
    "tests",
    "pyproject.toml",
    "template.yaml",
)


class ReceiptError(RuntimeError):
    """Raised when executed evidence cannot support a passed receipt."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"Cannot read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReceiptError(f"Expected a JSON object in {path}")
    return value


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReceiptError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _assert_same_commit_workspace() -> str:
    source_commit = _git_output("rev-parse", "HEAD").lower()
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReceiptError("Git HEAD is not a full 40-character commit SHA")
    dirty = _git_output(
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        *SAME_COMMIT_PATHS,
    )
    if dirty:
        raise ReceiptError(
            "GUI receipt code, application, and test inputs must be committed before execution:\n" + dirty
        )
    return source_commit


def _assert_under(path: Path, parent: Path, *, label: str) -> Path:
    resolved = path.expanduser().resolve()
    parent_resolved = parent.resolve()
    if resolved != parent_resolved and parent_resolved not in resolved.parents:
        raise ReceiptError(f"{label} must be under {parent_resolved}")
    return resolved


def _manifest_workflows(manifest: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    if manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(manifest.get("workflows"), list):
        raise ReceiptError(f"Manifest does not satisfy {MANIFEST_SCHEMA}")
    workflows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in manifest["workflows"]:
        if not isinstance(raw, dict):
            raise ReceiptError("Every GUI workflow manifest entry must be an object")
        workflow_id = raw.get("id")
        steps = raw.get("browser_steps")
        postcondition = raw.get("persisted_postcondition")
        if (
            not isinstance(workflow_id, str)
            or not workflow_id
            or workflow_id in seen
            or not isinstance(steps, list)
            or not steps
            or not all(isinstance(step, str) and step for step in steps)
            or not isinstance(postcondition, dict)
            or not isinstance(postcondition.get("owner"), str)
            or not isinstance(postcondition.get("request"), str)
            or not isinstance(postcondition.get("assert"), list)
            or not postcondition["assert"]
            or not all(isinstance(assertion, str) and assertion for assertion in postcondition["assert"])
        ):
            raise ReceiptError(f"Invalid GUI workflow manifest entry: {raw!r}")
        seen.add(workflow_id)
        workflows.append(raw)
    if not workflows:
        raise ReceiptError("GUI workflow manifest selects no workflows")
    return tuple(workflows)


def _valid_png(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    except OSError:
        return False


def _report_sections(report: str) -> dict[str, str]:
    matches = list(re.finditer(r"(?m)^### \d+\. ([a-z0-9-]+) on .+$", report))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        workflow_id = match.group(1)
        if workflow_id in sections:
            raise ReceiptError(f"GUI smoke report repeats workflow {workflow_id}")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(report)
        sections[workflow_id] = report[match.start() : end]
    return sections


def _resolved_bindings(template_request: str, resolved_request: str, *, run_id: str) -> dict[str, str]:
    names = re.findall(r"\{([a-z][a-z0-9_]*)\}", template_request)
    if not names:
        return {"run_id": run_id}
    parts = re.split(r"(\{[a-z][a-z0-9_]*\})", template_request)
    pattern: list[str] = []
    seen: set[str] = set()
    for part in parts:
        placeholder = re.fullmatch(r"\{([a-z][a-z0-9_]*)\}", part)
        if placeholder is None:
            pattern.append(re.escape(part))
            continue
        name = placeholder.group(1)
        if name in seen:
            pattern.append(f"(?P={name})")
        else:
            pattern.append(f"(?P<{name}>[^/?&#]+)")
            seen.add(name)
    match = re.fullmatch("".join(pattern), resolved_request)
    if match is None:
        raise ReceiptError(
            f"Resolved owner request {resolved_request!r} does not match manifest request {template_request!r}"
        )
    return {name: unquote(match.group(name)) for name in names}


def _line_value(section: str, prefix: str) -> str:
    for line in section.splitlines():
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
            if value:
                return value
    raise ReceiptError(f"GUI smoke report section lacks {prefix.strip()}")


def _screenshot_path(report_path: Path, section: str, label: str) -> Path:
    pattern = rf"(?m)^{re.escape(label)}: !\[[^]]+\]\(([^)]+)\)$"
    match = re.search(pattern, section)
    if match is None:
        raise ReceiptError(f"GUI smoke report section lacks {label} screenshot")
    path = (report_path.parent / match.group(1)).resolve()
    _assert_under(path, ROOT, label=f"{label} screenshot")
    if not _valid_png(path):
        raise ReceiptError(f"{label} screenshot is not a valid PNG: {path}")
    return path


def build_smoke_guide_evidence(
    *,
    manifest: Mapping[str, Any],
    result: Mapping[str, Any],
    environment: str,
    service_commit: str,
) -> dict[str, Any]:
    """Convert one completed real GUI smoke guide into structured evidence."""
    workflows = _manifest_workflows(manifest)
    if environment not in ENVIRONMENTS:
        raise ReceiptError(f"Unsupported GUI receipt environment: {environment!r}")
    if not COMMIT_RE.fullmatch(service_commit.lower()):
        raise ReceiptError("Owning Marvain service did not report a full commit SHA")
    run_id = result.get("run_id")
    if (
        result.get("ok") is not True
        or result.get("status") != "PASS"
        or not isinstance(run_id, str)
        or not run_id
        or result.get("pages") != len(workflows)
        or result.get("passed") != len(workflows)
        or result.get("blocked") != 0
        or result.get("failed") != 0
        or result.get("blockers") != []
        or result.get("failures") != []
    ):
        raise ReceiptError("GUI smoke guide did not pass every declared workflow without blockers")

    report_value = result.get("report_path")
    if not isinstance(report_value, str):
        raise ReceiptError("GUI smoke guide result has no report path")
    report_path = _assert_under(Path(report_value), ROOT, label="GUI smoke report")
    try:
        report = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReceiptError(f"Cannot read GUI smoke report {report_path}: {exc}") from exc
    if f"- Run ID: `{run_id}`" not in report or "- Result: `PASS`" not in report:
        raise ReceiptError("GUI smoke report does not match the passed structured result")
    sections = _report_sections(report)
    expected_ids = {str(workflow["id"]) for workflow in workflows}
    if set(sections) != expected_ids:
        raise ReceiptError("GUI smoke report workflow set differs from the manifest")

    evidence_workflows: list[dict[str, Any]] = []
    for workflow in workflows:
        workflow_id = str(workflow["id"])
        section = sections[workflow_id]
        if "Status: `PASS`" not in section:
            raise ReceiptError(f"{workflow_id}: GUI smoke report status is not PASS")
        for step in workflow["browser_steps"]:
            if not re.search(rf"(?m)^\d+\. {re.escape(step)}$", section):
                raise ReceiptError(f"{workflow_id}: browser step was not executed: {step}")

        postcondition = workflow["persisted_postcondition"]
        owner = str(postcondition["owner"])
        template_request = str(postcondition["request"])
        if f"- Owner: `{owner}`" not in section or f"- Request: `{template_request}`" not in section:
            raise ReceiptError(f"{workflow_id}: owner postcondition differs from the manifest")
        resolved_request = _line_value(section, "- Resolved owner request: ").strip("`")
        if resolved_request == "not resolved":
            raise ReceiptError(f"{workflow_id}: owner postcondition request was not resolved")
        record_ids = _resolved_bindings(template_request, resolved_request, run_id=run_id)

        assertion_results: list[dict[str, str]] = []
        for assertion in postcondition["assert"]:
            prefix = f"- Owner evidence: {assertion}: "
            concrete_evidence = _line_value(section, prefix)
            assertion_results.append(
                {
                    "description": assertion,
                    "status": "passed",
                    "evidence": concrete_evidence,
                }
            )

        screenshot_paths = {
            "before": _screenshot_path(report_path, section, "Before"),
            "before_submit": _screenshot_path(report_path, section, "Just before submit"),
            "after_submit": _screenshot_path(report_path, section, "After submit"),
        }
        evidence_workflows.append(
            {
                "id": workflow_id,
                "status": "passed",
                "test_nodeid": PLAYWRIGHT_TEST_NODEID,
                "steps": [{"name": step, "status": "passed"} for step in workflow["browser_steps"]],
                "persisted_postcondition": {
                    "status": "passed",
                    "owner": owner,
                    "request": template_request,
                    "resolved_request": resolved_request,
                    "record_ids": record_ids,
                    "assertions": assertion_results,
                },
                "screenshots": {phase: str(path.relative_to(ROOT)) for phase, path in screenshot_paths.items()},
            }
        )

    return {
        "schema": GUIDE_EVIDENCE_SCHEMA,
        "status": "passed",
        "runner": "playwright",
        "run_id": run_id,
        "environment": environment,
        "service_commit": service_commit.lower(),
        "report_path": str(report_path.relative_to(ROOT)),
        "workflows": evidence_workflows,
    }


def write_smoke_guide_event(payload: Mapping[str, Any]) -> None:
    raw_path = os.environ.get(EVENT_PATH_ENV)
    if not raw_path:
        raise ReceiptError(f"{EVENT_PATH_ENV} is required")
    _write_json_atomic(Path(raw_path).resolve(), payload)


def build_receipt(
    *,
    manifest: Mapping[str, Any],
    evidence: Mapping[str, Any],
    source_commit: str,
    command: str,
    completed_at: str,
) -> dict[str, Any]:
    workflows = _manifest_workflows(manifest)
    if not COMMIT_RE.fullmatch(source_commit.lower()):
        raise ReceiptError("Receipt source commit must be a full Git SHA")
    if (
        evidence.get("schema") != GUIDE_EVIDENCE_SCHEMA
        or evidence.get("status") != "passed"
        or evidence.get("runner") != "playwright"
        or evidence.get("service_commit") != source_commit.lower()
        or evidence.get("environment") not in ENVIRONMENTS
        or not isinstance(evidence.get("run_id"), str)
        or not evidence["run_id"]
        or not isinstance(evidence.get("workflows"), list)
    ):
        raise ReceiptError("Executed GUI evidence is not passed same-commit Playwright proof")

    results: dict[str, dict[str, Any]] = {}
    for raw in evidence["workflows"]:
        workflow_id = raw.get("id") if isinstance(raw, dict) else None
        if not isinstance(workflow_id, str) or workflow_id in results:
            raise ReceiptError(f"Invalid or duplicate executed workflow evidence: {raw!r}")
        results[workflow_id] = raw

    expected_ids = {str(workflow["id"]) for workflow in workflows}
    if set(results) != expected_ids:
        raise ReceiptError("Executed GUI evidence does not cover the exact manifest workflow set")
    for workflow in workflows:
        workflow_id = str(workflow["id"])
        result = results[workflow_id]
        postcondition = result.get("persisted_postcondition")
        screenshots = result.get("screenshots")
        if (
            result.get("status") != "passed"
            or result.get("test_nodeid") != PLAYWRIGHT_TEST_NODEID
            or not isinstance(postcondition, dict)
            or postcondition.get("status") != "passed"
            or postcondition.get("owner") != workflow["persisted_postcondition"]["owner"]
            or postcondition.get("request") != workflow["persisted_postcondition"]["request"]
            or not isinstance(postcondition.get("record_ids"), dict)
            or not postcondition["record_ids"]
            or not isinstance(screenshots, dict)
        ):
            raise ReceiptError(f"{workflow_id}: incomplete executed workflow proof")
        actual_steps = result.get("steps")
        if actual_steps != [{"name": step, "status": "passed"} for step in workflow["browser_steps"]]:
            raise ReceiptError(f"{workflow_id}: executed steps differ from the manifest")
        expected_assertions = workflow["persisted_postcondition"]["assert"]
        actual_assertions = postcondition.get("assertions")
        if (
            not isinstance(actual_assertions, list)
            or [
                assertion.get("description")
                for assertion in actual_assertions
                if isinstance(assertion, dict)
                and assertion.get("status") == "passed"
                and isinstance(assertion.get("evidence"), str)
                and assertion["evidence"].strip()
            ]
            != expected_assertions
        ):
            raise ReceiptError(f"{workflow_id}: owning service did not prove every manifest assertion")
        for phase in ("before", "before_submit", "after_submit"):
            value = screenshots.get(phase)
            if not isinstance(value, str):
                raise ReceiptError(f"{workflow_id}: missing valid {phase} screenshot")
            screenshot_path = _assert_under(ROOT / value, ROOT, label=f"{workflow_id} {phase} screenshot")
            if not _valid_png(screenshot_path):
                raise ReceiptError(f"{workflow_id}: missing valid {phase} screenshot")

    return {
        "schema": RECEIPT_SCHEMA,
        "source_commit": source_commit.lower(),
        "status": "passed",
        "runner": "playwright",
        "exit_code": 0,
        "run_id": evidence["run_id"],
        "environment": evidence["environment"],
        "completed_at": completed_at,
        "command": command,
        "workflows": [results[str(workflow["id"])] for workflow in workflows],
    }


def run_receipt(
    *,
    base_url: str,
    environment: str,
    manifest_path: Path,
    output_path: Path,
    guide_output: Path,
) -> dict[str, Any]:
    output_path = _assert_under(output_path, ROOT / "output" / "playwright", label="workflow receipt")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    parsed_url = urlparse(base_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ReceiptError("Base URL must be an explicit http:// or https:// URL")
    if environment not in ENVIRONMENTS:
        raise ReceiptError(f"Environment must be one of: {', '.join(sorted(ENVIRONMENTS))}")
    manifest_path = _assert_under(manifest_path, ROOT, label="GUI workflow manifest")
    guide_output = _assert_under(guide_output, ROOT / "output" / "playwright", label="GUI guide output")
    manifest = _load_json(manifest_path)
    _manifest_workflows(manifest)
    source_commit = _assert_same_commit_workspace()

    event_path = output_path.with_name(f".{output_path.stem}-{uuid.uuid4().hex}.json")
    command = [sys.executable, "-m", "pytest", "-q", "--tb=short", PLAYWRIGHT_TEST_NODEID]
    env = dict(os.environ)
    env.update(
        {
            EVENT_PATH_ENV: str(event_path),
            BASE_URL_ENV: base_url,
            ENVIRONMENT_ENV: environment,
            EXPECTED_COMMIT_ENV: source_commit,
            GUIDE_OUTPUT_ENV: str(guide_output),
        }
    )
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, check=False)
        if result.returncode != 0:
            raise ReceiptError(f"Playwright workflow test failed with exit code {result.returncode}")
        if _git_output("rev-parse", "HEAD").lower() != source_commit:
            raise ReceiptError("HEAD changed while Playwright workflows were running")
        evidence = _load_json(event_path)
        receipt = build_receipt(
            manifest=manifest,
            evidence=evidence,
            source_commit=source_commit,
            command=shlex.join(command),
            completed_at=_utc_now(),
        )
        _write_json_atomic(output_path, receipt)
        return receipt
    finally:
        event_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--guide-output", type=Path, default=DEFAULT_GUIDE_OUTPUT)
    args = parser.parse_args(argv)
    try:
        receipt = run_receipt(
            base_url=args.base_url,
            environment=args.environment,
            manifest_path=args.manifest,
            output_path=args.output,
            guide_output=args.guide_output,
        )
    except ReceiptError as exc:
        print(f"GUI workflow receipt failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}: {len(receipt['workflows'])} Playwright workflows at {receipt['source_commit'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
