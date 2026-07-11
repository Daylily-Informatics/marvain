#!/usr/bin/env python3
"""Execute focused route tests and emit a same-commit behavior receipt.

The committed manifest selects explicit pytest node IDs. Those tests emit the
HTTP outcomes and persisted readback assertions they actually observed. This
runner writes the ignored receipt only when pytest and every required evidence
class pass.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from _pytest.fixtures import FixtureRequest

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "route_behavior_manifest.json"
DEFAULT_OUTPUT = ROOT / "output" / "coverage" / "route_behavior_receipt.json"
EVENTS_ENV = "MARVAIN_ROUTE_BEHAVIOR_EVENTS"
MANIFEST_SCHEMA = "marvain.route-behavior-manifest.v1"
RECEIPT_SCHEMA = "marvain.route-behavior-receipt.v1"
BEHAVIOR_CLASSES = ("success", "denial", "validation", "postcondition")
HTTP_STATUS_CLASSES = {
    "success": range(200, 400),
    "denial": {401, 403},
    "validation": {400, 409, 415, 422},
}


class ReceiptError(RuntimeError):
    """Raised when executed evidence cannot support a passed receipt."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _nodeid(request: FixtureRequest) -> str:
    return str(request.node.nodeid)


def _events_path() -> Path | None:
    raw = os.environ.get(EVENTS_ENV)
    return Path(raw).resolve() if raw else None


def _append_event(event: Mapping[str, Any]) -> None:
    path = _events_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(event), sort_keys=True) + "\n")


def record_http_evidence(
    request: FixtureRequest,
    *,
    surface: str,
    method: str,
    path: str,
    kind: str,
    response: Any,
) -> None:
    """Record an HTTP status observed by the currently executing test."""
    if kind not in HTTP_STATUS_CLASSES:
        raise AssertionError(f"{kind!r} is not an HTTP behavior class")
    status = getattr(response, "status_code", None)
    if not isinstance(status, int) or status not in HTTP_STATUS_CLASSES[kind]:
        raise AssertionError(f"HTTP {status!r} does not satisfy {kind} evidence")
    _append_event(
        {
            "surface": surface,
            "method": method.upper(),
            "path": path,
            "kind": kind,
            "test_nodeid": _nodeid(request),
            "evidence": {
                "status": "passed",
                "test_nodeid": _nodeid(request),
                "http_status": status,
            },
        }
    )


def record_postcondition_evidence(
    request: FixtureRequest,
    *,
    surface: str,
    method: str,
    path: str,
    owner: str,
    query: str,
    record_ids: Mapping[str, str],
    assertions: Sequence[str],
) -> None:
    """Record assertions made after an explicit persisted-state readback."""
    if not owner.strip() or not query.strip():
        raise AssertionError("postcondition owner and query are required")
    normalized_ids = {str(key): str(value) for key, value in record_ids.items() if str(value).strip()}
    normalized_assertions = [str(value).strip() for value in assertions if str(value).strip()]
    if not normalized_ids or not normalized_assertions:
        raise AssertionError("postcondition evidence requires record IDs and assertions")
    _append_event(
        {
            "surface": surface,
            "method": method.upper(),
            "path": path,
            "kind": "postcondition",
            "test_nodeid": _nodeid(request),
            "evidence": {
                "status": "passed",
                "test_nodeid": _nodeid(request),
                "owner": owner,
                "query": query,
                "record_ids": normalized_ids,
                "assertions": [
                    {"description": description, "status": "passed"} for description in normalized_assertions
                ],
            },
        }
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"Cannot read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReceiptError(f"Expected a JSON object in {path}")
    return value


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        return events
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReceiptError(f"Invalid event JSON at {path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ReceiptError(f"Expected an event object at {path}:{line_number}")
        events.append(value)
    return events


def _is_required(value: object) -> bool:
    return value == "required"


def _is_not_applicable(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("status") == "not_applicable"
        and isinstance(value.get("reason"), str)
        and len(value["reason"].strip()) >= 12
    )


def manifest_nodeids(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    if manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(manifest.get("routes"), list):
        raise ReceiptError(f"Manifest does not satisfy {MANIFEST_SCHEMA}")
    nodeids: set[str] = set()
    seen_routes: set[tuple[str, str, str]] = set()
    for route in manifest["routes"]:
        if not isinstance(route, dict):
            raise ReceiptError("Every manifest route must be an object")
        surface = route.get("surface")
        method = route.get("method")
        path = route.get("path")
        if surface not in {"api", "gui"} or not isinstance(method, str) or not isinstance(path, str):
            raise ReceiptError(f"Invalid route identity: {route!r}")
        key = (surface, method.upper(), path.split("?", 1)[0])
        if key in seen_routes:
            raise ReceiptError(f"Duplicate route in manifest: {key}")
        seen_routes.add(key)
        requirements = route.get("requirements")
        tests = route.get("tests")
        if not isinstance(requirements, dict) or not isinstance(tests, dict):
            raise ReceiptError(f"{key}: requirements and tests are required")
        for kind in BEHAVIOR_CLASSES:
            requirement = requirements.get(kind)
            if not _is_required(requirement) and not _is_not_applicable(requirement):
                raise ReceiptError(f"{key}: {kind} must be required or explicitly not applicable")
            if _is_required(requirement):
                nodeid = tests.get(kind)
                if not isinstance(nodeid, str) or "::test_" not in nodeid:
                    raise ReceiptError(f"{key}: {kind} requires an explicit pytest node ID")
                nodeids.add(nodeid)
    if not nodeids:
        raise ReceiptError("Manifest selects no executable tests")
    return tuple(sorted(nodeids))


def build_receipt(
    *,
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    source_commit: str,
    command: str,
    run_id: str,
    completed_at: str,
) -> dict[str, Any]:
    manifest_nodeids(manifest)
    indexed: dict[tuple[str, str, str, str, str], Mapping[str, Any]] = {}
    for event in events:
        identity = (
            str(event.get("surface")),
            str(event.get("method")).upper(),
            str(event.get("path")).split("?", 1)[0],
            str(event.get("kind")),
            str(event.get("test_nodeid")),
        )
        if identity in indexed:
            raise ReceiptError(f"Duplicate executed evidence: {identity}")
        indexed[identity] = event

    results: list[dict[str, Any]] = []
    for route in manifest["routes"]:
        surface = str(route["surface"])
        method = str(route["method"]).upper()
        path = str(route["path"]).split("?", 1)[0]
        requirements = route["requirements"]
        tests = route["tests"]
        evidence: dict[str, Any] = {}
        for kind in BEHAVIOR_CLASSES:
            if not _is_required(requirements[kind]):
                continue
            nodeid = str(tests[kind])
            event = indexed.get((surface, method, path, kind, nodeid))
            if event is None or not isinstance(event.get("evidence"), dict):
                raise ReceiptError(f"Missing executed {kind} evidence for {surface} {method} {path} from {nodeid}")
            evidence[kind] = dict(event["evidence"])
        results.append(
            {
                "surface": surface,
                "method": method,
                "path": path,
                "status": "passed",
                "evidence": evidence,
            }
        )

    return {
        "schema": RECEIPT_SCHEMA,
        "source_commit": source_commit,
        "status": "passed",
        "runner": "pytest",
        "exit_code": 0,
        "run_id": run_id,
        "completed_at": completed_at,
        "command": command,
        "results": results,
    }


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


def _assert_receipt_inputs_committed(manifest: Mapping[str, Any], manifest_path: Path) -> str:
    source_commit = _git_output("rev-parse", "HEAD").lower()
    test_paths = {str(nodeid).split("::", 1)[0] for nodeid in manifest_nodeids(manifest)}
    relevant = sorted(
        {
            str(manifest_path.relative_to(ROOT)),
            "tests/route_behavior_receipt.py",
            "functions/hub_api/api_app.py",
            "functions/hub_api/app.py",
            *test_paths,
        }
    )
    dirty = _git_output("status", "--porcelain", "--untracked-files=all", "--", *relevant)
    if dirty:
        raise ReceiptError("Receipt inputs must be committed before execution:\n" + dirty)
    return source_commit


def run_receipt(*, manifest_path: Path, output_path: Path) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    source_commit = _assert_receipt_inputs_committed(manifest, manifest_path)
    nodeids = manifest_nodeids(manifest)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)
    events_path = output_path.with_name(f".{output_path.stem}-{uuid.uuid4().hex}.jsonl")
    command = [sys.executable, "-m", "pytest", "-q", "--tb=short", *nodeids]
    env = dict(os.environ)
    env[EVENTS_ENV] = str(events_path)
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode != 0:
        events_path.unlink(missing_ok=True)
        raise ReceiptError(f"Focused route tests failed with exit code {result.returncode}")
    if _git_output("rev-parse", "HEAD").lower() != source_commit:
        events_path.unlink(missing_ok=True)
        raise ReceiptError("HEAD changed while route behavior tests were running")
    try:
        receipt = build_receipt(
            manifest=manifest,
            events=_load_events(events_path),
            source_commit=source_commit,
            command=shlex.join(command),
            run_id=f"route-behavior-{uuid.uuid4()}",
            completed_at=_utc_now(),
        )
    finally:
        events_path.unlink(missing_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        receipt = run_receipt(manifest_path=args.manifest.resolve(), output_path=args.output.resolve())
    except ReceiptError as exc:
        print(f"route behavior receipt failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}: {len(receipt['results'])} route behaviors at {receipt['source_commit'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
