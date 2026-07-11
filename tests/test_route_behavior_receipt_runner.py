from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_receipt_module():
    path = ROOT / "tests" / "route_behavior_receipt.py"
    spec = importlib.util.spec_from_file_location("marvain_route_behavior_receipt_for_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest() -> dict:
    nodeids = {
        "success": "tests/test_widget_routes.py::test_create_widget_success",
        "denial": "tests/test_widget_routes.py::test_create_widget_denial",
        "validation": "tests/test_widget_routes.py::test_create_widget_validation",
        "postcondition": "tests/test_widget_routes.py::test_create_widget_postcondition",
    }
    return {
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
    }


def _events() -> list[dict]:
    statuses = {"success": 201, "denial": 403, "validation": 422}
    events = [
        {
            "surface": "api",
            "method": "POST",
            "path": "/v1/widgets",
            "kind": kind,
            "test_nodeid": f"tests/test_widget_routes.py::test_create_widget_{kind}",
            "evidence": {
                "status": "passed",
                "test_nodeid": f"tests/test_widget_routes.py::test_create_widget_{kind}",
                "http_status": status,
            },
        }
        for kind, status in statuses.items()
    ]
    events.append(
        {
            "surface": "api",
            "method": "POST",
            "path": "/v1/widgets",
            "kind": "postcondition",
            "test_nodeid": "tests/test_widget_routes.py::test_create_widget_postcondition",
            "evidence": {
                "status": "passed",
                "test_nodeid": "tests/test_widget_routes.py::test_create_widget_postcondition",
                "owner": "widget-service",
                "query": "GET /v1/widgets/{widget_id}",
                "record_ids": {"widget_id": "widget-1"},
                "assertions": [{"description": "stored widget matches", "status": "passed"}],
            },
        }
    )
    return events


def test_build_receipt_accepts_complete_executed_evidence() -> None:
    receipt_module = _load_receipt_module()

    receipt = receipt_module.build_receipt(
        manifest=_manifest(),
        events=_events(),
        source_commit="a" * 40,
        command="python -m pytest tests/test_widget_routes.py",
        run_id="route-test-run",
        completed_at="2026-07-11T00:00:00Z",
    )

    assert receipt["status"] == "passed"
    assert receipt["source_commit"] == "a" * 40
    assert receipt["results"][0]["evidence"]["postcondition"]["record_ids"] == {"widget_id": "widget-1"}


def test_build_receipt_rejects_missing_required_evidence() -> None:
    receipt_module = _load_receipt_module()

    with pytest.raises(receipt_module.ReceiptError, match="Missing executed validation evidence"):
        receipt_module.build_receipt(
            manifest=_manifest(),
            events=[event for event in _events() if event["kind"] != "validation"],
            source_commit="a" * 40,
            command="python -m pytest tests/test_widget_routes.py",
            run_id="route-test-run",
            completed_at="2026-07-11T00:00:00Z",
        )


def test_manifest_requires_explicit_test_for_each_required_class() -> None:
    receipt_module = _load_receipt_module()
    manifest = _manifest()
    del manifest["routes"][0]["tests"]["denial"]

    with pytest.raises(receipt_module.ReceiptError, match="denial requires an explicit pytest node ID"):
        receipt_module.manifest_nodeids(manifest)
