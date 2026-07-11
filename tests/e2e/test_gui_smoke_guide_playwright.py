from __future__ import annotations

import html
import json
import re
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from marvain_cli.smoke import (
    GUI_WORKFLOW_MANIFEST_PATH,
    GUI_WORKFLOW_PROOF_SCHEMA,
    GuiSmokeWorkflow,
    SmokeError,
    load_gui_workflow_manifest,
    run_gui_smoke_guide,
)

pytestmark = pytest.mark.e2e

_BINDING_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def _workflow_payload(workflow: GuiSmokeWorkflow) -> dict[str, Any]:
    return {
        "id": workflow.workflow_id,
        "page": workflow.page,
        "path": workflow.path,
        "heading": workflow.heading,
        "command": workflow.command,
        "browser_steps": list(workflow.browser_steps),
        "persisted_postcondition": {
            "owner": workflow.persisted_postcondition.owner,
            "request": workflow.persisted_postcondition.request,
            "assert": list(workflow.persisted_postcondition.assertions),
        },
    }


def _write_manifest(path: Path, workflows: tuple[GuiSmokeWorkflow, ...]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": "marvain.gui-workflows.v1",
                "screenshot_phases": ["before", "before_submit", "after_submit"],
                "workflows": [_workflow_payload(workflow) for workflow in workflows],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def _workflow_page(workflow: GuiSmokeWorkflow, *, expose_controls: bool) -> str:
    if not expose_controls:
        return f"<html><body><h1>{html.escape(workflow.heading)}</h1><p>No automation contract.</p></body></html>"
    workflow_id = json.dumps(workflow.workflow_id)
    workflow_attribute = html.escape(workflow.workflow_id, quote=True)
    return f"""
    <html>
      <body>
        <h1>{html.escape(workflow.heading)}</h1>
        <button data-marvain-smoke-prepare="{workflow_attribute}">Prepare</button>
        <button data-marvain-smoke-submit="{workflow_attribute}" hidden>Submit</button>
        <script>
          const workflowId = {workflow_id};
          const prepare = document.querySelector(`[data-marvain-smoke-prepare="${{workflowId}}"]`);
          const submit = document.querySelector(`[data-marvain-smoke-submit="${{workflowId}}"]`);
          prepare.addEventListener('click', () => {{ submit.hidden = false; }});
          submit.addEventListener('click', async () => {{
            const response = await fetch(`/__gui-smoke/command/${{workflowId}}`, {{method: 'POST'}});
            const receipt = await response.json();
            const node = document.createElement('script');
            node.type = 'application/json';
            node.dataset.marvainSmokeReceipt = workflowId;
            node.textContent = JSON.stringify(receipt);
            document.body.appendChild(node);
          }});
        </script>
      </body>
    </html>
    """


def _build_workflow_app(
    workflows: tuple[GuiSmokeWorkflow, ...],
    *,
    expose_controls: bool = True,
    failed_workflow_id: str | None = None,
) -> FastAPI:
    app = FastAPI()
    by_id = {workflow.workflow_id: workflow for workflow in workflows}
    by_path = {workflow.path.split("?", 1)[0]: workflow for workflow in workflows}
    executed: set[str] = set()

    @app.post("/__gui-smoke/command/{workflow_id}")
    async def run_command(workflow_id: str) -> JSONResponse:
        workflow = by_id.get(workflow_id)
        if workflow is None:
            raise HTTPException(status_code=404, detail="unknown workflow")
        executed.add(workflow_id)
        placeholders = _BINDING_RE.findall(workflow.persisted_postcondition.request)
        return JSONResponse(
            {
                "workflow_id": workflow_id,
                "command": workflow.command,
                "completed_browser_steps": list(workflow.browser_steps),
                "bindings": {placeholder: f"fixture-{placeholder}" for placeholder in placeholders},
            }
        )

    @app.get("/{requested_path:path}")
    async def page_or_owner_proof(
        request: Request,
        requested_path: str,
        workflow_id: str | None = Header(None, alias="X-Marvain-Gui-Smoke-Workflow-Id"),
        evidence_owner: str | None = Header(None, alias="X-Marvain-Gui-Smoke-Evidence-Owner"),
    ) -> Response:
        if workflow_id is None:
            workflow = by_path.get(f"/{requested_path}")
            if workflow is None:
                raise HTTPException(status_code=404, detail="unknown GUI page")
            return HTMLResponse(_workflow_page(workflow, expose_controls=expose_controls))

        workflow = by_id.get(workflow_id)
        if workflow is None or workflow_id not in executed:
            raise HTTPException(status_code=409, detail="workflow command has not completed")
        if evidence_owner != workflow.persisted_postcondition.owner:
            raise HTTPException(status_code=403, detail="incorrect evidence owner")
        query = f"?{request.url.query}" if request.url.query else ""
        resolved_request = f"GET {request.url.path}{query}"
        assertion_proofs = []
        for index, assertion in enumerate(workflow.persisted_postcondition.assertions):
            passed = not (workflow_id == failed_workflow_id and index == 0)
            assertion_proofs.append(
                {
                    "assert": assertion,
                    "passed": passed,
                    "evidence": f"persisted owner receipt for {workflow_id} assertion {index + 1}",
                }
            )
        return JSONResponse(
            {
                "workflow_proof": {
                    "schema": GUI_WORKFLOW_PROOF_SCHEMA,
                    "workflow_id": workflow_id,
                    "owner": workflow.persisted_postcondition.owner,
                    "request": resolved_request,
                    "assertions": assertion_proofs,
                }
            }
        )

    return app


@contextmanager
def _serve_app(app: FastAPI) -> Iterator[str]:
    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    host, port = sock.getsockname()
    config = uvicorn.Config(app, host=host, port=port, log_level="error", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        pytest.skip("Local GUI smoke fixture server did not start")
    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_gui_smoke_guide_verifies_every_manifest_workflow(tmp_path: Path) -> None:
    workflows = load_gui_workflow_manifest()
    with _serve_app(_build_workflow_app(workflows)) as base_url:
        result = run_gui_smoke_guide(base_url=base_url, output_dir=tmp_path, headless=True)

    assert result["ok"], result
    assert result["status"] == "PASS"
    assert result["pages"] == len(workflows)
    assert result["passed"] == len(workflows)
    assert result["blocked"] == 0
    assert result["failed"] == 0
    assert result["blockers"] == []
    assert result["failures"] == []

    report_path = Path(result["report_path"])
    report = report_path.read_text(encoding="utf-8")
    assert "# Marvain GUI Smoke Guide" in report
    assert "- Result: `PASS`" in report
    assert "Before: ![before]" in report
    assert "Just before submit: ![before submit]" in report
    assert "After submit: ![after submit]" in report
    for workflow in workflows:
        assert "### " in report and workflow.workflow_id in report
        assert f"Command: {workflow.command}" in report
        assert f"- Owner: `{workflow.persisted_postcondition.owner}`" in report
        assert f"- Request: `{workflow.persisted_postcondition.request}`" in report
        for step in workflow.browser_steps:
            assert step in report
        for assertion in workflow.persisted_postcondition.assertions:
            assert f"- Assert: {assertion}" in report
        page_dir = Path(result["output_dir"]) / workflow.page
        assert (page_dir / "before.png").exists()
        assert (page_dir / "before_submit.png").exists()
        assert (page_dir / "after_submit.png").exists()


def test_gui_smoke_guide_blocks_missing_named_workflow_control(tmp_path: Path) -> None:
    workflow = load_gui_workflow_manifest()[0]
    manifest_path = _write_manifest(tmp_path / "blocked-manifest.json", (workflow,))
    with _serve_app(_build_workflow_app((workflow,), expose_controls=False)) as base_url:
        result = run_gui_smoke_guide(
            base_url=base_url,
            output_dir=tmp_path / "blocked-output",
            headless=True,
            manifest_path=manifest_path,
        )

    assert not result["ok"]
    assert result["status"] == "BLOCKED"
    assert result["passed"] == 0
    assert result["blocked"] == 1
    assert result["failed"] == 0
    assert "required page-specific control is absent" in result["blockers"][0]
    report = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "- Result: `BLOCKED`" in report
    assert f"Command: {workflow.command}" in report
    assert f"- Request: `{workflow.persisted_postcondition.request}`" in report
    page_dir = Path(result["output_dir"]) / workflow.page
    assert (page_dir / "before.png").exists()
    assert (page_dir / "before_submit.png").exists()
    assert (page_dir / "after_submit.png").exists()


def test_gui_smoke_guide_fails_unverified_owner_postcondition(tmp_path: Path) -> None:
    workflow = load_gui_workflow_manifest()[0]
    manifest_path = _write_manifest(tmp_path / "failed-manifest.json", (workflow,))
    with _serve_app(_build_workflow_app((workflow,), failed_workflow_id=workflow.workflow_id)) as base_url:
        result = run_gui_smoke_guide(
            base_url=base_url,
            output_dir=tmp_path / "failed-output",
            headless=True,
            manifest_path=manifest_path,
        )

    assert not result["ok"]
    assert result["status"] == "FAIL"
    assert result["passed"] == 0
    assert result["blocked"] == 0
    assert result["failed"] == 1
    assert "owner did not verify assertion" in result["failures"][0]
    report = Path(result["report_path"]).read_text(encoding="utf-8")
    assert "- Result: `FAIL`" in report


def test_gui_smoke_manifest_fails_hard_instead_of_discovering_another_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(SmokeError, match="does not exist"):
        load_gui_workflow_manifest(missing)

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"schema": "wrong"}', encoding="utf-8")
    with pytest.raises(SmokeError, match="invalid keys"):
        load_gui_workflow_manifest(malformed)

    assert GUI_WORKFLOW_MANIFEST_PATH.is_file()
