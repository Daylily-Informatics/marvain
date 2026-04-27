from __future__ import annotations

import dataclasses
import importlib.util
import socket
import sys
import threading
import time
import types
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from marvain_cli.smoke import GUI_SMOKE_PAGES, run_gui_smoke_guide

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]


def _load_workflow_helpers():
    path = ROOT / "tests" / "e2e" / "test_gui_workflows_playwright.py"
    spec = importlib.util.spec_from_file_location("marvain_gui_workflow_helpers", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gui_module():
    helpers = _load_workflow_helpers()
    mod = helpers._load_hub_app_module()
    fake_db = helpers._FakeDb()
    fake_s3 = helpers._FakeS3()
    helpers._install_semantic_tapdb_fake()

    def fake_tapdb_web_app(*, config_path, env_name, host_bridge):  # noqa: ARG001
        tapdb = FastAPI()

        @tapdb.get("/graph")
        async def graph() -> HTMLResponse:
            return HTMLResponse("<html><body><h1>Graph</h1><div id='cy'>fixture graph</div></body></html>")

        @tapdb.get("/query")
        async def query() -> HTMLResponse:
            return HTMLResponse(
                "<html><body><h1>Query</h1><table><tr><td>MVN-MEMORY-QA</td></tr></table></body></html>"
            )

        @tapdb.get("/")
        async def index() -> HTMLResponse:
            return HTMLResponse("<html><body><h1>TapDB</h1></body></html>")

        return tapdb

    mod.validate_configuration_or_fail = lambda: None
    mod._cfg = dataclasses.replace(
        mod._cfg,
        stage="test",
        artifact_bucket="qa-artifacts",
        audit_bucket="qa-audit",
        ws_api_url=None,
        livekit_url="wss://livekit.example.test",
        livekit_secret_arn="arn:livekit",
        openai_secret_arn="arn:openai",
        cognito_region="us-east-1",
        cognito_domain="auth.example.test",
        cognito_user_pool_id="pool-test",
        cognito_user_pool_client_id="client-test",
    )
    mod._get_db = lambda: fake_db
    mod._get_s3 = lambda: fake_s3
    mod.get_secret_json = lambda arn: {"api_key": "test", "api_secret": "secret"}
    mod._agent_worker_status_dict = lambda: {"status": "stopped", "pid": None, "log_file": None}
    mod._gui_get_user = lambda request: mod.AuthenticatedUser(
        user_id="00000000-0000-0000-0000-000000000001",
        cognito_sub="qa-sub",
        email="qa@example.test",
    )
    mod.list_agents_for_user = lambda db, user_id: [
        types.SimpleNamespace(
            agent_id=helpers.AGENT_ID,
            name="QA Agent",
            role="owner",
            relationship_label="Primary",
            disabled=False,
        )
    ]
    mod.list_spaces_for_user = lambda db, user_id: [
        types.SimpleNamespace(
            space_id=helpers.SPACE_ID,
            agent_id=helpers.AGENT_ID,
            agent_name="QA Agent",
            name="Kitchen",
            livekit_room_mode="ephemeral",
        )
    ]
    mod._resolve_tapdb_runtime_config = mock.Mock(
        return_value=mod.TapdbRuntimeConfig(config_path="/tmp/tapdb-config.yaml", env_name="test")
    )
    mod.create_tapdb_web_app = fake_tapdb_web_app
    mod._tapdb_web_asgi_app = None
    return mod


@pytest.fixture(scope="module")
def gui_base_url(gui_module) -> Iterator[str]:
    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    host, port = sock.getsockname()
    config = uvicorn.Config(gui_module.app, host=host, port=port, log_level="error", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        pytest.skip("Local uvicorn GUI server did not start")
    try:
        yield f"http://{host}:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_gui_smoke_guide_generates_step_by_step_report(gui_base_url, tmp_path) -> None:
    result = run_gui_smoke_guide(base_url=gui_base_url, output_dir=tmp_path, headless=True)

    assert result["ok"], result["failures"]
    assert result["pages"] == len(GUI_SMOKE_PAGES)
    report_path = Path(result["report_path"])
    assert report_path.exists()
    report = report_path.read_text(encoding="utf-8")
    assert "# Marvain GUI Smoke Guide" in report
    assert "Before: ![before]" in report
    assert "Just before submit: ![before submit]" in report
    assert "After submit: ![after submit]" in report
    for page in GUI_SMOKE_PAGES:
        page_dir = Path(result["output_dir"]) / page.name
        assert (page_dir / "before.png").exists()
        assert (page_dir / "before_submit.png").exists()
        assert (page_dir / "after_submit.png").exists()
