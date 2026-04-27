from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import socket
import sys
import threading
import time
import types
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]
AGENT_ID = "11111111-1111-1111-1111-111111111111"
SPACE_ID = "22222222-2222-2222-2222-222222222222"
DEVICE_ID = "33333333-3333-3333-3333-333333333333"
PERSON_ID = "44444444-4444-4444-4444-444444444444"
SESSION_ID = "55555555-5555-5555-5555-555555555555"
ACTION_ID = "66666666-6666-6666-6666-666666666666"
MEMORY_ID = "77777777-7777-7777-7777-777777777777"
EVENT_ID = "88888888-8888-8888-8888-888888888888"
LOCATION_ID = "99999999-9999-9999-9999-999999999999"
PERSONA_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


class _FakeDb:
    def __init__(self) -> None:
        self.executed: list[tuple[str, dict | None]] = []

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        text = " ".join(sql.lower().split())
        now = datetime.now(timezone.utc)
        if "select count(*) as cnt from devices" in text:
            return [{"cnt": 1}]
        if "select count(*) as cnt from actions" in text:
            return [{"cnt": 1}]
        if "from devices d join agents" in text:
            return [self._device_row(now)]
        if "from devices where agent_id::text" in text:
            return [self._space_extra(now)]
        if "from actions ac join agents" in text:
            return [self._action_row(now, text_values="recent-actions" in text or "created_at::text" in text)]
        if "from agents a left join" in text and "online_devices" in text:
            return [
                {
                    "agent_id": AGENT_ID,
                    "name": "QA Agent",
                    "disabled": False,
                    "online_devices": 1,
                    "total_devices": 1,
                }
            ]
        if "from events e join agents" in text:
            return [self._event_row()]
        if "from spaces where space_id::text" in text:
            return [self._space_extra(now)]
        if "from people p" in text and "join agents" in text:
            return [self._person_row(now)]
        if "from consent_grants" in text:
            return [self._consent_row()]
        if "from memories m" in text:
            return [self._memory_row(now)]
        if "from people where agent_id::text" in text:
            return [{"person_id": PERSON_ID, "display_name": "QA Person"}]
        if "from locations l" in text:
            return [self._location_row()]
        if "from sessions se" in text:
            return [self._session_row()]
        if "from recognition_observations ro" in text:
            return [self._recognition_observation_row()]
        if "from recognition_hypotheses rh" in text:
            return [self._recognition_hypothesis_row()]
        if "from presence_assertions pa" in text:
            return [self._presence_row()]
        if "from artifact_references ar" in text:
            return [self._artifact_reference_row()]
        if "from voiceprints vp" in text or "from faceprints fp" in text:
            return [self._revocation_row()]
        if "from semantic_sync_status" in text:
            return [self._semantic_sync_row()]
        if "devices_total" in text and "semantic_failures" in text:
            return [
                {
                    "devices_total": 1,
                    "devices_online": 1,
                    "actions_pending": 1,
                    "actions_waiting": 0,
                    "memories_committed": 1,
                    "recognition_observations": 1,
                    "semantic_failures": 0,
                }
            ]
        if "from personas" in text:
            return [self._persona_row()]
        return []

    def execute(self, sql: str, params: dict | None = None) -> dict:
        self.executed.append((sql, params))
        return {"ok": True}

    def _device_row(self, now: datetime) -> dict:
        return {
            "device_id": DEVICE_ID,
            "agent_id": AGENT_ID,
            "name": "QA Kitchen Display",
            "scopes": json.dumps(["events:read", "actions:write"]),
            "revoked_at": None,
            "created_at": now,
            "last_seen": now,
            "last_heartbeat_at": now,
            "location_label": "Kitchen",
            "location_coords": json.dumps({"lat": 37.0, "lon": -122.0}),
            "is_online": True,
            "agent_name": "QA Agent",
            "metadata": json.dumps({"location_space_id": SPACE_ID}),
        }

    def _space_extra(self, now: datetime) -> dict:
        return {"space_id": SPACE_ID, "privacy_mode": False, "created_at": now}

    def _action_row(self, now: datetime, *, text_values: bool = False) -> dict:
        created_at = "2026-04-27T12:00:00+00:00" if text_values else now
        return {
            "action_id": ACTION_ID,
            "agent_id": AGENT_ID,
            "space_id": SPACE_ID,
            "kind": "device.notify",
            "payload": json.dumps({"message": "QA deterministic action"}),
            "required_scopes": json.dumps(["actions:write"]),
            "status": "proposed",
            "created_at": created_at,
            "updated_at": created_at,
            "executed_at": None,
            "agent_name": "QA Agent",
            "space_name": "Kitchen",
        }

    def _event_row(self) -> dict:
        return {
            "event_id": EVENT_ID,
            "session_id": SESSION_ID,
            "agent_id": AGENT_ID,
            "space_id": SPACE_ID,
            "person_id": PERSON_ID,
            "type": "chat.message",
            "payload": json.dumps({"text": "QA event text"}),
            "created_at": "2026-04-27T12:00:00+00:00",
            "agent_name": "QA Agent",
            "space_name": "Kitchen",
        }

    def _person_row(self, now: datetime) -> dict:
        return {
            "person_id": PERSON_ID,
            "agent_id": AGENT_ID,
            "display_name": "QA Person",
            "created_at": now,
            "agent_name": "QA Agent",
        }

    def _consent_row(self) -> dict:
        return {
            "consent_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "agent_id": AGENT_ID,
            "person_id": PERSON_ID,
            "person_name": "QA Person",
            "consent_type": "voice",
            "status": "active",
            "expires_at": None,
            "revoked_at": None,
        }

    def _memory_row(self, now: datetime) -> dict:
        return {
            "memory_id": MEMORY_ID,
            "agent_id": AGENT_ID,
            "space_id": SPACE_ID,
            "tier": "episodic",
            "content": "QA deterministic memory about the kitchen display.",
            "participants": json.dumps(["QA Person"]),
            "provenance": json.dumps({"source": "playwright"}),
            "created_at": now,
            "agent_name": "QA Agent",
            "space_name": "Kitchen",
            "subject_person_id": PERSON_ID,
            "subject_person_name": "QA Person",
            "tags": ["qa"],
            "scene_context": "Kitchen",
            "modality": "text",
            "confidence": 1.0,
            "related_memory_ids": [],
        }

    def _location_row(self) -> dict:
        return {
            "location_id": LOCATION_ID,
            "agent_id": AGENT_ID,
            "agent_name": "QA Agent",
            "name": "QA Home",
            "description": "Deterministic location",
            "address": "Local test",
            "metadata": json.dumps({"kind": "home"}),
            "tapdb_euid": "MVN-LOCATION-QA",
            "space_count": 1,
            "device_count": 1,
        }

    def _session_row(self) -> dict:
        return {
            "session_id": SESSION_ID,
            "agent_id": AGENT_ID,
            "agent_name": "QA Agent",
            "space_id": SPACE_ID,
            "space_name": "Kitchen",
            "location_id": LOCATION_ID,
            "location_name": "QA Home",
            "persona_id": PERSONA_ID,
            "persona_name": "QA Persona",
            "livekit_room": "qa-room",
            "status": "open",
            "started_at": "2026-04-27T12:00:00+00:00",
            "ended_at": None,
            "metadata": json.dumps({"source": "playwright"}),
            "event_count": 1,
            "memory_count": 1,
            "action_count": 1,
        }

    def _recognition_observation_row(self) -> dict:
        return {
            "observation_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "agent_id": AGENT_ID,
            "space_id": SPACE_ID,
            "location_id": LOCATION_ID,
            "device_id": DEVICE_ID,
            "session_id": SESSION_ID,
            "artifact_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "modality": "voice",
            "lifecycle_state": "matched",
            "model_name": "qa-model",
            "created_at": "2026-04-27T12:00:00+00:00",
            "agent_name": "QA Agent",
            "space_name": "Kitchen",
            "location_name": "QA Home",
            "device_name": "QA Kitchen Display",
        }

    def _recognition_hypothesis_row(self) -> dict:
        return {
            "hypothesis_id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            "observation_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "agent_id": AGENT_ID,
            "candidate_person_id": PERSON_ID,
            "person_name": "QA Person",
            "score": 0.91,
            "decision": "accepted",
            "consent_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "created_at": "2026-04-27T12:00:00+00:00",
            "reason": "deterministic",
        }

    def _presence_row(self) -> dict:
        return {
            "presence_assertion_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "agent_id": AGENT_ID,
            "person_id": PERSON_ID,
            "person_name": "QA Person",
            "space_id": SPACE_ID,
            "space_name": "Kitchen",
            "location_id": LOCATION_ID,
            "location_name": "QA Home",
            "status": "present",
            "source": "recognition",
            "asserted_at": "2026-04-27T12:00:00+00:00",
        }

    def _artifact_reference_row(self) -> dict:
        return {
            "artifact_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "agent_id": AGENT_ID,
            "observation_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "kind": "audio/wav",
            "uri": "s3://qa-artifacts/voice.wav",
            "lifecycle_state": "available",
            "created_at": "2026-04-27T12:00:00+00:00",
        }

    def _revocation_row(self) -> dict:
        return {
            "agent_id": AGENT_ID,
            "subject": "QA Person voice enrollment",
            "status": "not revoked",
            "updated_at": "2026-04-27T12:00:00+00:00",
            "projection_id": "12121212-1212-1212-1212-121212121212",
            "modality": "voice",
        }

    def _semantic_sync_row(self) -> dict:
        return {
            "source_table": "memories",
            "source_id": MEMORY_ID,
            "target_template_code": "marvain.memory.v1",
            "tapdb_euid": "MVN-MEMORY-QA",
            "status": "synced",
            "last_error": None,
            "updated_at": "2026-04-27T12:00:00+00:00",
        }

    def _persona_row(self) -> dict:
        return {
            "persona_id": PERSONA_ID,
            "agent_id": AGENT_ID,
            "agent_name": "QA Agent",
            "name": "QA Persona",
            "instructions": "Stay deterministic during Playwright QA.",
            "is_default": True,
            "lifecycle_state": "active",
            "session_count": 1,
        }


class _FakeS3:
    class exceptions:
        class NoSuchBucket(Exception):
            pass

    def get_bucket_location(self, Bucket: str) -> dict:
        return {"LocationConstraint": "us-east-1"}

    def get_paginator(self, name: str):
        assert name == "list_objects_v2"
        return self

    def paginate(self, **kwargs) -> list[dict]:
        key = f"{kwargs.get('Prefix', '')}qa-artifact.txt"
        return [{"Contents": [{"Key": key, "Size": 128, "LastModified": datetime.now(timezone.utc)}]}]

    def generate_presigned_url(self, **kwargs) -> str:
        key = kwargs["Params"]["Key"]
        return f"https://example.test/{key}"

    def get_object(self, **kwargs) -> dict:
        entry = {
            "entry_id": "audit-entry-1",
            "type": "qa.audit",
            "agent_id": AGENT_ID,
            "ts": "2026-04-27T12:00:00+00:00",
            "payload": {"ok": True},
            "hash": "hash-1",
            "prev_hash": "GENESIS",
        }
        return {"Body": types.SimpleNamespace(read=lambda: json.dumps(entry).encode("utf-8"))}


def _load_hub_app_module():
    shared = ROOT / "layers" / "shared" / "python"
    hub_api_dir = ROOT / "functions" / "hub_api"
    for path in (shared, hub_api_dir):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_REGION", "us-east-1")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    for mod_name in ("api_app", "hub_api_app_playwright_workflows"):
        sys.modules.pop(mod_name, None)

    spec = importlib.util.spec_from_file_location(
        "hub_api_app_playwright_workflows",
        ROOT / "functions" / "hub_api" / "app.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def _install_semantic_tapdb_fake() -> None:
    class _Store:
        @classmethod
        def from_environment(cls):
            return cls()

        def graph_for(self, semantic_id: str) -> dict:
            return {
                "semantic_id": semantic_id,
                "nodes": [{"semantic_id": semantic_id, "template": "memory", "name": "QA Memory", "depth": 0}],
                "edges": [],
            }

    module = types.ModuleType("agent_hub.semantic_tapdb")
    module.DaylilyTapdbSemanticStore = _Store
    sys.modules["agent_hub.semantic_tapdb"] = module


@pytest.fixture(scope="module")
def gui_module():
    mod = _load_hub_app_module()
    fake_db = _FakeDb()
    fake_s3 = _FakeS3()
    _install_semantic_tapdb_fake()
    tapdb_web = mod._FastAPI()
    tapdb_dag = mod._FastAPI()

    @tapdb_web.get("/")
    def _tapdb_home():
        return mod.HTMLResponse("<h1>Graph</h1><p>Semantic TapDB home</p>")

    @tapdb_web.get("/graph")
    def _tapdb_graph():
        return mod.HTMLResponse("<h1>Graph</h1><p>Semantic QA Memory</p>")

    @tapdb_web.get("/query")
    def _tapdb_query():
        return mod.HTMLResponse("<h1>Query</h1><p>Semantic QA Memory</p>")

    @tapdb_dag.get("/api/dag/data")
    def _tapdb_dag_data():
        return {"dag": {"nodes": [{"id": "MVN-MEMORY-QA", "name": "QA Memory"}], "edges": []}}

    mod._tapdb_web_asgi_app = tapdb_web
    mod._tapdb_dag_asgi_app = tapdb_dag
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
            agent_id=AGENT_ID,
            name="QA Agent",
            role="owner",
            relationship_label="Primary",
            disabled=False,
        )
    ]
    mod.list_spaces_for_user = lambda db, user_id: [
        types.SimpleNamespace(
            space_id=SPACE_ID,
            agent_id=AGENT_ID,
            agent_name="QA Agent",
            name="Kitchen",
            livekit_room_mode="ephemeral",
        )
    ]
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


@pytest.fixture(scope="module")
def browser_page(gui_base_url):
    sync_api = pytest.importorskip("playwright.sync_api")
    headless = os.getenv("MARVAIN_PLAYWRIGHT_HEADLESS", "1") != "0"
    with sync_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=headless)
        except Exception as exc:
            pytest.skip(f"Playwright Chromium is not installed or cannot launch: {exc}")
        context = browser.new_context(base_url=gui_base_url, ignore_https_errors=True)
        page = context.new_page()
        try:
            yield page
        finally:
            context.close()
            browser.close()


def _assert_page(page, path: str, heading: str, expected_text: str | None = None) -> None:
    page.goto(path, wait_until="domcontentloaded")
    page.locator("h1").filter(has_text=heading).first.wait_for(timeout=10_000)
    body = page.locator("body").inner_text(timeout=10_000)
    assert "Authentication Error" not in body
    assert "Not authenticated" not in body
    if expected_text:
        assert expected_text in body


@pytest.mark.parametrize(
    ("path", "heading", "expected_text"),
    [
        ("/", "Dashboard", "QA Agent"),
        ("/live-session", "Live Session", "Start Session"),
        ("/agents", "Agents", "QA Agent"),
        ("/people", "People", "QA Person"),
        ("/locations", "Locations", "QA Home"),
        ("/spaces", "Spaces", "Kitchen"),
        ("/devices", "Devices", "QA Kitchen Display"),
        ("/sessions", "Sessions", "qa-room"),
        ("/memories", "Memories", "QA deterministic memory"),
        ("/recognition", "Recognition", "QA Person"),
        ("/actions", "Actions", "device.notify"),
        ("/tapdb/graph?start_euid=MVN-MEMORY-QA", "Graph", "Semantic"),
        ("/audit", "Audit", "qa.audit"),
        ("/observability", "Observability", "openai-outage"),
        ("/capabilities", "Capability Matrix", "TapDB semantic graph"),
        ("/artifacts", "Artifacts", "qa-artifact.txt"),
        ("/profile", "Profile", "qa@example.test"),
    ],
)
def test_authenticated_gui_pages_render_without_external_credentials(
    browser_page, path, heading, expected_text
) -> None:
    _assert_page(browser_page, path, heading, expected_text)


def test_core_gui_browser_workflows_are_interactive(browser_page) -> None:
    page = browser_page

    _assert_page(page, "/actions", "Actions", "device.notify")
    page.get_by_role("button", name="Create Action").click()
    page.locator("#create-action-modal").wait_for(state="visible")
    page.locator("#action-agent").select_option(AGENT_ID)
    page.locator("#action-kind").select_option("device.notify")
    page.locator("#action-payload").fill('{"message":"hello"}')

    _assert_page(page, "/devices", "Devices", "QA Kitchen Display")
    page.get_by_role("button", name="Register Device").first.click()
    page.locator("#create-device-modal").wait_for(state="visible")
    page.locator("#device-name").fill("QA Browser Device")

    _assert_page(page, "/artifacts", "Artifacts", "qa-artifact.txt")
    page.get_by_role("button", name="Upload").click()
    page.locator("#upload-modal").wait_for(state="visible")

    _assert_page(page, "/memories", "Memories", "QA deterministic memory")
    page.locator("#search-filter").fill("kitchen display")
    assert page.locator(".memory-card").filter(has_text="QA deterministic memory").count() == 1

    _assert_page(page, "/live-session", "Live Session", "Kitchen")
    page.locator("#space_id").select_option(SPACE_ID)
    assert page.locator("#space_id").input_value() == SPACE_ID


def test_tapdb_dag_query_api_is_available_to_browser(browser_page) -> None:
    page = browser_page
    page.goto("/tapdb/graph?start_euid=MVN-MEMORY-QA", wait_until="domcontentloaded")
    result = page.evaluate(
        """async () => {
            const response = await fetch('/api/dag/data?start_euid=MVN-MEMORY-QA');
            return {status: response.status, body: await response.json()};
        }"""
    )
    assert result["status"] == 200
    assert result["body"]["dag"]["nodes"][0]["name"] == "QA Memory"
