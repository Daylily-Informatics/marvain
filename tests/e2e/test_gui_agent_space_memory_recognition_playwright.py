from __future__ import annotations

import dataclasses
import importlib.util
import json
import socket
import sys
import threading
import time
import types
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]
USER_ID = "00000000-0000-0000-0000-000000000001"
CREATED_AGENT_ID = "10101010-1010-4010-8010-101010101010"
CREATED_SPACE_ID = "20202020-2020-4020-8020-202020202020"
SESSION_ID = "30303030-3030-4030-8030-303030303030"
LOCATION_ID = "40404040-4040-4040-8040-404040404040"
DEVICE_ID = "50505050-5050-4050-8050-505050505050"
ADA_PERSON_ID = "60606060-6060-4060-8060-606060606060"
GRACE_PERSON_ID = "70707070-7070-4070-8070-707070707070"


def _load_workflow_helpers():
    path = ROOT / "tests" / "e2e" / "test_gui_workflows_playwright.py"
    spec = importlib.util.spec_from_file_location("marvain_gui_workflow_helpers_round4", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _json_response(route, payload: dict, *, status: int = 200) -> None:
    route.fulfill(
        status=status,
        content_type="application/json",
        body=json.dumps(payload),
    )


@dataclass
class _WorkflowState:
    agents: list[dict] = field(default_factory=list)
    spaces: list[dict] = field(default_factory=list)
    people: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    memory_candidates: list[dict] = field(default_factory=list)
    memories: list[dict] = field(default_factory=list)
    recognition_observations: list[dict] = field(default_factory=list)
    recognition_hypotheses: list[dict] = field(default_factory=list)
    presence: list[dict] = field(default_factory=list)
    consent_grants: list[dict] = field(default_factory=list)
    artifacts: list[dict] = field(default_factory=list)
    active_session: dict | None = None
    upload_count: int = 0
    voice_imprints: dict[str, bytes] = field(default_factory=dict)
    video_imprints: dict[str, bytes] = field(default_factory=dict)

    def agent_objects(self) -> list[types.SimpleNamespace]:
        return [
            types.SimpleNamespace(
                agent_id=a["agent_id"],
                name=a["name"],
                role=a.get("role", "owner"),
                relationship_label=a.get("relationship_label"),
                disabled=False,
            )
            for a in self.agents
        ]

    def space_objects(self) -> list[types.SimpleNamespace]:
        return [
            types.SimpleNamespace(
                space_id=s["space_id"],
                agent_id=s["agent_id"],
                agent_name=s["agent_name"],
                name=s["name"],
                livekit_room_mode=s.get("livekit_room_mode", "ephemeral"),
                privacy_mode=s.get("privacy_mode", False),
            )
            for s in self.spaces
        ]

    def seed_recognition_people(self) -> None:
        if not self.agents:
            self.agents.append(
                {
                    "agent_id": CREATED_AGENT_ID,
                    "name": "Round 4 Recognition Agent",
                    "role": "owner",
                    "relationship_label": "Recognition QA",
                }
            )
        if not self.spaces:
            self.spaces.append(
                {
                    "space_id": CREATED_SPACE_ID,
                    "agent_id": CREATED_AGENT_ID,
                    "agent_name": "Round 4 Recognition Agent",
                    "name": "Recognition Lab",
                    "privacy_mode": False,
                    "livekit_room_mode": "stable",
                }
            )
        self.people = [
            {
                "person_id": ADA_PERSON_ID,
                "agent_id": CREATED_AGENT_ID,
                "agent_name": "Round 4 Recognition Agent",
                "display_name": "Ada Voice",
                "created_at": datetime.now(timezone.utc),
            },
            {
                "person_id": GRACE_PERSON_ID,
                "agent_id": CREATED_AGENT_ID,
                "agent_name": "Round 4 Recognition Agent",
                "display_name": "Grace Video",
                "created_at": datetime.now(timezone.utc),
            },
        ]
        self.consent_grants = [
            {
                "consent_id": "80808080-8080-4080-8080-808080808080",
                "agent_id": CREATED_AGENT_ID,
                "person_id": ADA_PERSON_ID,
                "person_name": "Ada Voice",
                "consent_type": "voice",
                "status": "active",
                "expires_at": None,
                "revoked_at": None,
            },
            {
                "consent_id": "90909090-9090-4090-8090-909090909090",
                "agent_id": CREATED_AGENT_ID,
                "person_id": GRACE_PERSON_ID,
                "person_name": "Grace Video",
                "consent_type": "face",
                "status": "active",
                "expires_at": None,
                "revoked_at": None,
            },
        ]

    def create_agent(self, payload: dict) -> dict:
        agent = {
            "agent_id": CREATED_AGENT_ID,
            "name": payload["name"],
            "role": "owner",
            "relationship_label": payload.get("relationship_label"),
        }
        self.agents = [agent]
        return agent

    def create_space(self, payload: dict) -> dict:
        agent = self.agents[0]
        space = {
            "space_id": CREATED_SPACE_ID,
            "agent_id": agent["agent_id"],
            "agent_name": agent["name"],
            "name": payload["name"],
            "privacy_mode": bool(payload.get("privacy_mode")),
            "livekit_room_mode": payload.get("livekit_room_mode") or "ephemeral",
        }
        self.spaces = [space]
        return space

    def mint_session(self, space_id: str) -> dict:
        space = next(s for s in self.spaces if s["space_id"] == space_id)
        self.active_session = {
            "session_id": SESSION_ID,
            "agent_id": space["agent_id"],
            "space_id": space["space_id"],
            "agent_name": space["agent_name"],
            "space_name": space["name"],
            "livekit_room": f"marvain-test-{space['space_id'][:8]}",
            "status": "open",
        }
        return self.active_session

    def on_chat_event_inserted(self, params: dict) -> None:
        payload = json.loads(params["payload"])
        self.events.append(
            {
                "event_id": params["event_id"],
                "session_id": params["session_id"],
                "agent_id": params["agent_id"],
                "space_id": params["space_id"],
                "person_id": None,
                "type": "chat.message",
                "payload": params["payload"],
                "created_at": "2026-04-27T12:00:00+00:00",
            }
        )
        self.events.append(
            {
                "event_id": "31313131-3131-4131-8131-313131313131",
                "session_id": params["session_id"],
                "agent_id": params["agent_id"],
                "space_id": params["space_id"],
                "person_id": None,
                "type": "transcript_chunk",
                "payload": json.dumps({"text": payload["text"], "source": "typed_chat"}),
                "created_at": "2026-04-27T12:00:01+00:00",
            }
        )
        self.events.append(
            {
                "event_id": "32323232-3232-4232-8232-323232323232",
                "session_id": params["session_id"],
                "agent_id": params["agent_id"],
                "space_id": params["space_id"],
                "person_id": None,
                "type": "agent.response",
                "payload": json.dumps({"text": "Stored the useful details with provenance."}),
                "created_at": "2026-04-27T12:00:02+00:00",
            }
        )

    def on_memory_candidate_inserted(self, params: dict) -> None:
        candidate = {
            "memory_candidate_id": params["candidate_id"],
            "agent_id": params["agent_id"],
            "source_event_id": params["event_id"],
            "source_action_id": None,
            "space_id": params["space_id"],
            "session_id": params["session_id"],
            "subject_person_id": None,
            "subject_person_name": None,
            "tier": "episodic",
            "content": params["content"],
            "participants": params["participants"],
            "model": "round4-gui-worker",
            "confidence": 1.0,
            "lifecycle_state": "candidate",
            "tapdb_euid": "MVN-MEMORY-CANDIDATE-ROUND4",
            "created_at": "2026-04-27T12:00:03+00:00",
            "reviewed_at": None,
            "agent_name": self.active_session["agent_name"] if self.active_session else "Round 4 Agent",
            "space_name": self.active_session["space_name"] if self.active_session else "Round 4 Space",
        }
        self.memory_candidates.append(candidate)
        for index, tier in enumerate(MEMORY_KIND_VALUES, start=1):
            memory_id = f"a{index:07d}-aaaa-4aaa-8aaa-aaaaaaaaaaa{index}"
            self.memories.append(
                {
                    "memory_id": memory_id,
                    "agent_id": params["agent_id"],
                    "space_id": params["space_id"],
                    "tier": tier,
                    "content": f"{tier} memory stored from Round 4 GUI conversation: {params['content']}",
                    "participants": json.dumps([f"user:{USER_ID}"]),
                    "provenance": json.dumps(
                        {
                            "source": "live_session_chat",
                            "source_event_id": params["event_id"],
                            "memory_candidate_id": params["candidate_id"],
                        }
                    ),
                    "created_at": "2026-04-27T12:00:04+00:00",
                    "agent_name": self.active_session["agent_name"] if self.active_session else "Round 4 Agent",
                    "space_name": self.active_session["space_name"] if self.active_session else "Round 4 Space",
                    "subject_person_id": None,
                    "subject_person_name": None,
                    "tags": ["round4", tier],
                    "scene_context": "GUI-created space conversation",
                    "modality": "text",
                    "confidence": 1.0,
                    "related_memory_ids": [],
                    "tapdb_euid": f"MVN-MEMORY-ROUND4-{tier.upper()}",
                    "source_event_id": params["event_id"],
                }
            )
            self.events.append(
                {
                    "event_id": f"33333333-3333-4333-8333-33333333333{index}",
                    "session_id": params["session_id"],
                    "agent_id": params["agent_id"],
                    "space_id": params["space_id"],
                    "person_id": None,
                    "type": "memory.committed",
                    "payload": json.dumps({"tier": tier, "memory_id": memory_id}),
                    "created_at": f"2026-04-27T12:00:0{4 + index}+00:00",
                }
            )

    def record_enrollment(self, *, person_id: str, modality: str, artifact_key: str) -> dict:
        person = next(p for p in self.people if p["person_id"] == person_id)
        is_voice = modality == "voice"
        observation_id = "b1111111-1111-4111-8111-111111111111" if is_voice else "b2222222-2222-4222-8222-222222222222"
        hypothesis_id = "c1111111-1111-4111-8111-111111111111" if is_voice else "c2222222-2222-4222-8222-222222222222"
        artifact_id = "d1111111-1111-4111-8111-111111111111" if is_voice else "d2222222-2222-4222-8222-222222222222"
        model_name = "voice-imprint-test-mock" if is_voice else "video-frame-face-mock"
        sample = f"{modality}:{person['display_name']}".encode("utf-8")
        if is_voice:
            self.voice_imprints[person_id] = sample
        else:
            self.video_imprints[person_id] = sample
        self.artifacts.append(
            {
                "artifact_id": artifact_id,
                "agent_id": person["agent_id"],
                "observation_id": observation_id,
                "kind": "audio/webm" if is_voice else "video/mock-frame",
                "uri": f"s3://qa-artifacts/{artifact_key}",
                "lifecycle_state": "available",
                "created_at": "2026-04-27T12:01:00+00:00",
            }
        )
        self.recognition_observations.append(
            {
                "observation_id": observation_id,
                "agent_id": person["agent_id"],
                "space_id": self.spaces[0]["space_id"],
                "location_id": LOCATION_ID,
                "device_id": DEVICE_ID,
                "session_id": SESSION_ID,
                "artifact_id": artifact_id,
                "modality": modality if is_voice else "face",
                "lifecycle_state": "matched",
                "model_name": model_name,
                "created_at": "2026-04-27T12:01:01+00:00",
                "agent_name": person["agent_name"],
                "space_name": self.spaces[0]["name"],
                "location_name": "Recognition Lab",
                "device_name": "Mock Browser Capture",
            }
        )
        self.recognition_hypotheses.append(
            {
                "hypothesis_id": hypothesis_id,
                "observation_id": observation_id,
                "agent_id": person["agent_id"],
                "candidate_person_id": person_id,
                "person_name": person["display_name"],
                "score": 0.99,
                "decision": "accepted",
                "consent_id": next(c["consent_id"] for c in self.consent_grants if c["person_id"] == person_id),
                "created_at": "2026-04-27T12:01:02+00:00",
                "reason": "deterministic browser recognition fixture",
            }
        )
        self.presence.append(
            {
                "presence_assertion_id": "e1111111-1111-4111-8111-111111111111"
                if is_voice
                else "e2222222-2222-4222-8222-222222222222",
                "agent_id": person["agent_id"],
                "person_id": person_id,
                "person_name": person["display_name"],
                "space_id": self.spaces[0]["space_id"],
                "space_name": self.spaces[0]["name"],
                "location_id": LOCATION_ID,
                "location_name": "Recognition Lab",
                "status": "present",
                "source": "voice" if is_voice else "video",
                "asserted_at": "2026-04-27T12:01:03+00:00",
            }
        )
        return {"observation_id": observation_id, "hypothesis_id": hypothesis_id, "artifact_id": artifact_id}

    def identify_voice(self, sample: bytes) -> str | None:
        return self._identify(sample, self.voice_imprints)

    def identify_video(self, sample: bytes) -> str | None:
        return self._identify(sample, self.video_imprints)

    def _identify(self, sample: bytes, imprints: dict[str, bytes]) -> str | None:
        for person_id, imprint in imprints.items():
            if imprint == sample:
                return next(p["display_name"] for p in self.people if p["person_id"] == person_id)
        return None


class _WorkflowDb:
    def __init__(self, helpers, state: _WorkflowState) -> None:
        self._base = helpers._FakeDb()
        self.state = state
        self.executed: list[tuple[str, dict | None]] = []

    def query(self, sql: str, params: dict | None = None) -> list[dict]:
        text = " ".join(sql.lower().split())
        if "select se.session_id::text as session_id" in text and "from sessions se" in text:
            return [self.state.active_session] if self.state.active_session else []
        if "from events where session_id" in text:
            session_id = str((params or {}).get("session_id") or "")
            return [row for row in self.state.events if str(row.get("session_id")) == session_id]
        if "from memory_candidates mc" in text:
            expected_state = str((params or {}).get("state") or "")
            return [
                row
                for row in self.state.memory_candidates
                if not expected_state or row.get("lifecycle_state") == expected_state
            ]
        if "from memories m" in text:
            return list(self.state.memories)
        if "from people p" in text and "join agents" in text:
            return list(self.state.people)
        if "from people where agent_id::text" in text:
            return [{"person_id": p["person_id"], "display_name": p["display_name"]} for p in self.state.people]
        if "select consent_type, expires_at from consent_grants" in text:
            person_id = str((params or {}).get("person_id") or "")
            return [
                {"consent_type": c["consent_type"], "expires_at": c["expires_at"]}
                for c in self.state.consent_grants
                if c["person_id"] == person_id and not c.get("revoked_at")
            ]
        if "from consent_grants" in text:
            return list(self.state.consent_grants)
        if "from recognition_observations ro" in text:
            return list(self.state.recognition_observations)
        if "from recognition_hypotheses rh" in text:
            return list(self.state.recognition_hypotheses)
        if "from presence_assertions pa" in text:
            return list(self.state.presence)
        if "from artifact_references ar" in text:
            return list(self.state.artifacts)
        if "from voiceprints vp" in text or "from faceprints fp" in text:
            return []
        if "from devices d join agents" in text:
            return [
                {
                    **self._base._device_row(datetime.now(timezone.utc)),
                    "agent_id": self.state.agents[0]["agent_id"] if self.state.agents else CREATED_AGENT_ID,
                    "agent_name": self.state.agents[0]["name"] if self.state.agents else "Round 4 Agent",
                }
            ]
        return self._base.query(sql, params)

    def execute(self, sql: str, params: dict | None = None) -> dict:
        self.executed.append((sql, params))
        text = " ".join(sql.lower().split())
        payload = dict(params or {})
        if "insert into events" in text and payload.get("session_id"):
            self.state.on_chat_event_inserted(payload)
        if "insert into memory_candidates" in text and payload.get("event_id"):
            self.state.on_memory_candidate_inserted(payload)
        return {"ok": True}


@pytest.fixture
def workflow_state() -> _WorkflowState:
    return _WorkflowState()


@pytest.fixture
def gui_module(workflow_state):
    helpers = _load_workflow_helpers()
    mod = helpers._load_hub_app_module()
    fake_db = _WorkflowDb(helpers, workflow_state)
    fake_s3 = helpers._FakeS3()
    helpers._install_semantic_tapdb_fake()
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
    mod._agent_worker_status_dict = lambda: {"status": "running", "pid": 4242, "log_file": None}
    mod._live_session_config_error = lambda: None
    mod._require_live_session_config = lambda: None
    mod._gui_get_user = lambda request: mod.AuthenticatedUser(
        user_id=USER_ID,
        cognito_sub="qa-sub",
        email="qa@example.test",
    )
    mod.list_agents_for_user = lambda db, user_id: workflow_state.agent_objects()
    mod.list_spaces_for_user = lambda db, user_id: workflow_state.space_objects()

    async def fake_mint_livekit_token_for_user(*, user, space_id, room_mode=None):  # noqa: ARG001
        session = workflow_state.mint_session(space_id)
        return mod.LiveKitTokenOut(
            url="wss://livekit.example.test",
            token="test-livekit-token",
            room=session["livekit_room"],
            identity=f"user:{USER_ID}",
            session_id=session["session_id"],
        )

    mod._mint_livekit_token_for_user = fake_mint_livekit_token_for_user
    return mod


@pytest.fixture
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


@pytest.fixture
def browser_page(gui_base_url):
    sync_api = pytest.importorskip("playwright.sync_api")
    headless = True
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


LIVEKIT_BROWSER_STUB = """
window.LivekitClient = {
  RoomEvent: {
    Disconnected: 'disconnected',
    ParticipantConnected: 'participantConnected',
    DataReceived: 'dataReceived'
  },
  Room: class {
    constructor() {
      this.handlers = {};
      this.localParticipant = {
        publishTrack: async () => undefined,
        publishData: async () => undefined
      };
    }
    on(event, handler) { this.handlers[event] = handler; return this; }
    async connect() {
      if (this.handlers.participantConnected) {
        this.handlers.participantConnected({identity: 'agent-round4'});
      }
    }
    disconnect() {
      if (this.handlers.disconnected) this.handlers.disconnected('browser test complete');
    }
  },
  createLocalAudioTrack: async () => ({kind: 'audio', stop() {}})
};
"""


MEDIA_CAPTURE_STUB = """
class FakeMediaRecorder {
  constructor(stream) {
    this.stream = stream;
    this.state = 'inactive';
    this.mimeType = 'audio/webm';
    this.ondataavailable = null;
    this.onstop = null;
  }
  start() {
    this.state = 'recording';
    setTimeout(() => {
      if (this.ondataavailable) {
        this.ondataavailable({data: new Blob(['browser voice imprint'], {type: 'audio/webm'})});
      }
    }, 0);
  }
  stop() {
    this.state = 'inactive';
    setTimeout(() => { if (this.onstop) this.onstop(); }, 0);
  }
}
Object.defineProperty(window, 'MediaRecorder', {value: FakeMediaRecorder, configurable: true});
Object.defineProperty(navigator, 'mediaDevices', {
  value: {
    getUserMedia: async () => new MediaStream(),
    enumerateDevices: async () => [
      {kind: 'audioinput', deviceId: 'test-mic', label: 'Test Microphone'},
      {kind: 'audiooutput', deviceId: 'test-speaker', label: 'Test Speaker'},
      {kind: 'videoinput', deviceId: 'test-camera', label: 'Test Camera'}
    ]
  },
  configurable: true
});
HTMLCanvasElement.prototype.getContext = function() {
  return { drawImage: () => undefined };
};
HTMLCanvasElement.prototype.toBlob = function(callback, type) {
  callback(new Blob(['browser video frame'], {type: type || 'image/jpeg'}));
};
Object.defineProperty(HTMLMediaElement.prototype, 'videoWidth', {get() { return 640; }, configurable: true});
Object.defineProperty(HTMLMediaElement.prototype, 'videoHeight', {get() { return 480; }, configurable: true});
"""


def test_gui_creates_agent_space_and_conversation_stores_all_memory_tiers(browser_page, workflow_state) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    page = browser_page
    page.add_init_script(MEDIA_CAPTURE_STUB)
    page.route(
        "**/livekit-client.umd.min.js",
        lambda route: route.fulfill(status=200, content_type="text/javascript", body=LIVEKIT_BROWSER_STUB),
    )

    def create_agent(route) -> None:
        payload = route.request.post_data_json
        agent = workflow_state.create_agent(payload)
        _json_response(route, {"ok": True, "agent_id": agent["agent_id"], "agent": agent})

    def create_space(route) -> None:
        payload = route.request.post_data_json
        space = workflow_state.create_space(payload)
        _json_response(route, {"ok": True, "space_id": space["space_id"], "space": space})

    page.route("**/api/agents", create_agent)
    page.route("**/api/spaces", create_space)

    page.goto("/agents", wait_until="domcontentloaded")
    page.get_by_role("button", name="Create Agent").first.click()
    page.locator("#create-agent-modal").wait_for(state="visible")
    page.locator("#agent-name").fill("Round 4 Memory Agent")
    page.locator("#agent-label").fill("GUI memory QA")
    page.locator("#create-agent-modal").get_by_role("button", name="Create Agent").click()
    sync_api.expect(page.locator("body")).to_contain_text("Round 4 Memory Agent", timeout=10_000)
    assert workflow_state.agents[0]["name"] == "Round 4 Memory Agent"

    page.goto("/spaces", wait_until="domcontentloaded")
    page.get_by_role("button", name="Create Space").first.click()
    page.locator("#create-space-modal").wait_for(state="visible")
    page.locator("#space-agent").select_option(CREATED_AGENT_ID)
    page.locator("#space-name").fill("Round 4 Memory Studio")
    page.locator("#space-room-mode").select_option("stable")
    page.locator("#create-space-modal").get_by_role("button", name="Create Space").click()
    sync_api.expect(page.locator("body")).to_contain_text("Round 4 Memory Studio", timeout=10_000)
    assert workflow_state.spaces[0]["name"] == "Round 4 Memory Studio"

    page.goto(f"/live-session?space_id={CREATED_SPACE_ID}", wait_until="domcontentloaded")
    page.locator("#space_id").select_option(CREATED_SPACE_ID)
    page.locator("#btn-join").click()
    sync_api.expect(page.locator("#lifecycle-log")).to_contain_text("Microphone published", timeout=10_000)
    page.locator("#chat-input").fill("Remember that Ada prefers green tea and the studio lights should stay dim.")
    page.locator("#btn-send-chat").click()
    sync_api.expect(page.locator("#transcript-log")).to_contain_text("Ada prefers green tea", timeout=10_000)
    sync_api.expect(page.locator("#lifecycle-log")).to_contain_text("memory.committed", timeout=10_000)

    assert {m["tier"] for m in workflow_state.memories} == set(MEMORY_KIND_VALUES)
    assert workflow_state.memory_candidates
    assert workflow_state.memory_candidates[0]["source_event_id"]

    page.goto("/memories", wait_until="domcontentloaded")
    sync_api.expect(page.locator("body")).to_contain_text("Memory Candidates", timeout=10_000)
    sync_api.expect(page.locator("#memory-candidates-list")).to_contain_text("Ada prefers green tea", timeout=10_000)
    for tier in MEMORY_KIND_VALUES:
        sync_api.expect(page.locator("#memories-list")).to_contain_text(f"{tier} memory stored", timeout=10_000)
        assert page.locator(".memory-card", has_text=tier).count() >= 1


def test_gui_mock_voice_imprint_and_video_recognition_identify_distinct_users(browser_page, workflow_state) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    workflow_state.seed_recognition_people()
    page = browser_page
    page.add_init_script(MEDIA_CAPTURE_STUB)

    def upload_artifact(route) -> None:
        workflow_state.upload_count += 1
        _json_response(
            route,
            {
                "ok": True,
                "bucket": "qa-artifacts",
                "key": f"recognition/mock-{workflow_state.upload_count}.bin",
            },
        )

    def enroll(route) -> None:
        path = urlparse(route.request.url).path
        parts = path.strip("/").split("/")
        person_id = parts[2]
        modality = parts[-1]
        body = route.request.post_data_json
        created = workflow_state.record_enrollment(
            person_id=person_id,
            modality=modality,
            artifact_key=str(body.get("artifact_key") or f"{modality}.bin"),
        )
        _json_response(
            route, {"ok": True, "event_id": created["observation_id"], "queued": True, "space_id": CREATED_SPACE_ID}
        )

    page.route("**/api/artifacts/upload", upload_artifact)
    page.route("**/api/people/*/enroll/voice", enroll)
    page.route("**/api/people/*/enroll/face", enroll)

    page.goto("/people", wait_until="domcontentloaded")
    sync_api.expect(page.locator("body")).to_contain_text("Ada Voice")
    sync_api.expect(page.locator("body")).to_contain_text("Grace Video")

    page.locator(".person-card", has_text="Ada Voice").get_by_role("button", name="Enroll").click()
    page.locator("#enroll-modal").wait_for(state="visible")
    page.locator("#voice-start-btn").click()
    page.locator("#voice-stop-btn").click()
    sync_api.expect(page.locator("#voice-status")).to_contain_text("Recorded", timeout=10_000)
    page.locator("#voice-upload-btn").click()
    sync_api.expect(page.locator("#voice-status")).to_contain_text("Uploaded and queued", timeout=10_000)
    page.evaluate("Marvain.hideModal('enroll-modal')")

    page.locator(".person-card", has_text="Grace Video").get_by_role("button", name="Enroll").click()
    page.locator("#enroll-modal").wait_for(state="visible")
    page.locator("#face-start-btn").click()
    sync_api.expect(page.locator("#face-status")).to_contain_text("Camera ready", timeout=10_000)
    page.locator("#face-snap-btn").click()
    sync_api.expect(page.locator("#face-status")).to_contain_text("Snapshot", timeout=10_000)
    page.locator("#face-upload-btn").click()
    sync_api.expect(page.locator("#face-status")).to_contain_text("Uploaded and queued", timeout=10_000)

    assert workflow_state.identify_voice(b"voice:Ada Voice") == "Ada Voice"
    assert workflow_state.identify_video(b"face:Grace Video") == "Grace Video"
    assert workflow_state.identify_voice(b"voice:Grace Video") is None
    assert workflow_state.identify_video(b"face:Ada Voice") is None

    page.goto("/recognition", wait_until="domcontentloaded")
    sync_api.expect(page.locator("body")).to_contain_text("Ada Voice", timeout=10_000)
    sync_api.expect(page.locator("body")).to_contain_text("Grace Video", timeout=10_000)
    sync_api.expect(page.locator("body")).to_contain_text("voice-imprint-test-mock", timeout=10_000)
    sync_api.expect(page.locator("body")).to_contain_text("video-frame-face-mock", timeout=10_000)
    sync_api.expect(page.locator("body")).to_contain_text("video/mock-frame", timeout=10_000)
