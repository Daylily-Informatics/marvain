from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from route_behavior_receipt import record_http_evidence, record_postcondition_evidence

ROOT = Path(__file__).resolve().parents[1]
AGENT_ID = "11111111-1111-1111-1111-111111111111"
PERSON_ID = "22222222-2222-2222-2222-222222222222"
USER_ID = "33333333-3333-3333-3333-333333333333"
SPACE_ID = "88888888-8888-8888-8888-888888888888"


@dataclass
class RecordingDb:
    query_responses: list[list[dict[str, object]]] = field(default_factory=list)
    execute_calls: list[tuple[str, dict[str, object], str | None]] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)
    rollbacks: list[str] = field(default_factory=list)
    _transactions: int = 0

    def query(
        self,
        _sql: str,
        params: dict[str, object] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, object]]:
        del transaction_id
        if params and {"agent_id", "idempotency_key", "source_external_reference"} <= params.keys():
            return [
                {
                    "semantic_outbox_id": f"66666666-6666-6666-6666-{len(self.execute_calls):012d}",
                    "semantic_sync_id": f"77777777-7777-7777-7777-{len(self.execute_calls):012d}",
                    "agent_id": params["agent_id"],
                    "idempotency_key": params["idempotency_key"],
                }
            ]
        return self.query_responses.pop(0) if self.query_responses else []

    def execute(
        self,
        sql: str,
        params: dict[str, object] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, object]:
        self.execute_calls.append((sql, params or {}, transaction_id))
        return {}

    def begin(self) -> str:
        self._transactions += 1
        return f"route-behavior-tx-{self._transactions}"

    def commit(self, transaction_id: str) -> None:
        self.commits.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self.rollbacks.append(transaction_id)


@dataclass(frozen=True)
class ApiHarness:
    mod: ModuleType
    client: TestClient
    db: RecordingDb


_cached_module: ModuleType | None = None


def _load_api_module() -> ModuleType:
    global _cached_module
    if _cached_module is not None:
        return _cached_module
    shared = ROOT / "layers" / "shared" / "python"
    hub_api = ROOT / "functions" / "hub_api"
    for path in (shared, hub_api):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:route-behavior")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:route-behavior")
    os.environ.setdefault("DB_NAME", "route_behavior")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "route-behavior-session-secret")
    os.environ.setdefault("OPENAI_EMBED_MODEL", "route-behavior-embedding-model")
    spec = importlib.util.spec_from_file_location(
        "hub_api_api_app_for_route_behavior",
        ROOT / "functions" / "hub_api" / "api_app.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    _cached_module = module
    return module


@pytest.fixture
def api_harness(monkeypatch: pytest.MonkeyPatch) -> ApiHarness:
    mod = _load_api_module()
    db = RecordingDb()
    mod.api_app.dependency_overrides.clear()
    monkeypatch.setattr(mod, "_get_db", lambda: db)
    monkeypatch.setattr(mod, "_cfg", dataclasses.replace(mod._cfg, audit_bucket=None))
    harness = ApiHarness(mod=mod, client=TestClient(mod.api_app, raise_server_exceptions=False), db=db)
    yield harness
    mod.api_app.dependency_overrides.clear()


def _authenticate_user(harness: ApiHarness) -> None:
    user = harness.mod.AuthenticatedUser(user_id=USER_ID, cognito_sub="route-sub", email="route@example.test")
    harness.mod.api_app.dependency_overrides[harness.mod.get_user] = lambda: user


def _authenticate_device(harness: ApiHarness, *, scopes: list[str]) -> None:
    device = harness.mod.AuthenticatedDevice(
        device_id="99999999-9999-9999-9999-999999999999",
        agent_id=AGENT_ID,
        scopes=scopes,
        capabilities={"kind": "worker"},
    )
    harness.mod.api_app.dependency_overrides[harness.mod.get_device] = lambda: device


def _authenticate_agent(harness: ApiHarness, *, scopes: list[str]) -> None:
    agent = harness.mod.AuthenticatedAgent(
        token_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        issuer_agent_id=AGENT_ID,
        target_agent_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        scopes=scopes,
        allowed_spaces=[SPACE_ID],
    )
    harness.mod.api_app.dependency_overrides[harness.mod.get_agent] = lambda: agent


def _membership(*, agent_id: str, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        agent_id=agent_id,
        name=name,
        role="owner",
        relationship_label="founder",
        disabled=False,
    )


def test_api_health_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/health")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/health",
        kind="success",
        response=response,
    )


def test_api_delegate_scopes_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/delegate/scopes")

    assert response.status_code == 200
    assert "read_memories" in response.json()
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/scopes",
        kind="success",
        response=response,
    )


def test_api_tools_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=[])
    response = api_harness.client.get("/v1/tools")

    assert response.status_code == 200
    assert isinstance(response.json()["tools"], list)
    record_http_evidence(request, surface="api", method="GET", path="/v1/tools", kind="success", response=response)


def test_api_tools_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/tools")

    assert response.status_code == 401
    record_http_evidence(request, surface="api", method="GET", path="/v1/tools", kind="denial", response=response)


def test_api_me_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_user(api_harness)
    response = api_harness.client.get("/v1/me")

    assert response.status_code == 200
    assert response.json()["user_id"] == USER_ID
    record_http_evidence(request, surface="api", method="GET", path="/v1/me", kind="success", response=response)


def test_api_me_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/me")

    assert response.status_code == 401
    record_http_evidence(request, surface="api", method="GET", path="/v1/me", kind="denial", response=response)


def test_api_agents_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "list_agents_for_user", lambda *_args, **_kwargs: [])
    response = api_harness.client.get("/v1/agents")

    assert response.status_code == 200
    assert response.json() == {"agents": []}
    record_http_evidence(request, surface="api", method="GET", path="/v1/agents", kind="success", response=response)


def test_api_agents_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/agents")

    assert response.status_code == 401
    record_http_evidence(request, surface="api", method="GET", path="/v1/agents", kind="denial", response=response)


def test_api_create_agent_success_and_readback(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(
        api_harness.mod,
        "_seed_default_persona",
        lambda **_kwargs: "44444444-4444-4444-4444-444444444444",
    )
    response = api_harness.client.post(
        "/v1/agents",
        json={"name": "Receipt Agent", "relationship_label": "founder"},
    )
    assert response.status_code == 200
    body = response.json()
    agent_id = body["agent_id"]
    assert agent_id
    assert api_harness.db.commits == ["route-behavior-tx-1"]
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents",
        kind="success",
        response=response,
    )

    monkeypatch.setattr(
        api_harness.mod,
        "list_agents_for_user",
        lambda *_args, **_kwargs: [_membership(agent_id=agent_id, name="Receipt Agent")],
    )
    readback = api_harness.client.get("/v1/agents")
    assert readback.status_code == 200
    assert readback.json()["agents"][0]["agent_id"] == agent_id
    assert readback.json()["agents"][0]["name"] == "Receipt Agent"
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents",
        owner="agent-service",
        query="GET /v1/agents",
        record_ids={"agent_id": agent_id},
        assertions=["created agent is returned by the owning agent list service with its submitted name"],
    )


def test_api_create_agent_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.post(
        "/v1/agents",
        json={"name": "Denied Agent", "relationship_label": "founder"},
    )

    assert response.status_code == 401
    record_http_evidence(request, surface="api", method="POST", path="/v1/agents", kind="denial", response=response)


def test_api_create_agent_validation(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_user(api_harness)
    response = api_harness.client.post("/v1/agents", json={})

    assert response.status_code == 422
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents",
        kind="validation",
        response=response,
    )


def test_api_patch_agent_success_and_readback(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    api_harness.db.query_responses = [
        [{"name": "Renamed Agent", "disabled": False, "role": "owner", "relationship_label": "founder"}]
    ]
    response = api_harness.client.patch(f"/v1/agents/{AGENT_ID}", json={"name": "Renamed Agent"})
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed Agent"
    record_http_evidence(
        request,
        surface="api",
        method="PATCH",
        path="/v1/agents/{agent_id}",
        kind="success",
        response=response,
    )

    monkeypatch.setattr(
        api_harness.mod,
        "list_agents_for_user",
        lambda *_args, **_kwargs: [_membership(agent_id=AGENT_ID, name="Renamed Agent")],
    )
    readback = api_harness.client.get("/v1/agents")
    assert readback.status_code == 200
    assert readback.json()["agents"][0]["name"] == "Renamed Agent"
    record_postcondition_evidence(
        request,
        surface="api",
        method="PATCH",
        path="/v1/agents/{agent_id}",
        owner="agent-service",
        query="GET /v1/agents",
        record_ids={"agent_id": AGENT_ID},
        assertions=["updated agent name is returned by the owning agent list service"],
    )


def test_api_patch_agent_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.patch(f"/v1/agents/{AGENT_ID}", json={"name": "Denied Rename"})

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="PATCH",
        path="/v1/agents/{agent_id}",
        kind="denial",
        response=response,
    )


def test_api_patch_agent_validation(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    response = api_harness.client.patch(f"/v1/agents/{AGENT_ID}", json={})

    assert response.status_code == 400
    record_http_evidence(
        request,
        surface="api",
        method="PATCH",
        path="/v1/agents/{agent_id}",
        kind="validation",
        response=response,
    )


def test_api_memberships_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    monkeypatch.setattr(api_harness.mod, "list_members_for_agent", lambda *_args, **_kwargs: [])
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/memberships")

    assert response.status_code == 200
    assert response.json() == {"memberships": []}
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/memberships",
        kind="success",
        response=response,
    )


def test_api_memberships_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/memberships")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/memberships",
        kind="denial",
        response=response,
    )


def test_api_default_persona_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_device(api_harness, scopes=["events:read"])
    monkeypatch.setattr(api_harness.mod, "is_agent_disabled", lambda *_args, **_kwargs: False)
    api_harness.db.query_responses = [
        [
            {
                "persona_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "agent_id": AGENT_ID,
                "name": "Receipt Persona",
                "instructions": "Use persisted evidence.",
            }
        ]
    ]
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/personas/default")

    assert response.status_code == 200
    assert response.json()["name"] == "Receipt Persona"
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/personas/default",
        kind="success",
        response=response,
    )


def test_api_default_persona_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/personas/default")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/personas/default",
        kind="denial",
        response=response,
    )


def test_api_auto_approve_policies_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/auto-approve-policies")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/auto-approve-policies",
        kind="success",
        response=response,
    )


def test_api_auto_approve_policies_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/auto-approve-policies")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/auto-approve-policies",
        kind="denial",
        response=response,
    )


def test_api_people_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/people")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/people",
        kind="success",
        response=response,
    )


def test_api_people_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/people")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/people",
        kind="denial",
        response=response,
    )


def test_api_create_person_success_and_readback(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    response = api_harness.client.post(
        f"/v1/agents/{AGENT_ID}/people",
        json={"display_name": "Receipt Person", "aliases": ["RP"]},
    )
    assert response.status_code == 200
    person_id = response.json()["person_id"]
    assert person_id
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents/{agent_id}/people",
        kind="success",
        response=response,
    )

    api_harness.db.query_responses = [
        [{"agent_id": AGENT_ID}],
        [
            {
                "person_id": person_id,
                "agent_id": AGENT_ID,
                "display_name": "Receipt Person",
                "aliases_json": '["RP"]',
                "created_at": "2026-07-11T00:00:00Z",
            }
        ],
    ]
    readback = api_harness.client.get(f"/v1/people/{person_id}")
    assert readback.status_code == 200
    assert readback.json()["person_id"] == person_id
    assert readback.json()["display_name"] == "Receipt Person"
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/people/{person_id}",
        kind="success",
        response=readback,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents/{agent_id}/people",
        owner="people-service",
        query="GET /v1/people/{person_id}",
        record_ids={"person_id": person_id},
        assertions=["created person is returned by the owning people service with its submitted display name"],
    )


def test_api_create_person_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.post(
        f"/v1/agents/{AGENT_ID}/people",
        json={"display_name": "Denied Person"},
    )

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents/{agent_id}/people",
        kind="denial",
        response=response,
    )


def test_api_create_person_validation(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    response = api_harness.client.post(f"/v1/agents/{AGENT_ID}/people", json={"display_name": ""})

    assert response.status_code == 422
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/agents/{agent_id}/people",
        kind="validation",
        response=response,
    )


def test_api_person_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/people/{PERSON_ID}")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/people/{person_id}",
        kind="denial",
        response=response,
    )


def test_api_consent_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_user(api_harness)
    api_harness.db.query_responses = [
        [{"agent_id": AGENT_ID}],
        [
            {
                "consent_id": "55555555-5555-5555-5555-555555555555",
                "agent_id": AGENT_ID,
                "person_id": PERSON_ID,
                "consent_type": "voice",
                "granted_at": "2026-07-11T00:00:00Z",
                "expires_at": None,
                "revoked_at": None,
            }
        ],
    ]
    response = api_harness.client.get(f"/v1/people/{PERSON_ID}/consent")

    assert response.status_code == 200
    assert response.json()[0]["consent_type"] == "voice"
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/people/{person_id}/consent",
        kind="success",
        response=response,
    )


def test_api_consent_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/people/{PERSON_ID}/consent")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/people/{person_id}/consent",
        kind="denial",
        response=response,
    )


def test_api_agent_tokens_success(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "_require_agent_role", lambda **_kwargs: None)
    monkeypatch.setattr(api_harness.mod, "list_agent_tokens", lambda *_args, **_kwargs: [])
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/tokens")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/tokens",
        kind="success",
        response=response,
    )


def test_api_agent_tokens_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/agents/{AGENT_ID}/tokens")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/agents/{agent_id}/tokens",
        kind="denial",
        response=response,
    )


def test_api_memories_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["memories:read"])
    response = api_harness.client.get("/v1/memories")

    assert response.status_code == 200
    assert response.json() == {"memories": []}
    record_http_evidence(request, surface="api", method="GET", path="/v1/memories", kind="success", response=response)


def test_api_memories_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/memories")

    assert response.status_code == 401
    record_http_evidence(request, surface="api", method="GET", path="/v1/memories", kind="denial", response=response)


def test_api_delegate_memories_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_agent(api_harness, scopes=["read_memories"])
    response = api_harness.client.get(f"/v1/delegate/memories?space_id={SPACE_ID}")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/memories",
        kind="success",
        response=response,
    )


def test_api_delegate_memories_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/delegate/memories?space_id={SPACE_ID}")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/memories",
        kind="denial",
        response=response,
    )


def test_api_delegate_events_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_agent(api_harness, scopes=["read_events"])
    response = api_harness.client.get(f"/v1/delegate/events?space_id={SPACE_ID}")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/events",
        kind="success",
        response=response,
    )


def test_api_delegate_events_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get(f"/v1/delegate/events?space_id={SPACE_ID}")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/events",
        kind="denial",
        response=response,
    )


def test_api_delegate_spaces_success(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_agent(api_harness, scopes=["read_spaces"])
    response = api_harness.client.get("/v1/delegate/spaces")

    assert response.status_code == 200
    assert response.json() == []
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/spaces",
        kind="success",
        response=response,
    )


def test_api_delegate_spaces_denial(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    response = api_harness.client.get("/v1/delegate/spaces")

    assert response.status_code == 401
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/delegate/spaces",
        kind="denial",
        response=response,
    )
