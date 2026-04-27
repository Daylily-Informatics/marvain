from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES
from cli_core_yo import output
from cli_core_yo.runtime import get_context
from click import ClickException
from typer import Option

from marvain_cli.config import ConfigError
from marvain_cli.ops import aws_stack_outputs, load_ctx


class SmokeError(RuntimeError):
    """Raised when a smoke runtime cannot complete a required step."""


DEPLOYED_SMOKE_REQUIRED_OUTPUTS = (
    "HubRestApiBase",
    "HubWebSocketUrl",
    "CognitoUserPoolId",
    "CognitoAppClientId",
    "AdminApiKeySecretArn",
    "LiveKitUrl",
    "LiveKitSecretArn",
    "OpenAISecretArn",
)
DEPLOYED_SMOKE_REQUIRED_ENV = (
    "MARVAIN_SMOKE_COGNITO_USERNAME",
    "MARVAIN_SMOKE_COGNITO_PASSWORD",
)


@dataclass(frozen=True)
class LocalSmokeScenario:
    seed: str = "marvain-local-smoke-v1"
    agent_id: str = "agent-local"
    space_id: str = "space-local"
    device_id: str = "device-local-satellite"
    person_id: str = "person-local-user"
    transcript_text: str = "Remember that the Marvain local smoke completed."
    recall_query: str = "local smoke completed"
    recognition_modality: str = "face"
    action_kind: str = "device.notify"


@dataclass(frozen=True)
class SmokeReport:
    session_id: str
    transcript_event_id: str
    memory_id: str
    memory_ids_by_kind: dict[str, str]
    recall_result: dict[str, Any]
    recognition_observation_id: str
    action_id: str
    device_result: dict[str, Any]
    completion_score: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "transcript_event_id": self.transcript_event_id,
            "memory_id": self.memory_id,
            "memory_ids_by_kind": self.memory_ids_by_kind,
            "recall_result": self.recall_result,
            "recognition_observation_id": self.recognition_observation_id,
            "action_id": self.action_id,
            "device_result": self.device_result,
            "completion_score": self.completion_score,
        }


@dataclass(frozen=True)
class GuiSmokePage:
    name: str
    path: str
    heading: str
    expected_text: str | None = None


GUI_SMOKE_PAGES: tuple[GuiSmokePage, ...] = (
    GuiSmokePage("dashboard", "/", "Dashboard"),
    GuiSmokePage("agents", "/agents", "Agents"),
    GuiSmokePage("people", "/people", "People"),
    GuiSmokePage("locations", "/locations", "Locations"),
    GuiSmokePage("spaces", "/spaces", "Spaces"),
    GuiSmokePage("devices", "/devices", "Devices"),
    GuiSmokePage("sessions", "/sessions", "Sessions"),
    GuiSmokePage("live-session", "/live-session", "Live Session"),
    GuiSmokePage("memories", "/memories", "Memories"),
    GuiSmokePage("recognition", "/recognition", "Recognition"),
    GuiSmokePage("actions", "/actions", "Actions"),
    GuiSmokePage("tapdb-graph", "/tapdb/graph", "Graph"),
    GuiSmokePage("tapdb-query", "/tapdb/query?kind=instance&limit=50", "Query"),
    GuiSmokePage("audit", "/audit", "Audit"),
    GuiSmokePage("observability", "/observability", "Observability"),
    GuiSmokePage("capability-matrix", "/capabilities", "Capability Matrix"),
    GuiSmokePage("artifacts", "/artifacts", "Artifacts"),
    GuiSmokePage("settings-profile", "/profile", "Profile"),
)


class SmokeRuntime(Protocol):
    def start_session(self, scenario: LocalSmokeScenario) -> str: ...

    def record_transcript(self, session_id: str, scenario: LocalSmokeScenario) -> str: ...

    def commit_memory(
        self, *, transcript_event_id: str, session_id: str, scenario: LocalSmokeScenario
    ) -> tuple[str, dict[str, Any]]: ...

    def record_recognition(self, session_id: str, scenario: LocalSmokeScenario) -> str: ...

    def dispatch_action(self, *, session_id: str, transcript_event_id: str, scenario: LocalSmokeScenario) -> str: ...

    def record_device_result(self, action_id: str, scenario: LocalSmokeScenario) -> dict[str, Any]: ...


class LocalInMemorySmokeRuntime:
    """Deterministic no-network runtime used by `marvain smoke`."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.memories: dict[str, dict[str, Any]] = {}
        self.recognition_observations: dict[str, dict[str, Any]] = {}
        self.actions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _id(scenario: LocalSmokeScenario, label: str) -> str:
        return str(uuid5(NAMESPACE_URL, f"marvain:{scenario.seed}:{label}"))

    def start_session(self, scenario: LocalSmokeScenario) -> str:
        session_id = self._id(scenario, "session")
        self.sessions[session_id] = {
            "session_id": session_id,
            "agent_id": scenario.agent_id,
            "space_id": scenario.space_id,
            "device_id": scenario.device_id,
            "state": "active",
        }
        return session_id

    def record_transcript(self, session_id: str, scenario: LocalSmokeScenario) -> str:
        self._require_session(session_id)
        transcript_event_id = self._id(scenario, "transcript-event")
        self.events[transcript_event_id] = {
            "event_id": transcript_event_id,
            "session_id": session_id,
            "agent_id": scenario.agent_id,
            "space_id": scenario.space_id,
            "device_id": scenario.device_id,
            "type": "transcript_chunk",
            "text": scenario.transcript_text,
        }
        return transcript_event_id

    def commit_memory(
        self, *, transcript_event_id: str, session_id: str, scenario: LocalSmokeScenario
    ) -> tuple[str, dict[str, Any]]:
        self._require_session(session_id)
        event = self._require_event(transcript_event_id)
        if event["session_id"] != session_id:
            raise SmokeError("transcript event does not belong to session")
        memory_id = self._id(scenario, "memory")
        for kind in MEMORY_KIND_VALUES:
            kind_memory_id = self._id(scenario, f"memory-{kind}")
            self.memories[kind_memory_id] = {
                "memory_id": kind_memory_id,
                "agent_id": scenario.agent_id,
                "space_id": scenario.space_id,
                "session_id": session_id,
                "source_event_id": transcript_event_id,
                "device_id": scenario.device_id,
                "person_id": scenario.person_id,
                "content": f"{scenario.transcript_text} [{kind}]",
                "tier": kind,
                "lifecycle_state": "committed",
            }
        memory_id = self._id(scenario, "memory-episodic")
        return memory_id, self.recall_memory(memory_id=memory_id, query=scenario.recall_query)

    def recall_memory(self, *, memory_id: str, query: str) -> dict[str, Any]:
        memory = self._require_memory(memory_id)
        query_terms = {term.lower() for term in query.split() if term.strip()}
        content_terms = {term.lower().strip(".,") for term in str(memory["content"]).split() if term.strip()}
        matched_terms = sorted(query_terms & content_terms)
        return {
            "matched": bool(matched_terms),
            "memory_id": memory_id,
            "content": memory["content"],
            "source_event_id": memory["source_event_id"],
            "source_excerpt": str(memory["content"])[:240],
            "device_id": memory["device_id"],
            "space_id": memory["space_id"],
            "session_id": memory["session_id"],
            "person_id": memory["person_id"],
            "rank": 1,
            "score": 1.0 if matched_terms else 0.0,
            "ranking_features": {
                "rank": 1,
                "embedding_distance": 0.0 if matched_terms else 1.0,
                "keyword_match": matched_terms,
                "score": 1.0 if matched_terms else 0.0,
            },
            "matched_terms": matched_terms,
            "consent_filters": {"applied": True, "person_id": memory["person_id"]},
        }

    def record_recognition(self, session_id: str, scenario: LocalSmokeScenario) -> str:
        self._require_session(session_id)
        recognition_observation_id = self._id(scenario, "recognition-observation")
        self.recognition_observations[recognition_observation_id] = {
            "recognition_observation_id": recognition_observation_id,
            "session_id": session_id,
            "agent_id": scenario.agent_id,
            "space_id": scenario.space_id,
            "device_id": scenario.device_id,
            "modality": scenario.recognition_modality,
            "candidate_person_id": scenario.person_id,
            "confidence": 1.0,
            "matched": True,
        }
        return recognition_observation_id

    def dispatch_action(self, *, session_id: str, transcript_event_id: str, scenario: LocalSmokeScenario) -> str:
        self._require_session(session_id)
        self._require_event(transcript_event_id)
        action_id = self._id(scenario, "action")
        self.actions[action_id] = {
            "action_id": action_id,
            "session_id": session_id,
            "source_event_id": transcript_event_id,
            "agent_id": scenario.agent_id,
            "space_id": scenario.space_id,
            "target_device_id": scenario.device_id,
            "kind": scenario.action_kind,
            "status": "awaiting_device_result",
        }
        return action_id

    def record_device_result(self, action_id: str, scenario: LocalSmokeScenario) -> dict[str, Any]:
        action = self._require_action(action_id)
        if action["target_device_id"] != scenario.device_id:
            raise SmokeError("action target device mismatch")
        action["status"] = "completed"
        action["result"] = {"ok": True, "observation": "local device acknowledged command"}
        return {
            "action_id": action_id,
            "device_id": scenario.device_id,
            "status": "completed",
            "ok": True,
            "result": action["result"],
        }

    def _require_session(self, session_id: str) -> dict[str, Any]:
        try:
            return self.sessions[session_id]
        except KeyError as exc:
            raise SmokeError(f"unknown session_id: {session_id}") from exc

    def _require_event(self, event_id: str) -> dict[str, Any]:
        try:
            return self.events[event_id]
        except KeyError as exc:
            raise SmokeError(f"unknown transcript_event_id: {event_id}") from exc

    def _require_memory(self, memory_id: str) -> dict[str, Any]:
        try:
            return self.memories[memory_id]
        except KeyError as exc:
            raise SmokeError(f"unknown memory_id: {memory_id}") from exc

    def _require_action(self, action_id: str) -> dict[str, Any]:
        try:
            return self.actions[action_id]
        except KeyError as exc:
            raise SmokeError(f"unknown action_id: {action_id}") from exc


def run_local_smoke(*, runtime: SmokeRuntime | None = None, scenario: LocalSmokeScenario | None = None) -> SmokeReport:
    scenario = scenario or LocalSmokeScenario()
    runtime = runtime or LocalInMemorySmokeRuntime()

    session_id = runtime.start_session(scenario)
    transcript_event_id = runtime.record_transcript(session_id, scenario)
    memory_id, recall_result = runtime.commit_memory(
        transcript_event_id=transcript_event_id,
        session_id=session_id,
        scenario=scenario,
    )
    recognition_observation_id = runtime.record_recognition(session_id, scenario)
    action_id = runtime.dispatch_action(
        session_id=session_id,
        transcript_event_id=transcript_event_id,
        scenario=scenario,
    )
    device_result = runtime.record_device_result(action_id, scenario)
    completion_score = _completion_score(
        session_id=session_id,
        transcript_event_id=transcript_event_id,
        memory_id=memory_id,
        recall_result=recall_result,
        recognition_observation_id=recognition_observation_id,
        action_id=action_id,
        device_result=device_result,
    )
    return SmokeReport(
        session_id=session_id,
        transcript_event_id=transcript_event_id,
        memory_id=memory_id,
        memory_ids_by_kind={
            kind: getattr(runtime, "memories", {})
            .get(LocalInMemorySmokeRuntime._id(scenario, f"memory-{kind}"), {})
            .get("memory_id", "")
            for kind in MEMORY_KIND_VALUES
        },
        recall_result=recall_result,
        recognition_observation_id=recognition_observation_id,
        action_id=action_id,
        device_result=device_result,
        completion_score=completion_score,
    )


def _completion_score(
    *,
    session_id: str,
    transcript_event_id: str,
    memory_id: str,
    recall_result: dict[str, Any],
    recognition_observation_id: str,
    action_id: str,
    device_result: dict[str, Any],
) -> float:
    checks = [
        bool(session_id),
        bool(transcript_event_id),
        bool(memory_id),
        recall_result.get("matched") is True,
        bool(recognition_observation_id),
        bool(action_id),
        device_result.get("ok") is True,
        device_result.get("status") == "completed",
    ]
    return round(sum(1 for item in checks if item) / len(checks), 3)


def _emit_smoke_report(report: SmokeReport, *, mode: str, extra: dict[str, Any] | None = None) -> None:
    data: dict[str, Any] = {"mode": mode, **report.as_dict()}
    if extra:
        data.update(extra)
    _emit_mapping(data)


def _emit_mapping(data: dict[str, Any]) -> None:
    if get_context().json_mode:
        output.emit_json(data)
        return
    output.print_text(json.dumps(data, indent=2, sort_keys=True))


def _context_value(name: str) -> str | None:
    value = get_context().invocation.get(name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _load_smoke_ctx(*, stack: str | None):
    try:
        return load_ctx(
            config_override=str(get_context().config_path)
            if get_context().config_path
            else _context_value("config_path"),
            env=_context_value("env"),
            profile=_context_value("profile"),
            region=_context_value("region"),
            stack=stack or _context_value("stack"),
        )
    except ConfigError as exc:
        raise SmokeError(str(exc)) from exc


def _stack_outputs(ctx) -> dict[str, str]:
    configured = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("resources", {})
    outputs = {key: str(value) for key, value in configured.items() if isinstance(value, str) and value}
    try:
        live_outputs = aws_stack_outputs(ctx, dry_run=False)
    except Exception as exc:
        if not outputs:
            raise SmokeError(f"Could not resolve CloudFormation outputs for {ctx.env.stack_name}: {exc}") from exc
        live_outputs = {}
    outputs.update({key: str(value) for key, value in live_outputs.items() if value})
    return outputs


def _require_outputs(outputs: dict[str, str]) -> None:
    missing = [key for key in DEPLOYED_SMOKE_REQUIRED_OUTPUTS if not outputs.get(key)]
    if missing:
        raise SmokeError("Missing required dev stack outputs: " + ", ".join(missing))


def _require_env(names: tuple[str, ...]) -> dict[str, str]:
    values = {name: str(os.getenv(name) or "").strip() for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SmokeError("Missing required deployed smoke environment variables: " + ", ".join(missing))
    return values


def _secret_json(*, secret_arn: str, region: str, profile: str) -> dict[str, Any]:
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    raw = str(response.get("SecretString") or "").strip()
    if not raw:
        raise SmokeError(f"Secret {secret_arn} has no SecretString")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise SmokeError(f"Secret {secret_arn} did not contain a JSON object")
    return data


def _admin_key(*, outputs: dict[str, str], region: str, profile: str) -> str:
    explicit = str(os.getenv("MARVAIN_ADMIN_API_KEY") or "").strip()
    if explicit:
        return explicit
    data = _secret_json(secret_arn=outputs["AdminApiKeySecretArn"], region=region, profile=profile)
    key = str(data.get("admin_api_key") or "").strip()
    if not key:
        raise SmokeError("Admin API key secret is missing admin_api_key")
    return key


def _cognito_access_token(
    *,
    username: str,
    password: str,
    user_pool_id: str,
    app_client_id: str,
    region: str,
    profile: str,
) -> str:
    from daylily_auth_cognito.admin.client import CognitoAdminClient

    admin = CognitoAdminClient(
        region=region,
        aws_profile=profile,
        user_pool_id=user_pool_id,
        app_client_id=app_client_id,
    )
    try:
        response = admin.cognito.admin_initiate_auth(
            UserPoolId=user_pool_id,
            ClientId=app_client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    except Exception as exc:
        raise SmokeError(f"Cognito login failed for deployed smoke user {username}: {exc}") from exc
    auth_result = response.get("AuthenticationResult") or {}
    token = str(auth_result.get("AccessToken") or "").strip()
    if not token:
        raise SmokeError("Cognito login response did not include an access token")
    return token


def _http_json(
    *,
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    admin_key: str | None = None,
    timeout_s: int = 30,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method.upper())
    request.add_header("Accept", "application/json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if bearer_token:
        request.add_header("Authorization", f"Bearer {bearer_token}")
    if admin_key:
        request.add_header("X-Admin-Key", admin_key)
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        detail = raw.decode("utf-8", errors="replace")
        raise SmokeError(f"HTTP {exc.code} {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SmokeError(f"HTTP request failed for {url}: {exc}") from exc
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SmokeError(f"HTTP {url} did not return JSON") from exc
    if not isinstance(data, dict):
        raise SmokeError(f"HTTP {url} returned non-object JSON")
    return data


def _rest_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _assert_recall_proof(recall: dict[str, Any]) -> dict[str, Any]:
    memories = recall.get("memories")
    if not isinstance(memories, list) or not memories:
        raise SmokeError("Recall returned no memories")
    first = memories[0]
    if not isinstance(first, dict):
        raise SmokeError("Recall returned malformed memory row")
    explanation = first.get("explanation")
    if not isinstance(explanation, dict):
        raise SmokeError("Recall row is missing explanation")
    ranking = explanation.get("ranking")
    required_explanation = (
        "source_excerpt",
        "source_event_id",
        "device_id",
        "space_id",
        "session_id",
        "person_id",
        "consent_filters",
    )
    missing = [key for key in required_explanation if key not in explanation]
    if not isinstance(ranking, dict):
        missing.append("ranking")
    else:
        for key in ("embedding_distance", "keyword_match", "rank"):
            if key not in ranking:
                missing.append(f"ranking.{key}")
    if missing:
        raise SmokeError("Recall explanation missing proof fields: " + ", ".join(missing))
    return first


def _run_two_device_rest_proof(
    *,
    rest_base: str,
    admin_key: str,
    agent_id: str,
    space_id: str,
    run_id: str,
) -> dict[str, Any]:
    scopes = ["events:write", "events:read", "memories:write", "memories:read", "presence:write"]
    left = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/admin/devices/register"),
        payload={
            "agent_id": agent_id,
            "name": f"round5-left-{run_id}",
            "scopes": scopes,
            "capabilities": {"kind": "satellite", "round5_probe": True},
            "location_label": f"round5-left-location-{run_id}",
        },
        admin_key=admin_key,
    )
    right = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/admin/devices/register"),
        payload={
            "agent_id": agent_id,
            "name": f"round5-right-{run_id}",
            "scopes": scopes,
            "capabilities": {"kind": "satellite", "round5_probe": True},
            "location_label": f"round5-right-location-{run_id}",
        },
        admin_key=admin_key,
    )
    for label, device in (("left", left), ("right", right)):
        if not device.get("device_id") or not device.get("device_token"):
            raise SmokeError(f"Deployed {label} device registration did not return id and token")
    left_event = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/events"),
        payload={
            "space_id": space_id,
            "type": "round5.device.proof",
            "payload": {"target": "left", "run_id": run_id},
        },
        bearer_token=str(left["device_token"]),
    )
    right_event = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/events"),
        payload={
            "space_id": space_id,
            "type": "round5.device.proof",
            "payload": {"target": "right", "run_id": run_id},
        },
        bearer_token=str(right["device_token"]),
    )
    return {
        "left_device_id": left["device_id"],
        "right_device_id": right["device_id"],
        "left_event_id": left_event.get("event_id"),
        "right_event_id": right_event.get("event_id"),
        "routing_transport": "deployed-rest-device-token",
    }


def run_deployed_smoke(*, stack: str | None = None, include_two_device_proof: bool = False) -> dict[str, Any]:
    """Run the deployed V1 smoke against real dev-stack endpoints."""
    env = _require_env(DEPLOYED_SMOKE_REQUIRED_ENV)
    ctx = _load_smoke_ctx(stack=stack)
    outputs = _stack_outputs(ctx)
    _require_outputs(outputs)

    run_id = datetime.now(timezone.utc).strftime("round5-%Y%m%dT%H%M%SZ")
    rest_base = outputs["HubRestApiBase"].rstrip("/")
    admin_key = _admin_key(outputs=outputs, region=ctx.env.aws_region, profile=ctx.env.aws_profile)
    access_token = _cognito_access_token(
        username=env["MARVAIN_SMOKE_COGNITO_USERNAME"],
        password=env["MARVAIN_SMOKE_COGNITO_PASSWORD"],
        user_pool_id=outputs["CognitoUserPoolId"],
        app_client_id=outputs["CognitoAppClientId"],
        region=ctx.env.aws_region,
        profile=ctx.env.aws_profile,
    )
    health = _http_json(method="GET", url=_rest_url(rest_base, "/health"))
    bootstrap = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/admin/bootstrap"),
        payload={"agent_name": f"Round 5 Smoke {run_id}", "default_space_name": f"round5-space-{run_id}"},
        admin_key=admin_key,
    )
    agent_id = str(bootstrap.get("agent_id") or "")
    space_id = str(bootstrap.get("space_id") or "")
    device_token = str(bootstrap.get("device_token") or "")
    if not agent_id or not space_id or not device_token:
        raise SmokeError("Bootstrap did not return agent_id, space_id, and device_token")

    transcript = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/events"),
        payload={
            "space_id": space_id,
            "type": "transcript_chunk",
            "payload": {
                "text": f"Round 5 deployed smoke remembers taxonomy, recall, recognition, TapDB graph, and topology. {run_id}",
                "speaker": "smoke",
            },
        },
        bearer_token=device_token,
    )
    source_event_id = str(transcript.get("event_id") or "")
    if not source_event_id:
        raise SmokeError("Transcript event did not return event_id")

    memory_ids: dict[str, str] = {}
    for kind in MEMORY_KIND_VALUES:
        created = _http_json(
            method="POST",
            url=_rest_url(rest_base, "/v1/memories"),
            payload={
                "space_id": space_id,
                "source_event_id": source_event_id,
                "tier": kind,
                "content": f"Round 5 deployed smoke {kind} memory proof for {run_id}.",
                "metadata": {"run_id": run_id, "proof": "round5"},
                "modality": "text",
            },
            bearer_token=device_token,
        )
        memory_id = str(created.get("memory_id") or "")
        if not memory_id:
            raise SmokeError(f"Memory create did not return memory_id for kind {kind}")
        memory_ids[kind] = memory_id

    recall = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/recall"),
        payload={
            "agent_id": agent_id,
            "space_id": space_id,
            "query": f"Round 5 deployed smoke taxonomy recall {run_id}",
            "k": 5,
            "tiers": list(MEMORY_KIND_VALUES),
        },
        bearer_token=device_token,
    )
    recalled = _assert_recall_proof(recall)

    graph_probe = _http_json(
        method="GET",
        url=_rest_url(
            rest_base,
            f"/api/dag/data?start_euid={recalled.get('explanation', {}).get('tapdb_euid') or memory_ids['episodic']}&depth=3",
        ),
        bearer_token=access_token,
    )
    two_device = (
        _run_two_device_rest_proof(
            rest_base=rest_base,
            admin_key=admin_key,
            agent_id=agent_id,
            space_id=space_id,
            run_id=run_id,
        )
        if include_two_device_proof
        else None
    )
    return {
        "mode": "v1-dev-deployed",
        "dev_stack": ctx.env.stack_name,
        "mutates_runtime": True,
        "run_id": run_id,
        "health": health,
        "proofs": {
            "cognito_login": True,
            "worker_join": "requires LiveKit room evidence from deployed worker logs",
            "livekit_url_present": bool(outputs.get("LiveKitUrl")),
            "chat_transcript_event_id": source_event_id,
            "speech_transcript": "requires browser audio device; not simulated by CLI smoke",
            "memory_ids_by_kind": memory_ids,
            "recall_memory_id": recalled.get("memory_id"),
            "recall_explanation": recalled.get("explanation"),
            "recognition": "requires deployed biometric fixture or configured recognizer readiness endpoint",
            "tapdb_graph_probe": graph_probe,
            "observability": "health endpoint passed; GUI observability is covered by Playwright smoke",
            "two_device": two_device,
            "hub_websocket_url_present": bool(outputs.get("HubWebSocketUrl")),
        },
    }


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")


def _fill_visible_form(page: Any) -> bool:
    return bool(
        page.evaluate(
            """() => {
                const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                const forms = Array.from(document.querySelectorAll('form')).filter(visible);
                if (!forms.length) return false;
                const form = forms[0];
                for (const input of form.querySelectorAll('input, textarea, select')) {
                    if (!visible(input) || input.type === 'hidden' || input.disabled || input.readOnly) continue;
                    if (input.tagName === 'SELECT') {
                        const option = Array.from(input.options).find((item) => item.value);
                        if (option) input.value = option.value;
                    } else if (input.type === 'checkbox') {
                        input.checked = input.required || input.name.includes('consent');
                    } else if (input.type === 'file') {
                        continue;
                    } else if (!input.value) {
                        input.value = input.type === 'email' ? 'gui-smoke@example.test' : `gui-smoke-${input.name || input.id || 'value'}`;
                    }
                    input.dispatchEvent(new Event('input', {bubbles: true}));
                    input.dispatchEvent(new Event('change', {bubbles: true}));
                }
                return true;
            }"""
        )
    )


def _open_first_workflow_control(page: Any) -> str:
    labels = (
        "Create Action",
        "Register Device",
        "Create Space",
        "Add Person",
        "Create Person",
        "Upload",
        "Enroll",
        "Start Session",
        "Join",
        "Save Consent",
        "Accept",
        "Reject",
        "Revoke",
    )
    for label in labels:
        locator = page.get_by_role("button", name=label).first
        try:
            if locator.count() and locator.is_visible(timeout=300):
                locator.click(timeout=1_000)
                page.wait_for_timeout(250)
                return f"opened control: {label}"
        except Exception:
            continue
    return "no visible workflow control; captured read-only state"


def _submit_first_visible_form(page: Any) -> str:
    try:
        clicked = page.evaluate(
            """() => {
                const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
                const buttons = Array.from(document.querySelectorAll('button[type="submit"], input[type="submit"]'));
                const button = buttons.find((item) => visible(item) && !item.disabled);
                if (!button) return false;
                button.click();
                return true;
            }"""
        )
        if clicked:
            page.wait_for_timeout(600)
            return "submitted first visible form"
    except Exception as exc:
        return f"submit failed: {exc}"
    return "no visible submit button; after screenshot captured without submit"


def run_gui_smoke_guide(
    *,
    base_url: str,
    output_dir: Path,
    headless: bool = True,
    pages: tuple[GuiSmokePage, ...] = GUI_SMOKE_PAGES,
) -> dict[str, Any]:
    """Exercise GUI routes with Playwright and write a screenshot-backed report."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - depends on optional browser install
        raise SmokeError(f"Playwright is unavailable: {exc}") from exc

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_dir.expanduser().resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    rows: list[dict[str, Any]] = []
    console_errors: list[str] = []
    http_failures: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(
            base_url=base_url, ignore_https_errors=True, viewport={"width": 1440, "height": 1100}
        )
        page = context.new_page()

        def record_console_error(msg: Any) -> None:
            text = str(msg.text)
            if msg.type == "error" and not text.startswith("Failed to load resource:"):
                console_errors.append(text)

        page.on("console", record_console_error)
        page.on(
            "response",
            lambda response: (
                http_failures.append(f"{response.status} {response.url}") if response.status >= 500 else None
            ),
        )
        try:
            for item in pages:
                page_dir = run_dir / _slug(item.name)
                page_dir.mkdir(parents=True, exist_ok=True)
                before = page_dir / "before.png"
                before_submit = page_dir / "before_submit.png"
                after = page_dir / "after_submit.png"
                step_notes: list[str] = []
                try:
                    page.goto(item.path, wait_until="domcontentloaded", timeout=15_000)
                    page.locator("body").wait_for(timeout=10_000)
                    body = page.locator("body").inner_text(timeout=10_000)
                    if "Authentication Error" in body or "Not authenticated" in body:
                        raise SmokeError(
                            "page failed closed to authentication instead of rendering authenticated smoke state"
                        )
                    if item.heading not in body:
                        raise SmokeError(f"heading {item.heading!r} not found in body text")
                    if item.expected_text and item.expected_text not in body:
                        raise SmokeError(f"expected text {item.expected_text!r} not found")
                    page.screenshot(path=str(before), full_page=True)
                    step_notes.append(_open_first_workflow_control(page))
                    if _fill_visible_form(page):
                        step_notes.append("filled first visible form controls")
                    page.screenshot(path=str(before_submit), full_page=True)
                    step_notes.append(_submit_first_visible_form(page))
                    page.screenshot(path=str(after), full_page=True)
                except Exception as exc:
                    failures.append(f"{item.name}: {exc}")
                    step_notes.append(f"failure: {exc}")
                    try:
                        page.screenshot(path=str(after), full_page=True)
                    except Exception:
                        pass
                rows.append(
                    {
                        "name": item.name,
                        "path": item.path,
                        "notes": step_notes,
                        "before": before.relative_to(run_dir).as_posix(),
                        "before_submit": before_submit.relative_to(run_dir).as_posix(),
                        "after": after.relative_to(run_dir).as_posix(),
                    }
                )
        finally:
            context.close()
            browser.close()

    failures.extend(f"console error: {item}" for item in console_errors)
    failures.extend(f"http failure: {item}" for item in http_failures)
    report_path = run_dir / "GUI_SMOKE_REPORT.md"
    report_path.write_text(
        _render_gui_smoke_report(base_url=base_url, run_id=run_id, rows=rows, failures=failures), encoding="utf-8"
    )
    return {
        "run_id": run_id,
        "report_path": str(report_path),
        "output_dir": str(run_dir),
        "pages": len(rows),
        "failures": failures,
        "ok": not failures,
    }


def _render_gui_smoke_report(*, base_url: str, run_id: str, rows: list[dict[str, Any]], failures: list[str]) -> str:
    lines = [
        "# Marvain GUI Smoke Guide",
        "",
        f"- Run ID: `{run_id}`",
        f"- Base URL: `{base_url}`",
        f"- Result: `{'PASS' if not failures else 'FAIL'}`",
        "",
    ]
    if failures:
        lines.append("## Failures")
        lines.append("")
        lines.extend(f"- {item}" for item in failures)
        lines.append("")
    lines.append("## Page Walkthrough")
    lines.append("")
    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                f"### {index}. {row['name']} `{row['path']}`",
                "",
                "Steps:",
                *[f"- {note}" for note in row["notes"]],
                "",
                f"Before: ![before]({row['before']})",
                "",
                f"Just before submit: ![before submit]({row['before_submit']})",
                "",
                f"After submit: ![after submit]({row['after']})",
                "",
            ]
        )
    return "\n".join(lines)


def smoke_v1_local_cmd(
    seed: str = Option("marvain-local-smoke-v1", "--seed", help="Deterministic local smoke seed"),
) -> None:
    """Run the V1 local smoke without AWS, LiveKit, or OpenAI."""
    try:
        report = run_local_smoke(scenario=LocalSmokeScenario(seed=seed))
    except SmokeError as exc:
        raise ClickException(str(exc)) from exc
    _emit_smoke_report(report, mode="v1-local")


def smoke_v1_dev_cmd(
    stack: str | None = Option(None, "--stack", help="Dev stack name override"),
    include_two_device_proof: bool = Option(
        False,
        "--include-two-device-proof",
        help="Register two deployed dev devices and prove distinct device-token event paths",
    ),
) -> None:
    """Run the V1 deployed dev smoke without printing secrets."""
    try:
        result = run_deployed_smoke(stack=stack, include_two_device_proof=include_two_device_proof)
    except SmokeError as exc:
        raise ClickException(str(exc)) from exc
    _emit_mapping(result)


def smoke_gui_guide_cmd(
    base_url: str = Option("https://localhost:8084", "--base-url", help="Authenticated local GUI base URL"),
    output_dir: str = Option("output/playwright/round4-gui-smoke", "--output", help="Artifact output directory"),
    headed: bool = Option(False, "--headed", help="Run browser headed"),
) -> None:
    """Run the screenshot-backed GUI smoke guide."""
    try:
        result = run_gui_smoke_guide(base_url=base_url, output_dir=Path(output_dir), headless=not headed)
    except SmokeError as exc:
        raise ClickException(str(exc)) from exc
    if get_context().json_mode:
        output.emit_json(result)
    else:
        output.print_text(json.dumps(result, indent=2, sort_keys=True))
    if not result["ok"]:
        raise ClickException(f"GUI smoke guide failed; report: {result['report_path']}")
