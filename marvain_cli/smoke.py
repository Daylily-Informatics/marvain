from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
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


class SmokeBlockersError(SmokeError):
    """Raised when deployed smoke reaches known blockers after collecting proof."""

    def __init__(self, *, blockers: list[str], report: dict[str, Any]) -> None:
        self.blockers = blockers
        self.report = report
        joined = "\n".join(f"- {item}" for item in blockers)
        super().__init__(f"Deployed smoke blocked by missing required evidence:\n{joined}")


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
DEPLOYED_SMOKE_REQUIRED_RUNTIME_EVIDENCE = {
    "cognito_hosted_ui": "Cognito Hosted UI browser-session evidence",
    "worker_join": "LiveKit room join evidence from the deployed worker",
    "typed_chat": "typed chat turn handled by the deployed LiveKit worker",
    "speech_transcript": "speech transcript event created through the deployed LiveKit worker",
    "agent_audio": "agent audio publication and browser playback evidence",
    "memory_lifecycle": "classifier-backed memory candidate, commit, recall, and TapDB evidence",
    "recognition": "recognition observation or hypothesis created by the deployed recognition worker",
    "tapdb_graph": "TapDB graph response rooted at a persisted TapDB EUID",
    "observability": "deployed observability evidence for this smoke run",
}


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


@dataclass(frozen=True)
class GuiSmokePostcondition:
    owner: str
    request: str
    assertions: tuple[str, ...]


@dataclass(frozen=True)
class GuiSmokeWorkflow:
    workflow_id: str
    page: str
    path: str
    heading: str
    command: str
    browser_steps: tuple[str, ...]
    persisted_postcondition: GuiSmokePostcondition


GUI_WORKFLOW_MANIFEST_PATH = Path(__file__).resolve().parents[1] / "tests" / "e2e" / "gui_workflow_manifest.json"
GUI_WORKFLOW_MANIFEST_SCHEMA = "marvain.gui-workflows.v1"
GUI_WORKFLOW_PROOF_SCHEMA = "marvain.gui-workflow-proof.v1"
GUI_WORKFLOW_SCREENSHOT_PHASES = ("before", "before_submit", "after_submit")
_GUI_WORKFLOW_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_GUI_WORKFLOW_BINDING_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")


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
    GuiSmokePage("actions-guide", "/actions/guide", "Actions Guide"),
    GuiSmokePage("tools", "/tools", "Tool Catalog"),
    GuiSmokePage("personas", "/personas", "Personas"),
    GuiSmokePage("tapdb-graph", "/tapdb/graph", "Graph"),
    GuiSmokePage("tapdb-query", "/tapdb/query?kind=instance&limit=50", "Query"),
    GuiSmokePage("audit", "/audit", "Audit"),
    GuiSmokePage("observability", "/observability", "Observability"),
    GuiSmokePage("capability-matrix", "/capabilities", "Capability Matrix"),
    GuiSmokePage("artifacts", "/artifacts", "Artifacts"),
    GuiSmokePage("settings-profile", "/profile", "Profile"),
)


def _require_manifest_keys(value: dict[str, Any], *, expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise SmokeError(f"{context} has invalid keys; missing={missing}, unexpected={unexpected}")


def _require_manifest_string(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SmokeError(f"{context} must be a non-empty string")
    return value


def _require_manifest_strings(value: object, *, context: str, minimum: int = 1) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) < minimum:
        raise SmokeError(f"{context} must contain at least {minimum} strings")
    strings = tuple(_require_manifest_string(item, context=f"{context}[{index}]") for index, item in enumerate(value))
    if len(strings) != len(set(strings)):
        raise SmokeError(f"{context} contains duplicate entries")
    return strings


def load_gui_workflow_manifest(
    manifest_path: Path = GUI_WORKFLOW_MANIFEST_PATH,
) -> tuple[GuiSmokeWorkflow, ...]:
    """Load the one explicit GUI workflow inventory; missing or malformed data fails hard."""
    path = manifest_path.expanduser().resolve()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SmokeError(f"GUI workflow manifest does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SmokeError(f"GUI workflow manifest is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SmokeError("GUI workflow manifest root must be an object")
    _require_manifest_keys(
        payload,
        expected={"schema", "screenshot_phases", "workflows"},
        context="GUI workflow manifest",
    )
    if payload["schema"] != GUI_WORKFLOW_MANIFEST_SCHEMA:
        raise SmokeError(
            f"GUI workflow manifest schema must be {GUI_WORKFLOW_MANIFEST_SCHEMA!r}, got {payload['schema']!r}"
        )
    phases = _require_manifest_strings(payload["screenshot_phases"], context="screenshot_phases")
    if phases != GUI_WORKFLOW_SCREENSHOT_PHASES:
        raise SmokeError(f"screenshot_phases must be {list(GUI_WORKFLOW_SCREENSHOT_PHASES)!r}, got {list(phases)!r}")
    raw_workflows = payload["workflows"]
    if not isinstance(raw_workflows, list) or not raw_workflows:
        raise SmokeError("GUI workflow manifest workflows must be a non-empty list")

    workflows: list[GuiSmokeWorkflow] = []
    seen_ids: set[str] = set()
    seen_pages: set[str] = set()
    for index, raw_workflow in enumerate(raw_workflows):
        context = f"workflows[{index}]"
        if not isinstance(raw_workflow, dict):
            raise SmokeError(f"{context} must be an object")
        _require_manifest_keys(
            raw_workflow,
            expected={
                "id",
                "page",
                "path",
                "heading",
                "command",
                "browser_steps",
                "persisted_postcondition",
            },
            context=context,
        )
        workflow_id = _require_manifest_string(raw_workflow["id"], context=f"{context}.id")
        if _GUI_WORKFLOW_ID_RE.fullmatch(workflow_id) is None:
            raise SmokeError(f"{context}.id must be a lowercase hyphenated identifier")
        page = _require_manifest_string(raw_workflow["page"], context=f"{context}.page")
        path_value = _require_manifest_string(raw_workflow["path"], context=f"{context}.path")
        if not path_value.startswith("/") or path_value.startswith("//"):
            raise SmokeError(f"{context}.path must be an absolute application path")
        if workflow_id in seen_ids:
            raise SmokeError(f"duplicate GUI workflow id: {workflow_id}")
        if page in seen_pages:
            raise SmokeError(f"duplicate GUI workflow page: {page}")

        raw_postcondition = raw_workflow["persisted_postcondition"]
        if not isinstance(raw_postcondition, dict):
            raise SmokeError(f"{context}.persisted_postcondition must be an object")
        _require_manifest_keys(
            raw_postcondition,
            expected={"owner", "request", "assert"},
            context=f"{context}.persisted_postcondition",
        )
        request = _require_manifest_string(
            raw_postcondition["request"], context=f"{context}.persisted_postcondition.request"
        )
        if not request.startswith("GET /") or request.startswith("GET //"):
            raise SmokeError(f"{context}.persisted_postcondition.request must be an application-relative GET")
        workflow = GuiSmokeWorkflow(
            workflow_id=workflow_id,
            page=page,
            path=path_value,
            heading=_require_manifest_string(raw_workflow["heading"], context=f"{context}.heading"),
            command=_require_manifest_string(raw_workflow["command"], context=f"{context}.command"),
            browser_steps=_require_manifest_strings(
                raw_workflow["browser_steps"], context=f"{context}.browser_steps", minimum=2
            ),
            persisted_postcondition=GuiSmokePostcondition(
                owner=_require_manifest_string(
                    raw_postcondition["owner"], context=f"{context}.persisted_postcondition.owner"
                ),
                request=request,
                assertions=_require_manifest_strings(
                    raw_postcondition["assert"],
                    context=f"{context}.persisted_postcondition.assert",
                    minimum=2,
                ),
            ),
        )
        workflows.append(workflow)
        seen_ids.add(workflow_id)
        seen_pages.add(page)
    return tuple(workflows)


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
        event = self._require_event(str(memory["source_event_id"]))
        query_terms = {term.lower() for term in query.split() if term.strip()}
        content_terms = {term.lower().strip(".,") for term in str(memory["content"]).split() if term.strip()}
        matched_terms = sorted(query_terms & content_terms)
        source_excerpt = str(memory["content"])[:240]
        return {
            "matched": bool(matched_terms),
            "memory_id": memory_id,
            "content": memory["content"],
            "source_event_id": memory["source_event_id"],
            "source_evidence": {
                "event_id": memory["source_event_id"],
                "event_type": event["type"],
                "excerpt": source_excerpt,
                "device_id": memory["device_id"],
                "space_id": memory["space_id"],
                "session_id": memory["session_id"],
                "person_id": memory["person_id"],
            },
            "source_excerpt": source_excerpt,
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
            "consent_filters": {
                "applied": True,
                "agent_id": memory["agent_id"],
                "space_id": memory["space_id"],
                "person_id": memory["person_id"],
                "committed_only": True,
            },
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
    try:
        live_outputs = aws_stack_outputs(ctx, dry_run=False)
    except Exception as exc:
        raise SmokeError(f"Could not resolve live CloudFormation outputs for {ctx.env.stack_name}: {exc}") from exc
    return {key: str(value) for key, value in live_outputs.items() if value}


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
        response = admin.cognito.initiate_auth(
            ClientId=app_client_id,
            AuthFlow="USER_PASSWORD_AUTH",
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
        "source_evidence",
        "source_excerpt",
        "source_event_id",
        "device_id",
        "space_id",
        "session_id",
        "person_id",
        "consent_filters",
    )
    missing = [key for key in required_explanation if key not in explanation]
    source_evidence = explanation.get("source_evidence")
    if not isinstance(source_evidence, dict):
        missing.append("source_evidence")
    else:
        for key in ("event_id", "excerpt", "device_id", "space_id", "session_id", "person_id"):
            if key not in source_evidence:
                missing.append(f"source_evidence.{key}")
    if not isinstance(ranking, dict):
        missing.append("ranking")
    else:
        for key in ("embedding_distance", "keyword_match", "rank"):
            if key not in ranking:
                missing.append(f"ranking.{key}")
    if missing:
        raise SmokeError("Recall explanation missing proof fields: " + ", ".join(missing))
    return first


def _required_text_fields(evidence: dict[str, Any], fields: tuple[str, ...]) -> list[str]:
    return [field for field in fields if not str(evidence.get(field) or "").strip()]


def _runtime_evidence_contract_errors(
    key: str,
    evidence: dict[str, Any],
    *,
    run_id: str | None,
) -> list[str]:
    required_fields: dict[str, tuple[str, ...]] = {
        "cognito_hosted_ui": (
            "evidence_kind",
            "user_sub",
            "browser_session_id",
            "observed_at",
        ),
        "worker_join": (
            "evidence_kind",
            "room_name",
            "participant_identity",
            "session_id",
            "worker_version",
            "observed_at",
        ),
        "typed_chat": (
            "evidence_kind",
            "session_id",
            "user_event_id",
            "agent_event_id",
            "agent_response_text",
        ),
        "speech_transcript": (
            "evidence_kind",
            "session_id",
            "event_id",
            "audio_track_sid",
            "transcript_text",
        ),
        "agent_audio": (
            "evidence_kind",
            "session_id",
            "track_sid",
            "participant_identity",
            "playback_started_at",
        ),
        "memory_lifecycle": (
            "evidence_kind",
            "source_event_id",
            "candidate_id",
            "memory_id",
            "recall_id",
            "tapdb_euid",
        ),
        "recognition": (
            "evidence_kind",
            "observation_id",
            "worker_id",
            "model_version",
        ),
        "tapdb_graph": (
            "evidence_kind",
            "start_euid",
        ),
        "observability": (
            "evidence_kind",
            "run_id",
        ),
    }
    expected_kinds = {
        "cognito_hosted_ui": "hosted_ui_browser_session",
        "worker_join": "livekit_worker_participant",
        "typed_chat": "livekit_typed_chat_turn",
        "speech_transcript": "livekit_audio_transcript",
        "agent_audio": "livekit_agent_audio_playback",
        "memory_lifecycle": "memory_lifecycle",
        "recognition": "recognition_lifecycle",
        "tapdb_graph": "tapdb_graph",
        "observability": "correlated_runtime_state",
    }
    errors = [f"missing {field}" for field in _required_text_fields(evidence, required_fields[key])]
    expected_kind = expected_kinds[key]
    if evidence.get("evidence_kind") and evidence.get("evidence_kind") != expected_kind:
        errors.append(f"evidence_kind must be {expected_kind!r}")

    if key == "speech_transcript":
        input_modality = str(evidence.get("input_modality") or "")
        if input_modality not in {"microphone", "browser_audio"}:
            errors.append("input_modality must be real browser audio or microphone capture")
        if evidence.get("deterministic_fixture") is True:
            errors.append("deterministic fixture evidence is not deployed proof")
    elif key == "recognition":
        if not evidence.get("hypothesis_id") and not evidence.get("no_match_id"):
            errors.append("missing hypothesis_id or no_match_id")
        if evidence.get("fixture") is True:
            errors.append("fixture evidence is not deployed proof")
    elif key == "tapdb_graph":
        if not isinstance(evidence.get("node_count"), int) or int(evidence.get("node_count") or 0) < 1:
            errors.append("node_count must prove a persisted graph root")
        if not isinstance(evidence.get("edge_count"), int):
            errors.append("missing integer edge_count")
    elif key == "observability":
        states = evidence.get("states")
        if not isinstance(states, dict):
            errors.append("missing correlated states")
        else:
            for state in ("worker", "memory", "recognition", "device", "tapdb"):
                if state not in states:
                    errors.append(f"missing states.{state}")
        if run_id and evidence.get("run_id") != run_id:
            errors.append("run_id does not match the smoke run")
    return errors


def _two_device_evidence_errors(evidence: dict[str, Any]) -> list[str]:
    fields = (
        "evidence_kind",
        "left_device_id",
        "right_device_id",
        "left_location_id",
        "right_location_id",
        "left_space_id",
        "right_space_id",
        "left_action_id",
        "right_action_id",
        "left_ack_id",
        "right_ack_id",
        "left_result_id",
        "right_result_id",
    )
    errors = [f"missing {field}" for field in _required_text_fields(evidence, fields)]
    if evidence.get("evidence_kind") and evidence.get("evidence_kind") != "deployed_device_routing":
        errors.append("evidence_kind must be 'deployed_device_routing'")
    for left, right in (
        ("left_device_id", "right_device_id"),
        ("left_location_id", "right_location_id"),
        ("left_space_id", "right_space_id"),
    ):
        if evidence.get(left) and evidence.get(left) == evidence.get(right):
            errors.append(f"{left} and {right} must be distinct")
    return errors


def _runtime_evidence_blockers(
    proofs: dict[str, Any],
    *,
    run_id: str | None = None,
    include_two_device_proof: bool = False,
) -> list[str]:
    blockers: list[str] = []
    requirements = dict(DEPLOYED_SMOKE_REQUIRED_RUNTIME_EVIDENCE)
    if include_two_device_proof:
        requirements["two_device"] = "two distinct deployed devices routed through owning WebSocket/action services"
    for key, required in requirements.items():
        if key not in proofs:
            blockers.append(f"{key}: missing proof field; required evidence: {required}")
            continue
        evidence = proofs[key]
        if isinstance(evidence, str):
            blockers.append(f"{key}: placeholder string is not accepted; required evidence: {required}")
            continue
        if not isinstance(evidence, dict):
            blockers.append(f"{key}: malformed proof field {type(evidence).__name__}; required evidence: {required}")
            continue
        if evidence.get("ok") is True:
            errors = (
                _two_device_evidence_errors(evidence)
                if key == "two_device"
                else _runtime_evidence_contract_errors(key, evidence, run_id=run_id)
            )
            if errors:
                blockers.append(f"{key}: invalid owning-service evidence: " + "; ".join(errors))
            continue
        detail = str(evidence.get("blocker") or "").strip()
        if detail:
            blockers.append(f"{key}: {detail}")
        else:
            blockers.append(f"{key}: proof did not report ok=true; required evidence: {required}")
    return blockers


def run_deployed_smoke(*, stack: str | None = None, include_two_device_proof: bool = False) -> dict[str, Any]:
    """Run the deployed V1 smoke against real dev-stack endpoints."""
    env = _require_env(DEPLOYED_SMOKE_REQUIRED_ENV)
    ctx = _load_smoke_ctx(stack=stack)
    outputs = _stack_outputs(ctx)
    _require_outputs(outputs)

    run_id = datetime.now(timezone.utc).strftime("round6-%Y%m%dT%H%M%SZ")
    rest_base = outputs["HubRestApiBase"].rstrip("/")
    admin_key = _admin_key(outputs=outputs, region=ctx.env.aws_region, profile=ctx.env.aws_profile)
    _cognito_access_token(
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
        payload={"agent_name": f"Round 6 Smoke {run_id}", "default_space_name": f"round6-space-{run_id}"},
        admin_key=admin_key,
    )
    agent_id = str(bootstrap.get("agent_id") or "")
    space_id = str(bootstrap.get("space_id") or "")
    device_token = str(bootstrap.get("device_token") or "")
    if not agent_id or not space_id or not device_token:
        raise SmokeError("Bootstrap did not return agent_id, space_id, and device_token")

    source_evidence = _http_json(
        method="POST",
        url=_rest_url(rest_base, "/v1/events"),
        payload={
            "space_id": space_id,
            "type": "smoke.api_source_evidence",
            "payload": {
                "text": f"Round 6 deployed API probe source evidence. {run_id}",
                "producer": "marvain-cli",
            },
        },
        bearer_token=device_token,
    )
    source_event_id = str(source_evidence.get("event_id") or "")
    if not source_event_id:
        raise SmokeError("API source-evidence probe did not return event_id")

    api_health = _http_json(method="GET", url=_rest_url(rest_base, "/api_health"))
    endpoint_health = _http_json(method="GET", url=_rest_url(rest_base, "/endpoint_health?limit=200"))
    proofs: dict[str, Any] = {
        "cognito_api_auth_probe": {
            "authenticated": True,
            "user_pool_id": outputs["CognitoUserPoolId"],
            "app_client_id": outputs["CognitoAppClientId"],
        },
        "cognito_hosted_ui": {
            "ok": False,
            "blocker": "Hosted UI browser-session receipt collection is not implemented.",
        },
        "worker_join": {
            "ok": False,
            "blocker": "No participant receipt from the deployed LiveKit worker was collected.",
        },
        "livekit_url_present": bool(outputs.get("LiveKitUrl")),
        "api_source_event_id": source_event_id,
        "typed_chat": {
            "ok": False,
            "blocker": "No typed-chat turn receipt from the deployed LiveKit worker was collected.",
        },
        "speech_transcript": {
            "ok": False,
            "blocker": "No transcript receipt from real browser audio or microphone capture was collected.",
        },
        "agent_audio": {
            "ok": False,
            "blocker": "No agent audio publication and browser playback receipt was collected.",
        },
        "api_memory_probe": {
            "performed": False,
            "reason": "Admin-device memory creation is not accepted as live worker memory evidence.",
        },
        "memory_lifecycle": {
            "ok": False,
            "blocker": "No classifier-backed candidate, commit, and recall receipt from a live turn was collected.",
        },
        "recognition": {
            "ok": False,
            "blocker": "No observation lifecycle receipt from the deployed recognition worker was collected.",
        },
        "tapdb_graph": {
            "ok": False,
            "blocker": "No live memory lifecycle returned a persisted TapDB EUID for the graph probe.",
        },
        "observability": {
            "ok": False,
            "blocker": "Health responses were collected, but no run-correlated runtime state receipt was available.",
            "api_health_probe": api_health,
            "endpoint_health_probe": endpoint_health,
        },
        "two_device": (
            {
                "ok": False,
                "blocker": "No two-location WebSocket dispatch, acknowledgement, and result receipt was collected.",
            }
            if include_two_device_proof
            else None
        ),
        "hub_websocket_url_present": bool(outputs.get("HubWebSocketUrl")),
    }
    report: dict[str, Any] = {
        "mode": "v1-dev-deployed",
        "dev_stack": ctx.env.stack_name,
        "mutates_runtime": True,
        "run_id": run_id,
        "health": health,
        "proofs": proofs,
    }
    blockers = _runtime_evidence_blockers(
        proofs,
        run_id=run_id,
        include_two_device_proof=include_two_device_proof,
    )
    if blockers:
        report["ok"] = False
        report["blockers"] = blockers
        raise SmokeBlockersError(blockers=blockers, report=report)
    report["ok"] = True
    return report


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")


class GuiWorkflowBlocked(SmokeError):
    """Raised when an explicit workflow contract or owning service is unavailable."""


class GuiWorkflowFailed(SmokeError):
    """Raised when a workflow runs but its command or persisted proof is invalid."""


def _workflow_locator(page: Any, *, attribute: str, workflow_id: str) -> Any:
    return page.locator(f'[{attribute}="{workflow_id}"]')


def _require_single_visible_workflow_control(locator: Any, *, selector: str, workflow_id: str) -> None:
    count = locator.count()
    if count == 0:
        raise GuiWorkflowBlocked(f"{workflow_id}: required page-specific control is absent: {selector}")
    if count != 1:
        raise GuiWorkflowFailed(f"{workflow_id}: expected one page-specific control for {selector}, found {count}")
    if not locator.is_visible(timeout=500):
        raise GuiWorkflowBlocked(f"{workflow_id}: page-specific control is not visible: {selector}")


def _prepare_manifest_workflow(page: Any, workflow: GuiSmokeWorkflow) -> None:
    prepare_selector = f'data-marvain-smoke-prepare="{workflow.workflow_id}"'
    prepare = _workflow_locator(
        page,
        attribute="data-marvain-smoke-prepare",
        workflow_id=workflow.workflow_id,
    )
    _require_single_visible_workflow_control(
        prepare,
        selector=f"[{prepare_selector}]",
        workflow_id=workflow.workflow_id,
    )
    prepare.click(timeout=5_000)
    submit_selector = f'data-marvain-smoke-submit="{workflow.workflow_id}"'
    submit = _workflow_locator(
        page,
        attribute="data-marvain-smoke-submit",
        workflow_id=workflow.workflow_id,
    )
    _require_single_visible_workflow_control(
        submit,
        selector=f"[{submit_selector}]",
        workflow_id=workflow.workflow_id,
    )


def _load_workflow_receipt(page: Any, workflow: GuiSmokeWorkflow) -> dict[str, Any]:
    receipt = _workflow_locator(
        page,
        attribute="data-marvain-smoke-receipt",
        workflow_id=workflow.workflow_id,
    )
    try:
        receipt.wait_for(state="attached", timeout=10_000)
    except Exception as exc:
        raise GuiWorkflowFailed(
            f"{workflow.workflow_id}: command produced no workflow receipt within 10 seconds"
        ) from exc
    if receipt.count() != 1:
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: expected one command receipt, found {receipt.count()}")
    raw_receipt = receipt.text_content(timeout=2_000)
    try:
        payload = json.loads(raw_receipt or "")
    except json.JSONDecodeError as exc:
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: command receipt is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: command receipt must be an object")
    _require_manifest_keys(
        payload,
        expected={"workflow_id", "command", "completed_browser_steps", "bindings"},
        context=f"{workflow.workflow_id} command receipt",
    )
    if payload["workflow_id"] != workflow.workflow_id:
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: command receipt names a different workflow")
    if payload["command"] != workflow.command:
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: command receipt does not match the manifest command")
    completed_steps = payload["completed_browser_steps"]
    if completed_steps != list(workflow.browser_steps):
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: completed browser steps do not exactly match the manifest")
    bindings = payload["bindings"]
    if not isinstance(bindings, dict) or any(
        not isinstance(key, str) or not isinstance(value, (str, int, float)) or isinstance(value, bool)
        for key, value in bindings.items()
    ):
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: receipt bindings must be scalar identifier values")
    return payload


def _resolve_workflow_request(workflow: GuiSmokeWorkflow, bindings: dict[str, Any]) -> str:
    method, request_path = workflow.persisted_postcondition.request.split(" ", 1)
    if method != "GET":
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: only GET owner postconditions are supported")
    required = set(_GUI_WORKFLOW_BINDING_RE.findall(request_path))
    missing = sorted(required - set(bindings))
    if missing:
        raise GuiWorkflowFailed(
            f"{workflow.workflow_id}: command receipt is missing postcondition bindings: {', '.join(missing)}"
        )

    def replace(match: re.Match[str]) -> str:
        return urllib.parse.quote(str(bindings[match.group(1)]), safe="")

    resolved_path = _GUI_WORKFLOW_BINDING_RE.sub(replace, request_path)
    if "{" in resolved_path or "}" in resolved_path:
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner postcondition request remains unresolved")
    return f"GET {resolved_path}"


def _verify_owner_postcondition(
    *,
    page: Any,
    base_url: str,
    run_id: str,
    workflow: GuiSmokeWorkflow,
    resolved_request: str,
) -> list[str]:
    _method, request_path = resolved_request.split(" ", 1)
    request_url = urllib.parse.urljoin(f"{base_url.rstrip('/')}/", request_path.lstrip("/"))
    response = page.context.request.get(
        request_url,
        headers={
            "X-Marvain-Gui-Smoke-Run-Id": run_id,
            "X-Marvain-Gui-Smoke-Workflow-Id": workflow.workflow_id,
            "X-Marvain-Gui-Smoke-Evidence-Owner": workflow.persisted_postcondition.owner,
        },
        timeout=10_000,
    )
    if response.status in {401, 403, 404, 405}:
        raise GuiWorkflowBlocked(
            f"{workflow.workflow_id}: owner postcondition {resolved_request} returned HTTP {response.status}"
        )
    if response.status < 200 or response.status >= 300:
        raise GuiWorkflowFailed(
            f"{workflow.workflow_id}: owner postcondition {resolved_request} returned HTTP {response.status}"
        )
    try:
        payload = response.json()
    except Exception as exc:
        raise GuiWorkflowFailed(
            f"{workflow.workflow_id}: owner postcondition {resolved_request} did not return JSON proof"
        ) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_proof"), dict):
        raise GuiWorkflowFailed(
            f"{workflow.workflow_id}: owner response lacks workflow_proof from {workflow.persisted_postcondition.owner}"
        )
    proof = payload["workflow_proof"]
    _require_manifest_keys(
        proof,
        expected={"schema", "workflow_id", "owner", "request", "assertions"},
        context=f"{workflow.workflow_id} owner proof",
    )
    expected_header = {
        "schema": GUI_WORKFLOW_PROOF_SCHEMA,
        "workflow_id": workflow.workflow_id,
        "owner": workflow.persisted_postcondition.owner,
        "request": resolved_request,
    }
    for key, expected in expected_header.items():
        if proof[key] != expected:
            raise GuiWorkflowFailed(
                f"{workflow.workflow_id}: owner proof {key} does not match the manifest-derived value"
            )
    assertion_proofs = proof["assertions"]
    if not isinstance(assertion_proofs, list) or len(assertion_proofs) != len(
        workflow.persisted_postcondition.assertions
    ):
        raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner proof does not cover every manifest assertion")
    evidence: list[str] = []
    for expected, assertion_proof in zip(
        workflow.persisted_postcondition.assertions,
        assertion_proofs,
        strict=True,
    ):
        if not isinstance(assertion_proof, dict):
            raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner assertion proof must be an object")
        _require_manifest_keys(
            assertion_proof,
            expected={"assert", "passed", "evidence"},
            context=f"{workflow.workflow_id} owner assertion proof",
        )
        proof_evidence = assertion_proof["evidence"]
        if assertion_proof["assert"] != expected:
            raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner proof assertion text differs from the manifest")
        if assertion_proof["passed"] is not True:
            raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner did not verify assertion: {expected}")
        if not isinstance(proof_evidence, str) or not proof_evidence.strip():
            raise GuiWorkflowFailed(f"{workflow.workflow_id}: owner assertion has no concrete evidence: {expected}")
        evidence.append(f"{expected}: {proof_evidence}")
    return evidence


def _submit_and_verify_manifest_workflow(
    *,
    page: Any,
    base_url: str,
    run_id: str,
    workflow: GuiSmokeWorkflow,
) -> tuple[str, list[str]]:
    submit = _workflow_locator(
        page,
        attribute="data-marvain-smoke-submit",
        workflow_id=workflow.workflow_id,
    )
    submit.click(timeout=5_000)
    receipt = _load_workflow_receipt(page, workflow)
    resolved_request = _resolve_workflow_request(workflow, receipt["bindings"])
    evidence = _verify_owner_postcondition(
        page=page,
        base_url=base_url,
        run_id=run_id,
        workflow=workflow,
        resolved_request=resolved_request,
    )
    return resolved_request, evidence


def run_gui_smoke_guide(
    *,
    base_url: str,
    output_dir: Path,
    headless: bool = True,
    manifest_path: Path = GUI_WORKFLOW_MANIFEST_PATH,
) -> dict[str, Any]:
    """Execute the explicit GUI manifest and require owning-service postcondition proof."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - depends on optional browser install
        raise SmokeError(f"Playwright is unavailable: {exc}") from exc

    workflows = load_gui_workflow_manifest(manifest_path)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_dir.expanduser().resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    blockers: list[str] = []
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
            for workflow in workflows:
                page_dir = run_dir / _slug(workflow.workflow_id)
                page_dir.mkdir(parents=True, exist_ok=True)
                before = page_dir / "before.png"
                before_submit = page_dir / "before_submit.png"
                after = page_dir / "after_submit.png"
                row_failures: list[str] = []
                block_reason: str | None = None
                resolved_request: str | None = None
                verification_evidence: list[str] = []
                prepared = False
                try:
                    page.goto(workflow.path, wait_until="domcontentloaded", timeout=15_000)
                    page.locator("body").wait_for(timeout=10_000)
                    body = page.locator("body").inner_text(timeout=10_000)
                    if "Authentication Error" in body or "Not authenticated" in body:
                        raise GuiWorkflowBlocked(
                            "page failed closed to authentication instead of rendering authenticated smoke state"
                        )
                    if workflow.heading not in body:
                        raise GuiWorkflowFailed(f"heading {workflow.heading!r} not found in body text")
                    page.screenshot(path=str(before), full_page=True)
                    _prepare_manifest_workflow(page, workflow)
                    prepared = True
                except GuiWorkflowBlocked as exc:
                    block_reason = str(exc)
                except Exception as exc:
                    row_failures.append(str(exc))
                if not before.exists():
                    try:
                        page.screenshot(path=str(before), full_page=True)
                    except Exception as exc:
                        row_failures.append(f"before screenshot failed: {exc}")
                try:
                    page.screenshot(path=str(before_submit), full_page=True)
                except Exception as exc:
                    row_failures.append(f"before_submit screenshot failed: {exc}")
                if prepared and not row_failures and block_reason is None:
                    try:
                        resolved_request, verification_evidence = _submit_and_verify_manifest_workflow(
                            page=page,
                            base_url=base_url,
                            run_id=run_id,
                            workflow=workflow,
                        )
                    except GuiWorkflowBlocked as exc:
                        block_reason = str(exc)
                    except Exception as exc:
                        row_failures.append(str(exc))
                try:
                    page.screenshot(path=str(after), full_page=True)
                except Exception as exc:
                    row_failures.append(f"after_submit screenshot failed: {exc}")

                if row_failures:
                    status = "FAIL"
                    reason = "; ".join(row_failures)
                    failures.append(f"{workflow.workflow_id}: {reason}")
                elif block_reason is not None:
                    status = "BLOCKED"
                    reason = block_reason
                    blockers.append(f"{workflow.workflow_id}: {reason}")
                else:
                    status = "PASS"
                    reason = "command completed and every owner postcondition assertion was verified"
                rows.append(
                    {
                        "workflow_id": workflow.workflow_id,
                        "name": workflow.page,
                        "path": workflow.path,
                        "heading": workflow.heading,
                        "command": workflow.command,
                        "browser_steps": list(workflow.browser_steps),
                        "persisted_postcondition": {
                            "owner": workflow.persisted_postcondition.owner,
                            "request": workflow.persisted_postcondition.request,
                            "assert": list(workflow.persisted_postcondition.assertions),
                        },
                        "status": status,
                        "reason": reason,
                        "resolved_request": resolved_request,
                        "verification_evidence": verification_evidence,
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
    overall_status = "FAIL" if failures else "BLOCKED" if blockers else "PASS"
    report_path = run_dir / "GUI_SMOKE_REPORT.md"
    report_path.write_text(
        _render_gui_smoke_report(
            base_url=base_url,
            run_id=run_id,
            rows=rows,
            failures=failures,
            blockers=blockers,
        ),
        encoding="utf-8",
    )
    return {
        "run_id": run_id,
        "report_path": str(report_path),
        "output_dir": str(run_dir),
        "pages": len(rows),
        "status": overall_status,
        "passed": sum(row["status"] == "PASS" for row in rows),
        "blocked": sum(row["status"] == "BLOCKED" for row in rows),
        "failed": sum(row["status"] == "FAIL" for row in rows),
        "failures": failures,
        "blockers": blockers,
        "ok": overall_status == "PASS",
    }


def _render_gui_smoke_report(
    *,
    base_url: str,
    run_id: str,
    rows: list[dict[str, Any]],
    failures: list[str],
    blockers: list[str],
) -> str:
    overall_status = "FAIL" if failures else "BLOCKED" if blockers else "PASS"
    lines = [
        "# Marvain GUI Smoke Guide",
        "",
        f"- Run ID: `{run_id}`",
        f"- Base URL: `{base_url}`",
        f"- Result: `{overall_status}`",
        f"- Workflows: `{len(rows)}`",
        f"- Passed: `{sum(row['status'] == 'PASS' for row in rows)}`",
        f"- Blocked: `{sum(row['status'] == 'BLOCKED' for row in rows)}`",
        f"- Failed: `{sum(row['status'] == 'FAIL' for row in rows)}`",
        "",
    ]
    if failures:
        lines.append("## Failures")
        lines.append("")
        lines.extend(f"- {item}" for item in failures)
        lines.append("")
    if blockers:
        lines.append("## Blockers")
        lines.append("")
        lines.extend(f"- {item}" for item in blockers)
        lines.append("")
    lines.append("## Page Walkthrough")
    lines.append("")
    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                f"### {index}. {row['workflow_id']} on {row['name']} `{row['path']}`",
                "",
                f"Status: `{row['status']}`",
                "",
                f"Command: {row['command']}",
                "",
                "Browser steps:",
                *[f"{step_index}. {step}" for step_index, step in enumerate(row["browser_steps"], start=1)],
                "",
                "Persisted postcondition:",
                f"- Owner: `{row['persisted_postcondition']['owner']}`",
                f"- Request: `{row['persisted_postcondition']['request']}`",
                *[f"- Assert: {assertion}" for assertion in row["persisted_postcondition"]["assert"]],
                "",
                "Execution:",
                f"- Result: {row['reason']}",
                f"- Resolved owner request: `{row['resolved_request'] or 'not resolved'}`",
                *[f"- Owner evidence: {evidence}" for evidence in row["verification_evidence"]],
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
