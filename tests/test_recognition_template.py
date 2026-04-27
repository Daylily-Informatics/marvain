from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / "functions" / "hub_api" / "templates"


def _render_recognition(**context: object) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    def url_for(name: str, **params: object) -> str:
        if name == "static":
            return f"/static/{params['path']}"
        return f"/{name}"

    env.globals["url_for"] = url_for
    base_context: dict[str, object] = {
        "user": {"email": "tester@example.com", "user_id": "user-1"},
        "stage": "test",
        "active_page": "recognition",
        "ws_url": None,
        "agents": [{"agent_id": "agent-1", "name": "Agent One", "role": "owner"}],
        "observations": [],
        "hypotheses": [],
        "unknown_observations": [],
        "no_match_hypotheses": [],
        "presence": [],
        "consent_grants": [],
        "artifact_references": [],
        "revocation_statuses": [],
        "readiness_statuses": [],
        "error": None,
    }
    base_context.update(context)
    return env.get_template("recognition.html").render(**base_context)


def test_recognition_template_exposes_full_context_contract() -> None:
    html = _render_recognition(
        observations=[
            {
                "observation_id": "obs-face-1",
                "agent_id": "agent-1",
                "agent_name": "Agent One",
                "space_name": "Kitchen",
                "device_name": "Wall Display",
                "modality": "face",
                "lifecycle_state": "embedded",
                "model_name": "face-v1",
                "artifact_id": "artifact-face-1",
                "created_at": "2026-04-26T10:00:00Z",
            }
        ],
        hypotheses=[
            {
                "hypothesis_id": "hyp-face-1",
                "observation_id": "obs-face-1",
                "agent_id": "agent-1",
                "person_name": "Major",
                "candidate_person_id": "person-1",
                "decision": "accepted",
                "score": 0.98,
                "consent_id": "consent-face-1",
                "created_at": "2026-04-26T10:00:03Z",
            }
        ],
        unknown_observations=[
            {
                "observation_id": "obs-unknown-1",
                "agent_id": "agent-1",
                "modality": "voice",
                "lifecycle_state": "no_match",
                "reason": "No accepted person match",
                "created_at": "2026-04-26T10:02:00Z",
            }
        ],
        no_match_hypotheses=[
            {
                "hypothesis_id": "hyp-no-match-1",
                "observation_id": "obs-unknown-1",
                "agent_id": "agent-1",
                "decision": "no_match",
                "score": 0.12,
            }
        ],
        presence=[
            {
                "presence_assertion_id": "pa-1",
                "agent_id": "agent-1",
                "person_name": "Major",
                "space_name": "Kitchen",
                "status": "present",
                "source": "recognition",
                "asserted_at": "2026-04-26T10:00:04Z",
            }
        ],
        consent_grants=[
            {
                "consent_id": "consent-face-1",
                "agent_id": "agent-1",
                "person_name": "Major",
                "consent_type": "face",
                "status": "active",
                "expires_at": "2026-12-31",
                "revoked_at": None,
            }
        ],
        artifact_references=[
            {
                "artifact_id": "artifact-face-1",
                "agent_id": "agent-1",
                "observation_id": "obs-face-1",
                "kind": "face.snapshot",
                "uri": "s3://redacted/recognition/face.jpg",
                "lifecycle_state": "referenced",
                "created_at": "2026-04-26T10:00:01Z",
            }
        ],
        revocation_statuses=[
            {
                "subject": "Major face enrollment",
                "agent_id": "agent-1",
                "status": "not revoked",
                "detail": "No active revocation.",
            }
        ],
        readiness_statuses=[
            {
                "name": "Recognition worker",
                "agent_id": "agent-1",
                "status": "ready",
                "detail": "Queue and model configured.",
            }
        ],
    )

    expected_fragments = [
        "Recognition",
        "obs-face-1",
        "hyp-face-1",
        "obs-unknown-1",
        "hyp-no-match-1",
        "pa-1",
        "consent-face-1",
        "artifact-face-1",
        "s3://redacted/recognition/face.jpg",
        "Major face enrollment",
        "Recognition worker",
    ]
    for fragment in expected_fragments:
        assert fragment in html


def test_recognition_template_exposes_empty_context_placeholders() -> None:
    html = _render_recognition()

    expected_placeholders = [
        "Awaiting Recognition Observations",
        "Awaiting Identity Hypotheses",
        "No Unknown / No-Match Context",
        "Awaiting Presence Assertions",
        "Consent Grant Context Pending",
        "Artifact Reference Context Pending",
        "Revocation Status Pending",
        "Readiness Status Pending",
    ]
    for placeholder in expected_placeholders:
        assert placeholder in html
