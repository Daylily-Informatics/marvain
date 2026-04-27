from __future__ import annotations

import json
from pathlib import Path

from agent_hub.semantic_tapdb import TEMPLATE_CODES, validate_marvain_template_pack

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_marvain_tapdb_template_pack_validates() -> None:
    result = validate_marvain_template_pack()

    assert result.issues == []
    assert result.templates_loaded >= 23


def test_tapdb_base_schema_is_not_copied_into_marvain() -> None:
    from daylily_tapdb.templates.loader import find_tapdb_core_config_dir

    copied_schema_fragment = "/".join(("layers", "shared", "tapdb_schema"))
    assert not (REPO_ROOT / copied_schema_fragment).exists()
    core_config_dir = find_tapdb_core_config_dir()
    assert "daylily_tapdb" in str(core_config_dir)
    assert core_config_dir.exists()


def test_marvain_tapdb_registry_claims_mvn_for_marvain() -> None:
    domain = json.loads((REPO_ROOT / "tapdb_templates/domain_code_registry.json").read_text(encoding="utf-8"))
    prefix = json.loads((REPO_ROOT / "tapdb_templates/prefix_ownership_registry.json").read_text(encoding="utf-8"))

    assert domain["domains"]["MVN"]["name"] == "marvain"
    assert prefix["ownership"]["MVN"]["MVN"]["issuer_app_code"] == "marvain"


def test_marvain_template_codes_cover_required_semantic_objects() -> None:
    required = {
        "agent",
        "person",
        "account",
        "location",
        "space",
        "device",
        "session",
        "event_transcript",
        "event_sensor",
        "memory_candidate",
        "memory_committed",
        "memory_tombstone",
        "recognition_observation",
        "recognition_hypothesis",
        "presence_assertion",
        "consent_grant",
        "artifact_reference",
        "action_proposal",
        "action_approval",
        "action_execution",
        "action_result",
        "persona",
    }

    assert required <= set(TEMPLATE_CODES)
    assert all(code.startswith("MVN/") and code.endswith("/") for code in TEMPLATE_CODES.values())
