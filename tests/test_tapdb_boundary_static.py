from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_TAPDB_BOUNDARY_FILES = {
    "functions/hub_api/app.py",
    "layers/shared/python/agent_hub/semantic_tapdb.py",
    "functions/tapdb_writer/handler.py",
}


def test_daylily_tapdb_imports_are_confined_to_boundary() -> None:
    offenders: list[str] = []
    for root_name in ("functions", "layers", "apps", "marvain_cli"):
        for path in (REPO_ROOT / root_name).rglob("*.py"):
            rel = str(path.relative_to(REPO_ROOT))
            if rel in ALLOWED_TAPDB_BOUNDARY_FILES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "daylily_tapdb" in text:
                offenders.append(rel)

    assert offenders == []


def test_raw_tapdb_owned_table_access_is_confined_to_boundary() -> None:
    tapdb_tables = (
        "generic_template",
        "generic_instance",
        "generic_instance_lineage",
        "outbox_event",
        "inbox_message",
        "audit_log",
    )
    offenders: list[str] = []
    for root_name in ("functions", "layers", "apps", "marvain_cli"):
        for path in (REPO_ROOT / root_name).rglob("*.py"):
            rel = str(path.relative_to(REPO_ROOT))
            if rel in ALLOWED_TAPDB_BOUNDARY_FILES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if any(table in text for table in tapdb_tables):
                offenders.append(rel)

    assert offenders == []


def test_marvain_does_not_package_a_copied_tapdb_schema() -> None:
    assert not (REPO_ROOT / "layers" / "shared" / "tapdb_schema").exists()


def test_semantic_tapdb_uses_public_tapdb_api_surface() -> None:
    text = (REPO_ROOT / "layers" / "shared" / "python" / "agent_hub" / "semantic_tapdb.py").read_text(encoding="utf-8")
    forbidden = (
        "daylily_tapdb.models",
        "daylily_tapdb.aurora",
        "from sqlalchemy",
        "import sqlalchemy",
        "engine.begin",
        "exec_driver_sql",
        "generic_instance",
        "generic_instance_lineage",
        "tapdb_schema.sql",
    )
    offenders = [token for token in forbidden if token in text]
    assert offenders == []


def test_custom_lineage_routes_are_removed() -> None:
    runtime_files = [
        REPO_ROOT / "functions" / "hub_api" / "app.py",
        REPO_ROOT / "scripts" / "generate_capability_matrix.py",
    ]
    forbidden = ('@app.get("/lineage"', '@app.get("/api/lineage/', '"/lineage"', "lineage.html")
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{token}"
        for path in runtime_files
        for token in forbidden
        if token in path.read_text(encoding="utf-8", errors="ignore")
    ]
    assert offenders == []
