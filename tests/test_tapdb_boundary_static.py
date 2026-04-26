from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_TAPDB_BOUNDARY_FILES = {
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
