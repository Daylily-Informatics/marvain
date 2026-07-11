#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "plans" / "20260711T011234Z_marvain_operational_100_percent_ledger.md"
MANIFEST = ROOT / "docs" / "reports" / "marvain_operational_completion_evidence.json"
OUT_FILE = ROOT / "docs" / "OPERATIONAL_COMPLETION_STATUS.generated.md"
SCHEMA_VERSION = "marvain.operational-evidence.v1"
CAPABILITY_ID_RE = re.compile(r"^(FND|AGT|MEM|IDN|LIV|TOP|ACT|INT|DAT|OPS)-\d{2}$")

# These weights encode the assessment's stated emphasis on the usable companion,
# memory, action, auth, topology, and integration foundations.
CATEGORY_WEIGHTS: dict[str, float] = {
    "FND": 1.6,
    "AGT": 0.75,
    "MEM": 1.4,
    "IDN": 0.75,
    "LIV": 1.4,
    "TOP": 1.6,
    "ACT": 1.6,
    "INT": 1.6,
    "DAT": 1.0,
    "OPS": 0.75,
}
EVIDENCE_CLASSES = (
    "implementation",
    "local_workflow",
    "integration",
    "deployed",
    "failure_recovery",
    "observability",
    "documentation",
    "regression",
)


@dataclass(frozen=True)
class CapabilityRow:
    capability_id: str
    title: str
    baseline: int
    target: int
    current: int
    status: str
    owner: str
    gate: str

    @property
    def category(self) -> str:
        return self.capability_id.split("-", 1)[0]


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_capability_ledger(path: Path = LEDGER) -> tuple[CapabilityRow, ...]:
    rows: list[CapabilityRow] = []
    in_table = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "## Capability Ledger":
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("|"):
            continue
        cells = _table_cells(line)
        if not cells or not CAPABILITY_ID_RE.fullmatch(cells[0]):
            continue
        if len(cells) != 15:
            raise ValueError(f"{cells[0]} ledger row has {len(cells)} columns; expected 15")
        rows.append(
            CapabilityRow(
                capability_id=cells[0],
                title=cells[1],
                baseline=int(cells[2]),
                target=int(cells[3]),
                current=int(cells[4]),
                status=cells[5],
                owner=cells[6],
                gate=cells[7],
            )
        )
    ids = [row.capability_id for row in rows]
    if len(rows) != 85:
        raise ValueError(f"operational ledger must contain exactly 85 capabilities; found {len(rows)}")
    if len(ids) != len(set(ids)):
        raise ValueError("operational ledger contains duplicate capability IDs")
    return tuple(rows)


def _baseline_evidence(row: CapabilityRow) -> dict[str, list[str]]:
    source = f"docs/sol_ultra_repo_assessment_completion_notes.md#{row.capability_id.lower()}"
    evidence = {key: [] for key in EVIDENCE_CLASSES}
    if row.current >= 50:
        evidence["implementation"] = [source]
    if row.current >= 75:
        evidence["local_workflow"] = [source]
    evidence["documentation"] = [source]
    return evidence


def build_baseline_manifest(rows: tuple[CapabilityRow, ...]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "ledger": str(LEDGER.relative_to(ROOT)),
        "assessment_source": "docs/sol_ultra_repo_assessment_completion_notes.md",
        "capabilities": {
            row.capability_id: {
                "title": row.title,
                "current_score": row.current,
                "evidence": _baseline_evidence(row),
            }
            for row in rows
        },
    }


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"evidence manifest must use schema_version {SCHEMA_VERSION}")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ValueError("evidence manifest capabilities must be an object")
    return payload


def evidence_cap(record: dict[str, Any]) -> int:
    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("capability evidence must be an object")
    present: dict[str, bool] = {}
    for key in EVIDENCE_CLASSES:
        values = evidence.get(key, [])
        if not isinstance(values, list) or not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError(f"evidence class {key} must be a list of non-empty strings")
        present[key] = bool(values)
    if not present["implementation"]:
        return 49
    if not present["local_workflow"]:
        return 74
    if not present["integration"]:
        return 84
    if not present["deployed"]:
        return 94
    final_classes = ("failure_recovery", "observability", "documentation", "regression")
    if not all(present[key] for key in final_classes):
        return 99
    return 100


def validate(rows: tuple[CapabilityRow, ...], manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    records = manifest["capabilities"]
    row_ids = {row.capability_id for row in rows}
    record_ids = set(records)
    if record_ids != row_ids:
        missing = sorted(row_ids - record_ids)
        extra = sorted(record_ids - row_ids)
        issues.append(f"manifest/ledger ID mismatch: missing={missing}, extra={extra}")
    for row in rows:
        record = records.get(row.capability_id)
        if not isinstance(record, dict):
            continue
        score = record.get("current_score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            issues.append(f"{row.capability_id}: current_score must be an integer from 0 to 100")
            continue
        if score != row.current:
            issues.append(f"{row.capability_id}: manifest score {score} differs from ledger score {row.current}")
        try:
            cap = evidence_cap(record)
        except ValueError as exc:
            issues.append(f"{row.capability_id}: {exc}")
            continue
        if score > cap:
            issues.append(f"{row.capability_id}: score {score} exceeds evidence cap {cap}")
        if score == 100 and row.status != "SUCCESS":
            issues.append(f"{row.capability_id}: score 100 requires ledger status SUCCESS")
        if row.status == "SUCCESS" and score != 100:
            issues.append(f"{row.capability_id}: SUCCESS requires score 100")
    return issues


def operational_score(rows: tuple[CapabilityRow, ...], manifest: dict[str, Any]) -> int:
    weighted_total = 0.0
    weight_total = 0.0
    for row in rows:
        weight = CATEGORY_WEIGHTS[row.category]
        score = int(manifest["capabilities"][row.capability_id]["current_score"])
        weighted_total += score * weight
        weight_total += weight
    return round(weighted_total / weight_total)


def build_doc(rows: tuple[CapabilityRow, ...], manifest: dict[str, Any]) -> str:
    score = operational_score(rows, manifest)
    complete = sum(1 for row in rows if row.current == 100 and row.status == "SUCCESS")
    lines = [
        "# Marvain Operational Completion Status",
        "",
        "This status is computed from the 85-row execution ledger and machine-readable evidence manifest. It is separate from the repository evidence-presence score.",
        "",
        f"Operational score: **{score}%**.",
        f"Capabilities at 100/SUCCESS: **{complete}/85**.",
        "",
        "## Category Summary",
        "",
        "| Category | Score | Capabilities at 100 | Total |",
        "|---|---:|---:|---:|",
    ]
    for category in CATEGORY_WEIGHTS:
        category_rows = [row for row in rows if row.category == category]
        category_score = round(
            sum(int(manifest["capabilities"][row.capability_id]["current_score"]) for row in category_rows)
            / len(category_rows)
        )
        category_complete = sum(1 for row in category_rows if row.current == 100 and row.status == "SUCCESS")
        lines.append(f"| `{category}` | {category_score}% | {category_complete} | {len(category_rows)} |")
    lines.extend(
        [
            "",
            "## Capability Evidence",
            "",
            "| ID | Capability | Score | Evidence cap | Status | Owner | Gate |",
            "|---|---|---:|---:|---|---|---:|",
        ]
    )
    for row in rows:
        record = manifest["capabilities"][row.capability_id]
        lines.append(
            f"| `{row.capability_id}` | {row.title} | {record['current_score']}% | "
            f"{evidence_cap(record)}% | `{row.status}` | `{row.owner}` | {row.gate} |"
        )
    lines.extend(
        [
            "",
            "## Gates",
            "",
            "- Operating well requires score >=85, every core V1 capability >=85, no P0/P1 findings, and fresh clean-room proof.",
            "- 100% requires every capability at 100/SUCCESS and all final evidence classes.",
            "- Test fixtures and source-token presence cannot satisfy deployed evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Marvain operational completion status")
    parser.add_argument("--bootstrap", action="store_true", help="Create the baseline evidence manifest")
    parser.add_argument("--check", action="store_true", help="Fail if generated status is stale")
    parser.add_argument("--require-score", type=int, default=0)
    parser.add_argument("--require-all-100", action="store_true")
    args = parser.parse_args()

    rows = parse_capability_ledger()
    if args.bootstrap:
        if MANIFEST.exists():
            print(f"Refusing to overwrite existing evidence manifest: {MANIFEST}", file=sys.stderr)
            return 2
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(build_baseline_manifest(rows), indent=2) + "\n", encoding="utf-8")

    if not MANIFEST.exists():
        print(f"Evidence manifest does not exist: {MANIFEST}. Run with --bootstrap.", file=sys.stderr)
        return 2
    manifest = load_manifest()
    issues = validate(rows, manifest)
    if issues:
        print("Operational evidence validation failed:", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1

    doc = build_doc(rows, manifest)
    score = operational_score(rows, manifest)
    if args.check:
        if not OUT_FILE.exists() or OUT_FILE.read_text(encoding="utf-8") != doc:
            print(f"Operational completion status is stale: {OUT_FILE}", file=sys.stderr)
            return 1
    else:
        OUT_FILE.write_text(doc, encoding="utf-8")

    if score < args.require_score:
        print(f"Operational score {score}% is below required {args.require_score}%", file=sys.stderr)
        return 1
    if args.require_all_100 and any(row.current != 100 or row.status != "SUCCESS" for row in rows):
        print("Not all 85 capability rows are at 100/SUCCESS", file=sys.stderr)
        return 1
    print(f"Operational completion status is current; score {score}%, 85 capabilities tracked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
