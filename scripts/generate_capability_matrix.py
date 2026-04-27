#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT_FILE = ROOT / "docs" / "CAPABILITY_MATRIX.generated.md"

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
SQL_TABLE_RE = re.compile(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][\w.]*)", re.IGNORECASE)


@dataclass(frozen=True)
class SourceItem:
    label: str
    source: str
    search_text: str


@dataclass(frozen=True)
class CapabilityRule:
    name: str
    keywords: tuple[str, ...]
    exposure_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityRow:
    name: str
    route_hits: tuple[SourceItem, ...]
    template_hits: tuple[SourceItem, ...]
    cli_hits: tuple[SourceItem, ...]
    tool_hits: tuple[SourceItem, ...]
    worker_hits: tuple[SourceItem, ...]
    sql_hits: tuple[SourceItem, ...]
    tapdb_hits: tuple[SourceItem, ...]
    has_route_template_exposure: bool


CAPABILITY_RULES: tuple[CapabilityRule, ...] = (
    CapabilityRule("agents", ("agent", "agents")),
    CapabilityRule("people", ("person", "people", "account")),
    CapabilityRule("locations", ("location", "locations"), ("/locations", "locations.html")),
    CapabilityRule("spaces", ("space", "spaces", "room")),
    CapabilityRule("sessions", ("session", "sessions"), ("/sessions", "sessions.html")),
    CapabilityRule(
        "recognition",
        ("recognition", "identify", "voiceprint", "faceprint", "biometric"),
        ("/recognition", "recognition.html"),
    ),
    CapabilityRule("memory", ("memory", "memories", "recall")),
    CapabilityRule("actions", ("action", "actions", "approval", "execution")),
    CapabilityRule("lineage", ("lineage", "semantic", "tapdb_euid"), ("/tapdb/graph", "/api/dag", "tapdb")),
    CapabilityRule(
        "observability",
        ("observability", "monitor", "metrics", "dashboard", "audit"),
        ("/observability", "observability.html"),
    ),
    CapabilityRule(
        "live-session/capabilities",
        ("live-session", "live_session", "livekit", "capability", "capabilities"),
        ("/live-session", "live_session.html", "capabilities.html"),
    ),
    CapabilityRule("artifacts", ("artifact", "artifacts", "presign")),
    CapabilityRule("integrations", ("integration", "github", "gmail", "slack", "twilio")),
    CapabilityRule("policy/consent", ("policy", "consent", "auto-approve", "privacy")),
    CapabilityRule("persona", ("persona", "personas"), ("/personas", "personas.html")),
)

MAJOR_CAPABILITY_PAGES = {
    "locations",
    "sessions",
    "recognition",
    "lineage",
    "observability",
    "live-session/capabilities",
    "persona",
}


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def _read_ast(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _call_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return ""


def _source(path: Path, node: ast.AST) -> str:
    return f"{_rel(path)}:{getattr(node, 'lineno', 1)}"


def _source_item(label: str, source: str, *parts: object) -> SourceItem:
    text = " ".join(str(part) for part in (label, source, *parts) if part is not None)
    return SourceItem(label=label, source=source, search_text=text.lower())


def _dedupe(items: Iterable[SourceItem]) -> tuple[SourceItem, ...]:
    seen: set[tuple[str, str]] = set()
    out: list[SourceItem] = []
    for item in items:
        key = (item.label, item.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return tuple(sorted(out, key=lambda item: (item.label, item.source)))


def collect_fastapi_routes(root: Path = ROOT) -> tuple[SourceItem, ...]:
    items: list[SourceItem] = []
    for path in (root / "functions" / "hub_api").glob("*.py"):
        tree = _read_ast(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                func = dec.func
                if not isinstance(func, ast.Attribute) or func.attr not in HTTP_METHODS:
                    continue
                if not dec.args:
                    continue
                route = _string_constant(dec.args[0])
                if route is None:
                    continue
                label = f"{func.attr.upper()} {route}"
                items.append(_source_item(label, _source(path, dec), node.name))
    return _dedupe(items)


def collect_template_inventory(root: Path = ROOT) -> tuple[SourceItem, ...]:
    items: list[SourceItem] = []
    template_dir = root / "functions" / "hub_api" / "templates"
    if template_dir.exists():
        for path in template_dir.rglob("*.html"):
            items.append(_source_item(str(path.relative_to(template_dir)), _rel(path), _read_text(path)))

    for path in (root / "functions" / "hub_api").glob("*.py"):
        tree = _read_ast(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _call_name(node.func).endswith("TemplateResponse"):
                continue
            template_name = _string_constant(node.args[0]) if node.args else None
            if template_name is None:
                for kw in node.keywords:
                    if kw.arg == "name":
                        template_name = _string_constant(kw.value)
                        break
            if template_name:
                items.append(_source_item(template_name, _source(path, node), "TemplateResponse"))
    return _dedupe(items)


def collect_cli_commands(root: Path = ROOT) -> tuple[SourceItem, ...]:
    path = root / "marvain_cli" / "commands.py"
    if not path.exists():
        return ()
    tree = _read_ast(path)
    items: list[SourceItem] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name == "register_root_command" and len(node.args) >= 2:
            command = _string_constant(node.args[1])
            handler = _call_name(node.args[2]) if len(node.args) >= 3 else ""
            if command:
                items.append(_source_item(command, _source(path, node), handler))
        if name == "register_group_commands" and len(node.args) >= 4:
            group = _string_constant(node.args[1])
            command_list = node.args[3]
            if not group or not isinstance(command_list, (ast.List, ast.Tuple)):
                continue
            for entry in command_list.elts:
                if not isinstance(entry, ast.Tuple) or not entry.elts:
                    continue
                subcommand = _string_constant(entry.elts[0])
                if subcommand:
                    handler = _call_name(entry.elts[1]) if len(entry.elts) > 1 else ""
                    items.append(_source_item(f"{group} {subcommand}", _source(path, entry), handler))
    return _dedupe(items)


def collect_tool_modules(root: Path = ROOT) -> tuple[SourceItem, ...]:
    tool_dir = root / "layers" / "shared" / "python" / "agent_hub" / "tools"
    if not tool_dir.exists():
        return ()
    items: list[SourceItem] = []
    for path in sorted(tool_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tool_names: list[str] = []
        try:
            tree = _read_ast(path)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "TOOL_NAME" for target in node.targets
                ):
                    value = _string_constant(node.value)
                    if value:
                        tool_names.append(value)
                if isinstance(node, ast.Call) and _call_name(node.func).endswith(".register") and node.args:
                    value = _string_constant(node.args[0])
                    if value:
                        tool_names.append(value)
        label = ", ".join(sorted(set(tool_names))) if tool_names else path.stem
        items.append(_source_item(label, _rel(path), path.stem))
    return _dedupe(items)


def collect_worker_directories(root: Path = ROOT) -> tuple[SourceItem, ...]:
    items: list[SourceItem] = []
    for parent in (root / "functions", root / "apps"):
        if not parent.exists():
            continue
        for path in sorted(item for item in parent.iterdir() if item.is_dir()):
            markers = [
                marker.name
                for marker in (path / "handler.py", path / "worker.py", path / "daemon.py", path / "requirements.txt")
                if marker.exists()
            ]
            if markers:
                items.append(_source_item(_rel(path), _rel(path), ", ".join(markers)))
    return _dedupe(items)


def collect_sql_tables(root: Path = ROOT) -> tuple[SourceItem, ...]:
    items: list[SourceItem] = []
    sql_paths = sorted((root / "sql").glob("*.sql"))
    for path in sql_paths:
        text = path.read_text(encoding="utf-8")
        for match in SQL_TABLE_RE.finditer(text):
            table = match.group(1).strip('"')
            line = text.count("\n", 0, match.start()) + 1
            items.append(_source_item(table, f"{_rel(path)}:{line}"))
    return _dedupe(items)


def collect_tapdb_template_codes(root: Path = ROOT) -> tuple[SourceItem, ...]:
    items: list[SourceItem] = []
    for pack in (root / "tapdb_templates" / "MVN").glob("*.json"):
        payload = json.loads(pack.read_text(encoding="utf-8"))
        for template in payload.get("templates", []):
            try:
                code = f"{template['category']}/{template['type']}/{template['subtype']}/{template['version']}/"
            except KeyError:
                continue
            name = str(template.get("name") or "")
            items.append(_source_item(code, _rel(pack), name))

    semantic_path = root / "layers" / "shared" / "python" / "agent_hub" / "semantic_tapdb.py"
    if semantic_path.exists():
        tree = _read_ast(semantic_path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "TEMPLATE_CODES" for target in node.targets):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            for key_node, value_node in zip(node.value.keys, node.value.values, strict=False):
                key = _string_constant(key_node) if key_node is not None else None
                value = _string_constant(value_node)
                if key and value:
                    items.append(_source_item(value, _source(semantic_path, node), key))
    return _dedupe(items)


def collect_inventory(root: Path = ROOT) -> dict[str, tuple[SourceItem, ...]]:
    return {
        "routes": collect_fastapi_routes(root),
        "templates": collect_template_inventory(root),
        "cli": collect_cli_commands(root),
        "tools": collect_tool_modules(root),
        "workers": collect_worker_directories(root),
        "sql": collect_sql_tables(root),
        "tapdb": collect_tapdb_template_codes(root),
    }


def _matches(item: SourceItem, tokens: Iterable[str]) -> bool:
    return any(token.lower() in item.search_text for token in tokens)


def _hits(items: tuple[SourceItem, ...], rule: CapabilityRule) -> tuple[SourceItem, ...]:
    return tuple(item for item in items if _matches(item, rule.keywords))


def _exposure_hits(items: tuple[SourceItem, ...], rule: CapabilityRule) -> tuple[SourceItem, ...]:
    tokens = rule.exposure_tokens or rule.keywords
    return tuple(item for item in items if _matches(item, tokens))


def build_matrix(root: Path = ROOT) -> tuple[CapabilityRow, ...]:
    inventory = collect_inventory(root)
    rows: list[CapabilityRow] = []
    for rule in CAPABILITY_RULES:
        route_hits = _hits(inventory["routes"], rule)
        template_hits = _hits(inventory["templates"], rule)
        exposure_routes = _exposure_hits(inventory["routes"], rule)
        exposure_templates = _exposure_hits(inventory["templates"], rule)
        rows.append(
            CapabilityRow(
                name=rule.name,
                route_hits=route_hits,
                template_hits=template_hits,
                cli_hits=_hits(inventory["cli"], rule),
                tool_hits=_hits(inventory["tools"], rule),
                worker_hits=_hits(inventory["workers"], rule),
                sql_hits=_hits(inventory["sql"], rule),
                tapdb_hits=_hits(inventory["tapdb"], rule),
                has_route_template_exposure=bool(exposure_routes or exposure_templates),
            )
        )
    return tuple(rows)


def missing_major_page_exposures(root: Path = ROOT) -> tuple[str, ...]:
    return tuple(
        row.name
        for row in build_matrix(root)
        if row.name in MAJOR_CAPABILITY_PAGES and not row.has_route_template_exposure
    )


def _format_items(items: tuple[SourceItem, ...], *, limit: int = 6) -> str:
    if not items:
        return "-"
    labels = [item.label for item in items[:limit]]
    if len(items) > limit:
        labels.append(f"+{len(items) - limit} more")
    return "<br>".join(f"`{label}`" for label in labels)


def _inventory_section(title: str, items: tuple[SourceItem, ...]) -> list[str]:
    lines = [f"## {title}", ""]
    if not items:
        lines.extend(["No items discovered.", ""])
        return lines
    for item in items:
        lines.append(f"- `{item.label}` ({item.source})")
    lines.append("")
    return lines


def build_doc(root: Path = ROOT) -> str:
    inventory = collect_inventory(root)
    rows = build_matrix(root)
    lines = [
        "# Capability Matrix (Generated)",
        "",
        "This file is generated by `scripts/generate_capability_matrix.py`.",
        "Route/template exposure uses page-level route or template tokens for V1 major capability pages.",
        "",
        "| Capability | Route/template | Routes | Templates | CLI | Tools | Workers | SQL tables | TapDB templates |",
        "|---|---:|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        status = "YES" if row.has_route_template_exposure else "NO"
        lines.append(
            "| "
            + " | ".join(
                [
                    row.name,
                    status,
                    _format_items(row.route_hits),
                    _format_items(row.template_hits),
                    _format_items(row.cli_hits),
                    _format_items(row.tool_hits),
                    _format_items(row.worker_hits),
                    _format_items(row.sql_hits),
                    _format_items(row.tapdb_hits),
                ]
            )
            + " |"
        )
    lines.append("")

    missing = missing_major_page_exposures(root)
    if missing:
        lines.append(f"Major capability page exposure gaps: {', '.join(missing)}.")
    else:
        lines.append("Major capability page exposure gaps: none.")
    lines.append("")

    lines.extend(_inventory_section("FastAPI Routes", inventory["routes"]))
    lines.extend(_inventory_section("Template Files And References", inventory["templates"]))
    lines.extend(_inventory_section("CLI Commands", inventory["cli"]))
    lines.extend(_inventory_section("Tool Modules", inventory["tools"]))
    lines.extend(_inventory_section("Worker Directories", inventory["workers"]))
    lines.extend(_inventory_section("SQL Tables", inventory["sql"]))
    lines.extend(_inventory_section("TapDB Template Codes", inventory["tapdb"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if generated output differs")
    args = parser.parse_args()

    generated = build_doc()
    if args.check:
        existing = OUT_FILE.read_text(encoding="utf-8") if OUT_FILE.exists() else ""
        if existing != generated:
            print("Capability matrix doc is out of date. Re-run generator.")
            return 1
        print("Capability matrix doc is up to date.")
        return 0

    OUT_FILE.write_text(generated, encoding="utf-8")
    print(f"Wrote {OUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
