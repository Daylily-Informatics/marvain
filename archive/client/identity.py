"""Minimal local identity registry helpers for debug tooling.

The debug utilities under ``bin/`` expect a module that can list and delete
voice/face entries. The implementation here stores a tiny registry in a local
JSON file so that the scripts (and GUI debug panel) have something to query.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, MutableMapping


REGISTRY_PATH = Path(os.environ.get("IDENTITY_REGISTRY_PATH", "identity_registry.json"))


def _empty_registry() -> Dict[str, list]:
    return {"voices": [], "faces": []}


def _load_registry() -> MutableMapping[str, list]:
    if not REGISTRY_PATH.exists():
        return _empty_registry()
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _empty_registry()
    if not isinstance(data, dict):
        return _empty_registry()
    data.setdefault("voices", [])
    data.setdefault("faces", [])
    return data  # type: ignore[return-value]


def _save_registry(reg: MutableMapping[str, list]) -> None:
    REGISTRY_PATH.write_text(json.dumps(reg, indent=2, sort_keys=True), encoding="utf-8")


def _names(entries: Iterable[MutableMapping[str, str]]) -> List[str]:
    return sorted({(entry.get("name") or "").strip() for entry in entries if entry.get("name")})


def list_voice_names() -> List[str]:
    return _names(_load_registry().get("voices", []))


def list_face_names() -> List[str]:
    return _names(_load_registry().get("faces", []))


def delete_voice(name: str) -> bool:
    return _delete_entry("voices", name)


def delete_face(name: str) -> bool:
    return _delete_entry("faces", name)


def _delete_entry(kind: str, name: str) -> bool:
    reg = _load_registry()
    entries = reg.get(kind, [])
    lowered = name.lower().strip()
    kept = [e for e in entries if (e.get("name") or "").lower().strip() != lowered]
    changed = len(kept) != len(entries)
    if changed:
        reg[kind] = kept
        _save_registry(reg)
    return changed


def reset_registry() -> None:
    _save_registry(_empty_registry())


def registry_details() -> Dict[str, list]:
    """Return the raw registry contents for debug display."""
    reg = _load_registry()
    reg.setdefault("voices", [])
    reg.setdefault("faces", [])
    return reg  # type: ignore[return-value]
