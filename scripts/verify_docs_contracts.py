#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "layers/shared/python"))

from agent_hub.contracts import validate_tool_payload

GUIDE = Path("functions/hub_api/templates/actions_guide.html")


PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"


def _normalize_placeholders(raw: str) -> str:
    text = raw.replace("<space-uuid>", PLACEHOLDER_UUID)
    text = text.replace("<device-uuid>", PLACEHOLDER_UUID)
    return text


def main() -> int:
    src = GUIDE.read_text(encoding="utf-8")

    pattern = re.compile(r"<h4[^>]*><code>([^<]+)</code></h4>.*?<pre[^>]*>(.*?)</pre>", re.S)
    matches = pattern.findall(src)
    if not matches:
        raise SystemExit("No action examples found in actions_guide.html")

    validated = 0
    errors: list[str] = []
    seen_kinds: set[str] = set()

    for kind, raw_pre in matches:
        action_kind = kind.strip()
        seen_kinds.add(action_kind)
        json_text = _normalize_placeholders(html.unescape(raw_pre.strip()))
        try:
            payload = json.loads(json_text)
        except Exception as exc:
            errors.append(f"{action_kind}: invalid JSON example ({exc})")
            continue

        try:
            validate_tool_payload(action_kind, payload)
            validated += 1
        except Exception as exc:
            errors.append(f"{action_kind}: {exc}")

    required_kinds = {"send_message", "create_memory", "http_request", "device_command", "shell_command"}
    missing = sorted(required_kinds - seen_kinds)
    if missing:
        errors.append(f"Missing examples for kinds: {', '.join(missing)}")

    if errors:
        for line in errors:
            print(f"ERROR: {line}")
        return 1

    print(f"OK: validated {validated} action examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
