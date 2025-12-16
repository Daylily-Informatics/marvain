from __future__ import annotations

import json
from typing import Any


def json_dumps_safe(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def truncate_str(s: str, max_chars: int) -> str:
    if s is None:
        return ""
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 3] + "..."
