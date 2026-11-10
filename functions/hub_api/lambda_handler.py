"""Lambda entrypoint for the shared Hub API and server-rendered GUI."""

from __future__ import annotations

import os
from typing import Any

from agent_hub.semantic_tapdb import write_hosted_tapdb_runtime_config
from mangum import Mangum

write_hosted_tapdb_runtime_config()

from app import app

_stage = os.environ.get("STAGE", "").strip().strip("/")
if not _stage:
    raise RuntimeError("STAGE is required for the hosted Hub")
_root_path = f"/{_stage}"


async def _stage_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    if scope["type"] in {"http", "websocket"}:
        path = scope["path"]
        raw_path = scope.get("raw_path")
        scope = {**scope, "root_path": _root_path, "path": _root_path + path}
        if raw_path is not None:
            scope["raw_path"] = _root_path.encode("utf-8") + raw_path
    await app(scope, receive, send)


_adapter = Mangum(
    _stage_app, lifespan="off",
    text_mime_types=["text/", "application/json", "application/javascript", "application/xml",
                     "application/vnd.api+json", "application/vnd.oai.openapi", "image/svg+xml"],
)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    path = event.get("path")
    if isinstance(path, str) and (path == _root_path or path.startswith(f"{_root_path}/")):
        event = {**event, "path": path[len(_root_path):] or "/"}
    return _adapter(event, context)
