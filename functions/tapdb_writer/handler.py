from __future__ import annotations

import json
import logging
from typing import Any

from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore, validate_marvain_template_pack

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _store() -> DaylilyTapdbSemanticStore:
    return DaylilyTapdbSemanticStore.from_environment()


def _json_body(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("body") or "{}"
    try:
        payload = json.loads(body)
    except Exception as exc:
        raise ValueError("invalid_json") from exc
    if not isinstance(payload, dict):
        raise ValueError("message body must be an object")
    return payload


def _record_semantic(payload: dict[str, Any]) -> dict[str, Any]:
    template_code = str(payload.get("template_code") or "").strip()
    name = str(payload.get("name") or "").strip()
    lifecycle_state = str(payload.get("lifecycle_state") or "created").strip()
    properties = payload.get("properties") or {}
    if not template_code:
        raise ValueError("template_code is required")
    if not name:
        raise ValueError("name is required")
    if not isinstance(properties, dict):
        raise ValueError("properties must be an object")
    obj = _store().create_object(
        template_code=template_code,
        name=name,
        properties=properties,
        lifecycle_state=lifecycle_state,
    )
    return {"ok": True, "semantic_id": obj.semantic_id, "template_code": obj.template_code}


def _link_semantic(payload: dict[str, Any]) -> dict[str, Any]:
    parent = str(payload.get("parent_semantic_id") or "").strip()
    child = str(payload.get("child_semantic_id") or "").strip()
    rel = str(payload.get("relationship_type") or "").strip()
    if not parent or not child or not rel:
        raise ValueError("parent_semantic_id, child_semantic_id, and relationship_type are required")
    edge = _store().link_objects(parent_semantic_id=parent, child_semantic_id=child, relationship_type=rel)
    return {"ok": True, "edge_id": edge.edge_id}


def _dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "record").strip()
    if action == "validate_templates":
        result = validate_marvain_template_pack()
        return {"ok": not result.issues, "templates_loaded": result.templates_loaded, "issues": result.issues}
    if action == "seed_templates":
        summary = _store().seed_templates(overwrite=bool(payload.get("overwrite", True)))
        return {
            "ok": True,
            "templates_loaded": summary.templates_loaded,
            "inserted": summary.inserted,
            "updated": summary.updated,
            "skipped": summary.skipped,
            "prefixes_ensured": summary.prefixes_ensured,
        }
    if action == "record":
        return _record_semantic(payload)
    if action == "link":
        return _link_semantic(payload)
    raise ValueError(f"unsupported action: {action}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if "Records" not in event:
        try:
            return _dispatch(event)
        except Exception as exc:
            logger.exception("TapDB writer invocation failed")
            return {"ok": False, "error": str(exc)}

    failures: list[dict[str, str]] = []
    processed = 0
    for record in event.get("Records") or []:
        message_id = str(record.get("messageId") or "")
        try:
            _dispatch(_json_body(record))
            processed += 1
        except Exception as exc:
            logger.exception("TapDB writer failed message_id=%s", message_id)
            failures.append({"itemIdentifier": message_id, "error": str(exc)})

    return {
        "ok": not failures,
        "processed": processed,
        "batchItemFailures": [{"itemIdentifier": item["itemIdentifier"]} for item in failures],
    }
