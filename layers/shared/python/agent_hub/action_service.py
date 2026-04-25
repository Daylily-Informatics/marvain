from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from agent_hub.audit import append_audit_entry
from agent_hub.auto_approve_policy import evaluate_auto_approve
from agent_hub.contracts import validate_tool_payload
from agent_hub.permission_service import normalize_scopes
from agent_hub.rds_data import RdsData
from agent_hub.tools.registry import get_registry

logger = logging.getLogger(__name__)


class ActionServiceError(RuntimeError):
    def __init__(self, code: str, *, message: str | None = None, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.extra = extra or {}


@dataclass(frozen=True)
class ActionDecision:
    status: str
    approval_source: str | None
    approval_policy_id: str | None
    policy_decision_kind: str
    policy_decision_reason: str
    approval_reason: str


def _json_loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, type(fallback)):
        return value
    try:
        parsed = json.loads(value)
    except Exception:
        return fallback
    return parsed if isinstance(parsed, type(fallback)) else fallback


def _record_policy_decision(*, db: RdsData, action_id: str, policy_id: str | None, decision: str, reason: str) -> None:
    try:
        db.execute(
            """
            INSERT INTO action_policy_decisions(action_id, policy_id, decision, reason)
            VALUES(
              :action_id::uuid,
              CASE WHEN :policy_id IS NULL OR :policy_id = '' THEN NULL ELSE :policy_id::uuid END,
              :decision,
              :reason
            )
            """,
            {
                "action_id": action_id,
                "policy_id": policy_id,
                "decision": decision,
                "reason": reason[:500],
            },
        )
    except Exception as exc:
        logger.warning("Failed to record policy decision for %s: %s", action_id, exc)


def _append_action_audit(
    db: RdsData,
    *,
    audit_bucket: str | None,
    agent_id: str,
    entry_type: str,
    entry: dict[str, Any],
) -> None:
    bucket_name = str(audit_bucket or "").strip() if isinstance(audit_bucket, str) else ""
    if not bucket_name:
        return
    append_audit_entry(
        db,
        bucket=bucket_name,
        agent_id=agent_id,
        entry_type=entry_type,
        entry=entry,
    )


def _normalize_requested_approval_mode(requested_approval_mode: str | None, manual_auto_approve: bool | None) -> str:
    mode = str(requested_approval_mode or "").strip().lower()
    if mode in {"manual_immediate", "policy_only"}:
        return mode
    if manual_auto_approve:
        return "manual_immediate"
    return "policy_only"


def _require_known_tool(kind: str) -> None:
    tool = get_registry().get(kind)
    if tool is None:
        raise ActionServiceError("unknown_action_kind", message=f"unknown_action_kind: {kind}")


def _registry_required_scopes(kind: str) -> list[str]:
    try:
        registry = get_registry()
    except Exception as exc:  # pragma: no cover - defensive against registry bootstrap failures
        logger.warning("Tool registry unavailable for %s: %s", kind, exc)
        return []

    try:
        tool = registry.get(kind)
    except Exception as exc:  # pragma: no cover - defensive against registry lookup failures
        logger.warning("Tool registry lookup failed for %s: %s", kind, exc)
        return []

    if tool is None:
        return []
    return normalize_scopes(getattr(tool, "required_scopes", []) or [])


def prepare_action_request(
    *, kind: str, payload: dict[str, Any], required_scopes: list[str] | None
) -> tuple[dict[str, Any], list[str]]:
    kind_n = str(kind or "").strip()
    if not kind_n:
        raise ActionServiceError("missing_action_kind")
    _require_known_tool(kind_n)
    try:
        normalized_payload = validate_tool_payload(kind_n, payload or {})
    except Exception as exc:  # pragma: no cover - routed through callers in tests
        raise ActionServiceError("invalid_payload", message=str(exc)) from exc
    requested_scopes = normalize_scopes(required_scopes)
    merged_scopes = normalize_scopes([*requested_scopes, *_registry_required_scopes(kind_n)])
    return normalized_payload, merged_scopes


def _determine_initial_decision(
    db: RdsData,
    *,
    agent_id: str,
    kind: str,
    required_scopes: list[str],
    requested_approval_mode: str,
    policy_mode: str,
) -> ActionDecision:
    policy = evaluate_auto_approve(
        db,
        agent_id=agent_id,
        action_kind=kind,
        action_required_scopes=required_scopes,
    )
    if policy.matched and policy_mode == "enforce":
        return ActionDecision(
            status="approved",
            approval_source="policy",
            approval_policy_id=policy.policy_id,
            policy_decision_kind="policy_auto_approved",
            policy_decision_reason=policy.reason,
            approval_reason=policy.reason,
        )
    if requested_approval_mode == "manual_immediate":
        return ActionDecision(
            status="approved",
            approval_source="manual",
            approval_policy_id=None,
            policy_decision_kind="no_match" if not policy.matched else "policy_matched_manual_override",
            policy_decision_reason=policy.reason if policy.matched else "no_policy_match",
            approval_reason="requested_approval_mode=manual_immediate",
        )
    return ActionDecision(
        status="proposed",
        approval_source=None,
        approval_policy_id=None,
        policy_decision_kind="no_match" if not policy.matched else "policy_matched_not_enforced",
        policy_decision_reason=policy.reason if policy.matched else "no_policy_match",
        approval_reason="manual_approval_required",
    )


def load_action(db: RdsData, action_id: str) -> dict[str, Any] | None:
    rows = db.query(
        """
        SELECT action_id::TEXT as action_id,
               agent_id::TEXT as agent_id,
               space_id::TEXT as space_id,
               kind,
               payload::TEXT as payload_json,
               required_scopes::TEXT as required_scopes_json,
               status,
               target_device_id::TEXT as target_device_id,
               correlation_id::TEXT as correlation_id,
               approved_by::TEXT as approved_by,
               approved_at::TEXT as approved_at,
               approval_source,
               approval_policy_id::TEXT as approval_policy_id,
               request_idempotency_key,
               request_actor_type,
               request_actor_id,
               request_origin,
               result::TEXT as result_json,
               error,
               execution_metadata::TEXT as execution_metadata_json,
               COALESCE(EXTRACT(EPOCH FROM (now() - created_at)) * 1000, 0) as age_ms
        FROM actions
        WHERE action_id = :action_id::uuid
        LIMIT 1
        """,
        {"action_id": action_id},
    )
    if not rows:
        return None
    row = rows[0]
    row["payload"] = _json_loads(row.get("payload_json"), {})
    row["required_scopes"] = _json_loads(row.get("required_scopes_json"), [])
    row["result"] = _json_loads(row.get("result_json"), {})
    row["execution_metadata"] = _json_loads(row.get("execution_metadata_json"), {})
    return row


def _load_existing_idempotent_action(
    db: RdsData,
    *,
    agent_id: str,
    idempotency_key: str | None,
    request_actor_type: str | None,
    request_actor_id: str | None,
) -> dict[str, Any] | None:
    key = str(idempotency_key or "").strip()
    actor_type = str(request_actor_type or "").strip()
    actor_id = str(request_actor_id or "").strip()
    if not key or not actor_type or not actor_id:
        return None

    rows = db.query(
        """
        SELECT action_id::TEXT as action_id
        FROM actions
        WHERE agent_id = :agent_id::uuid
          AND request_idempotency_key = :request_idempotency_key
          AND request_actor_type = :request_actor_type
          AND request_actor_id = :request_actor_id
        ORDER BY created_at DESC
        LIMIT 1
        """,
        {
            "agent_id": agent_id,
            "request_idempotency_key": key,
            "request_actor_type": actor_type,
            "request_actor_id": actor_id,
        },
    )
    if not rows:
        return None
    return load_action(db, str(rows[0]["action_id"]))


def create_action(
    db: RdsData,
    *,
    agent_id: str,
    space_id: str | None,
    kind: str,
    payload: dict[str, Any],
    required_scopes: list[str] | None = None,
    requested_approval_mode: str | None = None,
    manual_auto_approve: bool | None = None,
    approved_by_user_id: str | None = None,
    idempotency_key: str | None = None,
    request_actor_type: str | None = None,
    request_actor_id: str | None = None,
    request_origin: str = "",
    policy_mode: str = "enforce",
    audit_bucket: str | None = None,
    sqs_client: Any | None = None,
    action_queue_url: str | None = None,
) -> dict[str, Any]:
    normalized_payload, normalized_required_scopes = prepare_action_request(
        kind=kind,
        payload=payload,
        required_scopes=required_scopes,
    )
    approval_mode = _normalize_requested_approval_mode(requested_approval_mode, manual_auto_approve)
    existing = _load_existing_idempotent_action(
        db,
        agent_id=agent_id,
        idempotency_key=idempotency_key,
        request_actor_type=request_actor_type,
        request_actor_id=request_actor_id,
    )
    if existing:
        return existing
    decision = _determine_initial_decision(
        db,
        agent_id=agent_id,
        kind=str(kind),
        required_scopes=normalized_required_scopes,
        requested_approval_mode=approval_mode,
        policy_mode=str(policy_mode or "enforce").strip().lower(),
    )
    action_id = str(uuid.uuid4())

    try:
        db.execute(
            """
            INSERT INTO actions(
              action_id, agent_id, space_id, kind, payload, required_scopes, status,
              approval_source, approval_policy_id, approved_by, approved_at,
              request_idempotency_key, request_actor_type, request_actor_id, request_origin
            )
            VALUES(
              :action_id::uuid,
              :agent_id::uuid,
              CASE WHEN :space_id IS NULL OR :space_id = '' THEN NULL ELSE :space_id::uuid END,
              :kind,
              :payload::jsonb,
              :required_scopes::jsonb,
              :status,
              :approval_source,
              CASE WHEN :approval_policy_id IS NULL OR :approval_policy_id = '' THEN NULL ELSE :approval_policy_id::uuid END,
              CASE
                WHEN :approved_by_user_id IS NULL OR :status <> 'approved'
                THEN NULL
                ELSE :approved_by_user_id::uuid
              END,
              CASE WHEN :status = 'approved' THEN now() ELSE NULL END,
              CASE WHEN :request_idempotency_key = '' THEN NULL ELSE :request_idempotency_key END,
              CASE WHEN :request_actor_type = '' THEN NULL ELSE :request_actor_type END,
              CASE WHEN :request_actor_id = '' THEN NULL ELSE :request_actor_id END,
              CASE WHEN :request_origin = '' THEN NULL ELSE :request_origin END
            )
            """,
            {
                "action_id": action_id,
                "agent_id": agent_id,
                "space_id": space_id,
                "kind": kind,
                "payload": json.dumps(normalized_payload),
                "required_scopes": json.dumps(normalized_required_scopes),
                "status": decision.status,
                "approval_source": decision.approval_source,
                "approval_policy_id": decision.approval_policy_id,
                "approved_by_user_id": approved_by_user_id,
                "request_idempotency_key": str(idempotency_key or "").strip(),
                "request_actor_type": str(request_actor_type or "").strip(),
                "request_actor_id": str(request_actor_id or "").strip(),
                "request_origin": str(request_origin or "").strip(),
            },
        )
    except Exception:
        existing = _load_existing_idempotent_action(
            db,
            agent_id=agent_id,
            idempotency_key=idempotency_key,
            request_actor_type=request_actor_type,
            request_actor_id=request_actor_id,
        )
        if existing:
            return existing
        raise

    _record_policy_decision(
        db=db,
        action_id=action_id,
        policy_id=decision.approval_policy_id,
        decision=decision.policy_decision_kind,
        reason=decision.policy_decision_reason,
    )
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=agent_id,
        entry_type="action_created",
        entry={
            "action_id": action_id,
            "space_id": space_id,
            "kind": kind,
            "status": decision.status,
            "approval_source": decision.approval_source,
            "required_scopes": normalized_required_scopes,
            "approved_by_user_id": approved_by_user_id,
        },
    )
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=agent_id,
        entry_type="action_policy_evaluated",
        entry={
            "action_id": action_id,
            "kind": kind,
            "decision": decision.policy_decision_kind,
            "reason": decision.policy_decision_reason,
            "approval_source": decision.approval_source,
            "approval_policy_id": decision.approval_policy_id,
        },
    )
    if decision.status == "approved":
        _append_action_audit(
            db,
            audit_bucket=audit_bucket,
            agent_id=agent_id,
            entry_type="action_decision",
            entry={
                "action_id": action_id,
                "decision": "approved",
                "by_user_id": approved_by_user_id,
                "approval_source": decision.approval_source,
                "reason": decision.approval_reason,
            },
        )
        if action_queue_url and sqs_client is not None:
            sqs_client.send_message(
                QueueUrl=action_queue_url,
                MessageBody=json.dumps({"action_id": action_id, "agent_id": agent_id}),
            )

    return {
        "action_id": action_id,
        "agent_id": agent_id,
        "space_id": space_id,
        "kind": str(kind),
        "payload": normalized_payload,
        "required_scopes": normalized_required_scopes,
        "status": decision.status,
        "approval_source": decision.approval_source,
        "approval_policy_id": decision.approval_policy_id,
        "request_idempotency_key": str(idempotency_key or "").strip() or None,
        "request_actor_type": str(request_actor_type or "").strip() or None,
        "request_actor_id": str(request_actor_id or "").strip() or None,
        "request_origin": str(request_origin or "").strip() or None,
    }


def approve_action(
    db: RdsData,
    *,
    action_id: str,
    user_id: str,
    audit_bucket: str | None = None,
    sqs_client: Any | None = None,
    action_queue_url: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    rows = db.query(
        """
        UPDATE actions
        SET status = 'approved',
            updated_at = now(),
            approved_by = :user_id::uuid,
            approved_at = now(),
            approval_source = COALESCE(approval_source, 'manual')
        WHERE action_id = :action_id::uuid
          AND status = 'proposed'
        RETURNING agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  payload::TEXT as payload_json,
                  required_scopes::TEXT as required_scopes_json
        """,
        {"action_id": action_id, "user_id": user_id},
    )
    if not rows:
        action = load_action(db, action_id)
        if not action:
            raise ActionServiceError("action_not_found")
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    action = rows[0]
    action["payload"] = _json_loads(action.get("payload_json"), {})
    action["required_scopes"] = _json_loads(action.get("required_scopes_json"), [])
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_decision",
        entry={
            "action_id": action_id,
            "decision": "approved",
            "by_user_id": user_id,
            "reason": reason,
        },
    )
    if action_queue_url and sqs_client is not None:
        sqs_client.send_message(
            QueueUrl=action_queue_url,
            MessageBody=json.dumps({"action_id": action_id, "agent_id": action["agent_id"]}),
        )
    action["status"] = "approved"
    action["approved_by"] = user_id
    return action


def reject_action(
    db: RdsData,
    *,
    action_id: str,
    user_id: str,
    reason: str = "",
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    rows = db.query(
        """
        UPDATE actions
        SET status = 'rejected',
            updated_at = now()
        WHERE action_id = :action_id::uuid
          AND status = 'proposed'
        RETURNING agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  payload::TEXT as payload_json,
                  required_scopes::TEXT as required_scopes_json
        """,
        {"action_id": action_id},
    )
    if not rows:
        action = load_action(db, action_id)
        if not action:
            raise ActionServiceError("action_not_found")
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    action = rows[0]
    action["payload"] = _json_loads(action.get("payload_json"), {})
    action["required_scopes"] = _json_loads(action.get("required_scopes_json"), [])
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_decision",
        entry={
            "action_id": action_id,
            "decision": "rejected",
            "by_user_id": user_id,
            "reason": reason,
        },
    )
    action["status"] = "rejected"
    return action


def reserve_action_for_execution(db: RdsData, action_id: str) -> dict[str, Any] | None:
    rows = db.query(
        """
        UPDATE actions
        SET status = 'executing',
            updated_at = now()
        WHERE action_id = :action_id::uuid
          AND status = 'approved'
        RETURNING action_id::TEXT as action_id,
                  agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  payload::TEXT as payload_json,
                  required_scopes::TEXT as required_scopes_json,
                  status
        """,
        {"action_id": action_id},
    )
    if not rows:
        return None
    row = rows[0]
    row["payload"] = _json_loads(row.get("payload_json"), {})
    row["required_scopes"] = _json_loads(row.get("required_scopes_json"), [])
    return row


def record_action_dispatch_started(
    db: RdsData,
    *,
    action_id: str,
    audit_bucket: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    action = load_action(db, action_id)
    if not action:
        raise ActionServiceError("action_not_found")
    if str(action.get("status") or "") != "executing":
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_dispatch_started",
        entry={
            "action_id": action_id,
            "kind": action.get("kind"),
            **(details or {}),
        },
    )
    return action


def begin_device_dispatch(
    db: RdsData,
    *,
    action_id: str,
    target_device_id: str | None,
    correlation_id: str | None,
    timeout_seconds: int,
    execution_metadata: dict[str, Any],
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    rows = db.query(
        """
        UPDATE actions
        SET status = 'awaiting_device_result',
            updated_at = now(),
            target_device_id = CASE
              WHEN :target_device_id IS NULL OR :target_device_id = ''
              THEN NULL
              ELSE :target_device_id::uuid
            END,
            correlation_id = CASE
              WHEN :correlation_id IS NULL OR :correlation_id = ''
              THEN NULL
              ELSE :correlation_id::uuid
            END,
            awaiting_result_until = now() + (:timeout_seconds || ' seconds')::interval,
            execution_metadata = COALESCE(execution_metadata, '{}'::jsonb) || :execution_metadata::jsonb,
            result = NULL,
            error = NULL
        WHERE action_id = :action_id::uuid
          AND status = 'executing'
        RETURNING action_id::TEXT as action_id,
                  agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  target_device_id::TEXT as target_device_id,
                  correlation_id::TEXT as correlation_id,
                  execution_metadata::TEXT as execution_metadata_json
        """,
        {
            "action_id": action_id,
            "target_device_id": target_device_id,
            "correlation_id": correlation_id,
            "timeout_seconds": timeout_seconds,
            "execution_metadata": json.dumps(execution_metadata),
        },
    )
    if not rows:
        action = load_action(db, action_id)
        if not action:
            raise ActionServiceError("action_not_found")
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    row = rows[0]
    row["execution_metadata"] = _json_loads(row.get("execution_metadata_json"), {})
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(row["agent_id"]),
        entry_type="action_dispatch_started",
        entry={
            "action_id": action_id,
            "kind": row.get("kind"),
            "target_device_id": target_device_id,
            "correlation_id": correlation_id,
            "timeout_seconds": timeout_seconds,
        },
    )
    return row


def mark_action_awaiting_device_result(
    db: RdsData,
    *,
    action_id: str,
    target_device_id: str | None,
    correlation_id: str | None,
    timeout_seconds: int,
    execution_metadata: dict[str, Any],
) -> None:
    begin_device_dispatch(
        db,
        action_id=action_id,
        target_device_id=target_device_id,
        correlation_id=correlation_id,
        timeout_seconds=timeout_seconds,
        execution_metadata=execution_metadata,
        audit_bucket=None,
    )


def mark_action_dispatch_failed(
    db: RdsData,
    *,
    action_id: str,
    error: str,
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    rows = db.query(
        """
        UPDATE actions
        SET status = 'failed',
            updated_at = now(),
            executed_at = now(),
            completed_at = now(),
            device_response_at = now(),
            awaiting_result_until = NULL,
            error = :error
        WHERE action_id = :action_id::uuid
          AND status = 'awaiting_device_result'
        RETURNING action_id::TEXT as action_id,
                  agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  error
        """,
        {"action_id": action_id, "error": error},
    )
    if not rows:
        action = load_action(db, action_id)
        if not action:
            raise ActionServiceError("action_not_found")
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    row = rows[0]
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(row["agent_id"]),
        entry_type="action_executed",
        entry={
            "action_id": action_id,
            "kind": row.get("kind"),
            "status": "failed",
            "error": error,
        },
    )
    return row


def mark_action_completed(
    db: RdsData,
    *,
    action_id: str,
    ok: bool,
    result: dict[str, Any] | None,
    error: str | None,
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    action = load_action(db, action_id)
    if not action:
        raise ActionServiceError("action_not_found")

    new_status = "executed" if ok else "failed"
    db.execute(
        """
        UPDATE actions
        SET status = :status,
            updated_at = now(),
            executed_at = now(),
            completed_at = now(),
            result = :result::jsonb,
            error = :error
        WHERE action_id = :action_id::uuid
        """,
        {
            "action_id": action_id,
            "status": new_status,
            "result": json.dumps(result or {}) if ok else None,
            "error": error if not ok else None,
        },
    )
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_executed",
        entry={
            "action_id": action_id,
            "kind": action.get("kind"),
            "status": new_status,
            "error": error if not ok else None,
        },
    )
    action["status"] = new_status
    action["error"] = error if not ok else None
    return action


def _load_action_for_device_result(db: RdsData, action_id: str) -> dict[str, Any]:
    action = load_action(db, action_id)
    if not action:
        raise ActionServiceError("action_not_found")
    if str(action.get("status") or "") not in (
        "awaiting_device_result",
        "device_acknowledged",
        "executed",
        "failed",
        "device_timeout",
    ):
        raise ActionServiceError("invalid_status", extra={"current_status": action.get("status")})
    return action


def record_device_ack(
    db: RdsData,
    *,
    action_id: str,
    device_id: str,
    correlation_id: str,
    received_at_ms: int | None,
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    action = _load_action_for_device_result(db, action_id)
    target_device_id = str(action.get("target_device_id") or "")
    if target_device_id and target_device_id != device_id:
        raise ActionServiceError("permission_denied")
    action_correlation_id = str(action.get("correlation_id") or "")
    if action_correlation_id and action_correlation_id != correlation_id:
        raise ActionServiceError("correlation_mismatch")
    current_status = str(action.get("status") or "")
    if current_status in {"device_acknowledged", "executed", "failed", "device_timeout"}:
        action["duplicate"] = True
        return action

    rows = db.query(
        """
        UPDATE actions
        SET status = 'device_acknowledged',
            updated_at = now(),
            device_acknowledged_at = now(),
            execution_metadata = COALESCE(execution_metadata, '{}'::jsonb) || :meta::jsonb
        WHERE action_id = :action_id::uuid
          AND status = 'awaiting_device_result'
        RETURNING agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  payload::TEXT as payload_json,
                  required_scopes::TEXT as required_scopes_json
        """,
        {
            "action_id": action_id,
            "meta": json.dumps(
                {
                    "acknowledged_by_device_id": device_id,
                    "acknowledged_at_ms": received_at_ms,
                }
            ),
        },
    )
    if not rows:
        refreshed = _load_action_for_device_result(db, action_id)
        refreshed_status = str(refreshed.get("status") or "")
        if refreshed_status in {"device_acknowledged", "executed", "failed", "device_timeout"}:
            refreshed["duplicate"] = True
            return refreshed
        raise ActionServiceError("invalid_status", extra={"current_status": refreshed_status})
    action = rows[0]
    action["payload"] = _json_loads(action.get("payload_json"), {})
    action["required_scopes"] = _json_loads(action.get("required_scopes_json"), [])
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_device_ack",
        entry={
            "action_id": action_id,
            "device_id": device_id,
            "correlation_id": correlation_id,
            "received_at_ms": received_at_ms,
        },
    )
    action["status"] = "device_acknowledged"
    return action


def record_device_result(
    db: RdsData,
    *,
    action_id: str,
    device_id: str,
    correlation_id: str,
    result_status: str,
    result_payload: dict[str, Any] | None,
    error_text: str | None,
    completed_at_ms: int | None,
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    action = _load_action_for_device_result(db, action_id)
    target_device_id = str(action.get("target_device_id") or "")
    if target_device_id and target_device_id != device_id:
        raise ActionServiceError("permission_denied")
    action_correlation_id = str(action.get("correlation_id") or "")
    if action_correlation_id and action_correlation_id != correlation_id:
        raise ActionServiceError("correlation_mismatch")
    current_status = str(action.get("status") or "")
    if current_status in {"executed", "failed", "device_timeout"}:
        action["duplicate"] = True
        return action

    new_status = "executed" if result_status == "success" else "failed"
    err_text = None if result_status == "success" else (error_text or f"device_{result_status}")
    rows = db.query(
        """
        UPDATE actions
        SET status = :status,
            updated_at = now(),
            executed_at = now(),
            completed_at = now(),
            device_response_at = now(),
            awaiting_result_until = NULL,
            result = :result::jsonb,
            error = :error
        WHERE action_id = :action_id::uuid
          AND status IN ('awaiting_device_result', 'device_acknowledged')
        RETURNING agent_id::TEXT as agent_id,
                  space_id::TEXT as space_id,
                  kind,
                  status,
                  error,
                  COALESCE(EXTRACT(EPOCH FROM (now() - created_at)) * 1000, 0) as age_ms
        """,
        {
            "action_id": action_id,
            "status": new_status,
            "result": json.dumps(result_payload or {}),
            "error": err_text,
        },
    )
    if not rows:
        refreshed = _load_action_for_device_result(db, action_id)
        refreshed_status = str(refreshed.get("status") or "")
        if refreshed_status in {"executed", "failed", "device_timeout"}:
            refreshed["duplicate"] = True
            return refreshed
        raise ActionServiceError("invalid_status", extra={"current_status": refreshed_status})
    action = rows[0]
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_executed",
        entry={
            "action_id": action_id,
            "kind": action.get("kind"),
            "status": new_status,
            "device_id": device_id,
            "correlation_id": correlation_id,
            "completed_at_ms": completed_at_ms,
            "error": err_text,
        },
    )
    action["status"] = new_status
    action["error"] = err_text
    return action


def mark_action_timed_out(
    db: RdsData,
    *,
    action_id: str,
    audit_bucket: str | None = None,
) -> dict[str, Any]:
    action = load_action(db, action_id)
    if not action:
        raise ActionServiceError("action_not_found")
    db.execute(
        """
        UPDATE actions
        SET status = 'device_timeout',
            updated_at = now(),
            completed_at = now(),
            device_response_at = now(),
            error = :error
        WHERE action_id = :action_id::uuid
        """,
        {
            "action_id": action_id,
            "error": "device_timeout",
        },
    )
    _append_action_audit(
        db,
        audit_bucket=audit_bucket,
        agent_id=str(action["agent_id"]),
        entry_type="action_timeout",
        entry={
            "action_id": action_id,
            "kind": action.get("kind"),
            "status": "device_timeout",
        },
    )
    action["status"] = "device_timeout"
    action["error"] = "device_timeout"
    return action
