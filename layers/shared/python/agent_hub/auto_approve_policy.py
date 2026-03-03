from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from agent_hub.rds_data import RdsData


@dataclass
class PolicyDecision:
    matched: bool
    policy_id: str | None
    reason: str


def _json_as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(v) for v in parsed if str(v).strip()]
        except Exception:
            return []
    return []


def _json_as_dict(value: object) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _kind_match(policy_kind: str, action_kind: str) -> bool:
    policy_kind = str(policy_kind or "").strip().lower()
    action_kind = str(action_kind or "").strip().lower()
    return policy_kind in {"*", "any", action_kind}


def _required_scopes_match(policy_scopes: list[str], action_scopes: list[str]) -> bool:
    if not policy_scopes:
        return True
    return set(policy_scopes).issubset(set(action_scopes or []))


def _within_time_window(window: dict, now_utc: datetime) -> bool:
    if not window:
        return True

    tz_name = str(window.get("timezone") or "UTC")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")

    now_local = now_utc.astimezone(tz)

    days = window.get("days")
    if isinstance(days, list) and days:
        allowed = {int(d) for d in days if str(d).isdigit()}
        if now_local.weekday() not in allowed:
            return False

    start_s = str(window.get("start") or "").strip()
    end_s = str(window.get("end") or "").strip()
    if not start_s or not end_s:
        return True

    try:
        sh, sm = [int(x) for x in start_s.split(":", 1)]
        eh, em = [int(x) for x in end_s.split(":", 1)]
    except Exception:
        return True

    cur = now_local.hour * 60 + now_local.minute
    start_m = sh * 60 + sm
    end_m = eh * 60 + em

    if start_m <= end_m:
        return start_m <= cur <= end_m
    return cur >= start_m or cur <= end_m


def evaluate_auto_approve(
    db: RdsData,
    *,
    agent_id: str,
    action_kind: str,
    action_required_scopes: list[str],
    now_utc: datetime | None = None,
) -> PolicyDecision:
    now = now_utc or datetime.now(tz=UTC)
    try:
        rows = db.query(
            """
            SELECT policy_id::TEXT as policy_id,
                   action_kind,
                   required_scopes::TEXT as required_scopes,
                   time_window::TEXT as time_window
            FROM action_auto_approve_policies
            WHERE agent_id = :agent_id::uuid
              AND enabled = true
              AND revoked_at IS NULL
            ORDER BY priority ASC, created_at ASC
            """,
            {"agent_id": agent_id},
        )
    except Exception:
        return PolicyDecision(matched=False, policy_id=None, reason="policy_table_unavailable")

    for row in rows:
        if not _kind_match(str(row.get("action_kind") or ""), action_kind):
            continue

        policy_scopes = _json_as_list(row.get("required_scopes"))
        if not _required_scopes_match(policy_scopes, action_required_scopes):
            continue

        time_window = _json_as_dict(row.get("time_window"))
        if not _within_time_window(time_window, now):
            continue

        return PolicyDecision(matched=True, policy_id=str(row.get("policy_id") or ""), reason="matched")

    return PolicyDecision(matched=False, policy_id=None, reason="no_policy_match")
