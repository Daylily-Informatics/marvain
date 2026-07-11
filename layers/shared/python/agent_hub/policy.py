from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agent_hub.rds_data import RdsData


class PolicyStateError(RuntimeError):
    """Raised when persisted policy state cannot support a trustworthy decision."""


@dataclass(frozen=True)
class PrivacyCheckRequest:
    space_id: str


@dataclass(frozen=True)
class ConsentCheckRequest:
    person_id: str
    consent_type: str


@dataclass(frozen=True)
class PolicyCheckEvidence:
    check: str
    allowed: bool
    fields: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "allowed": self.allowed,
            "fields": dict(self.fields),
        }


@dataclass(frozen=True)
class PolicyDecision:
    operation: str
    allowed: bool
    reason: str
    evidence: tuple[PolicyCheckEvidence, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "allowed": self.allowed,
            "reason": self.reason,
            "evidence": [item.as_dict() for item in self.evidence],
        }


def _required_text(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _policy_text(value: Any, *, field_name: str, state_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyStateError(f"Malformed {state_name}: {field_name} must be a non-empty string")
    return value


def _policy_bool(value: Any, *, field_name: str, state_name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyStateError(f"Malformed {state_name}: {field_name} must be a boolean")
    return value


def _policy_object(value: Any, *, field_name: str, state_name: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise PolicyStateError(f"Malformed {state_name}: {field_name} must contain JSON")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise PolicyStateError(f"Malformed {state_name}: {field_name} contains invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise PolicyStateError(f"Malformed {state_name}: {field_name} must be a JSON object")
    return parsed


def _optional_policy_text(value: Any, *, field_name: str, state_name: str) -> str | None:
    if value is None:
        return None
    return _policy_text(value, field_name=field_name, state_name=state_name)


def _agent_check(db: RdsData, *, agent_id: str) -> PolicyCheckEvidence:
    rows = db.query(
        """
        SELECT disabled
        FROM agents
        WHERE agent_id = :agent_id::uuid
        LIMIT 1
        """,
        {"agent_id": agent_id},
    )
    if not rows:
        return PolicyCheckEvidence(
            check="agent_enabled",
            allowed=False,
            fields={"agent_id": agent_id, "found": False},
        )

    disabled = _policy_bool(rows[0].get("disabled"), field_name="disabled", state_name="agent policy state")
    return PolicyCheckEvidence(
        check="agent_enabled",
        allowed=not disabled,
        fields={"agent_id": agent_id, "found": True, "disabled": disabled},
    )


def _privacy_check(db: RdsData, *, agent_id: str, space_id: str) -> PolicyCheckEvidence:
    rows = db.query(
        """
        SELECT agent_id::TEXT as agent_id, privacy_mode
        FROM spaces
        WHERE space_id = :space_id::uuid
        LIMIT 1
        """,
        {"space_id": space_id},
    )
    if not rows:
        return PolicyCheckEvidence(
            check="space_privacy",
            allowed=False,
            fields={"space_id": space_id, "found": False},
        )

    row = rows[0]
    space_agent_id = _policy_text(row.get("agent_id"), field_name="agent_id", state_name="space policy state")
    privacy_mode = _policy_bool(
        row.get("privacy_mode"),
        field_name="privacy_mode",
        state_name="space policy state",
    )
    owner_matches = space_agent_id == agent_id
    return PolicyCheckEvidence(
        check="space_privacy",
        allowed=owner_matches and not privacy_mode,
        fields={
            "space_id": space_id,
            "found": True,
            "space_agent_id": space_agent_id,
            "agent_matches": owner_matches,
            "privacy_mode": privacy_mode,
        },
    )


def _consent_check(
    db: RdsData,
    *,
    agent_id: str,
    person_id: str,
    consent_type: str,
) -> PolicyCheckEvidence:
    rows = db.query(
        """
        SELECT cg.consent_id::TEXT as consent_id,
               cg.consent_type,
               cg.scope::TEXT as scope_json,
               cg.granted_at::TEXT as granted_at,
               cg.expires_at::TEXT as expires_at
        FROM consent_grants cg
        JOIN people p ON p.person_id = cg.person_id
        WHERE cg.agent_id = :agent_id::uuid
          AND p.agent_id = :agent_id::uuid
          AND cg.person_id = :person_id::uuid
          AND cg.consent_type IN (:consent_type, 'global')
          AND cg.revoked_at IS NULL
          AND (cg.expires_at IS NULL OR cg.expires_at > NOW())
        ORDER BY CASE WHEN cg.consent_type = :consent_type THEN 0 ELSE 1 END,
                 cg.granted_at DESC
        LIMIT 1
        """,
        {
            "agent_id": agent_id,
            "person_id": person_id,
            "consent_type": consent_type,
        },
    )
    if not rows:
        return PolicyCheckEvidence(
            check="active_consent",
            allowed=False,
            fields={
                "agent_id": agent_id,
                "person_id": person_id,
                "requested_consent_type": consent_type,
                "found": False,
            },
        )

    row = rows[0]
    matched_consent_type = _policy_text(
        row.get("consent_type"),
        field_name="consent_type",
        state_name="consent policy state",
    )
    if matched_consent_type not in {consent_type, "global"}:
        raise PolicyStateError("Malformed consent policy state: consent_type does not satisfy the requested check")
    return PolicyCheckEvidence(
        check="active_consent",
        allowed=True,
        fields={
            "agent_id": agent_id,
            "person_id": person_id,
            "requested_consent_type": consent_type,
            "found": True,
            "consent_id": _policy_text(
                row.get("consent_id"),
                field_name="consent_id",
                state_name="consent policy state",
            ),
            "matched_consent_type": matched_consent_type,
            "scope": _policy_object(
                row.get("scope_json"),
                field_name="scope",
                state_name="consent policy state",
            ),
            "granted_at": _policy_text(
                row.get("granted_at"),
                field_name="granted_at",
                state_name="consent policy state",
            ),
            "expires_at": _optional_policy_text(
                row.get("expires_at"),
                field_name="expires_at",
                state_name="consent policy state",
            ),
        },
    )


def _reason_for(check: PolicyCheckEvidence) -> str:
    if check.check == "agent_enabled":
        return "agent_disabled" if check.fields.get("found") else "agent_not_found"
    if check.check == "space_privacy":
        if not check.fields.get("found"):
            return "space_not_found"
        if not check.fields.get("agent_matches"):
            return "space_agent_mismatch"
        return "privacy_mode_enabled"
    if check.check == "active_consent":
        return "no_active_consent"
    raise PolicyStateError(f"Unsupported policy check: {check.check}")


def evaluate_policy(
    db: RdsData,
    *,
    operation: str,
    agent_id: str,
    privacy: PrivacyCheckRequest | None,
    consent: ConsentCheckRequest | None,
) -> PolicyDecision:
    """Evaluate explicit policy checks and return evidence only for checks performed.

    ``privacy`` and ``consent`` have no defaults. Callers must explicitly request
    each check or explicitly pass ``None`` when the operation does not require it.
    Evaluation short-circuits on denial, so evidence never claims a later check ran.
    """

    operation = _required_text(operation, field_name="operation")
    agent_id = _required_text(agent_id, field_name="agent_id")
    if privacy is not None and not isinstance(privacy, PrivacyCheckRequest):
        raise TypeError("privacy must be PrivacyCheckRequest or None")
    if consent is not None and not isinstance(consent, ConsentCheckRequest):
        raise TypeError("consent must be ConsentCheckRequest or None")

    evidence: list[PolicyCheckEvidence] = []
    agent_result = _agent_check(db, agent_id=agent_id)
    evidence.append(agent_result)
    if not agent_result.allowed:
        return PolicyDecision(operation, False, _reason_for(agent_result), tuple(evidence))

    if privacy is not None:
        space_id = _required_text(privacy.space_id, field_name="privacy.space_id")
        privacy_result = _privacy_check(db, agent_id=agent_id, space_id=space_id)
        evidence.append(privacy_result)
        if not privacy_result.allowed:
            return PolicyDecision(operation, False, _reason_for(privacy_result), tuple(evidence))

    if consent is not None:
        person_id = _required_text(consent.person_id, field_name="consent.person_id")
        consent_type = _required_text(consent.consent_type, field_name="consent.consent_type")
        if consent_type != consent_type.lower():
            raise ValueError("consent.consent_type must be lowercase")
        consent_result = _consent_check(
            db,
            agent_id=agent_id,
            person_id=person_id,
            consent_type=consent_type,
        )
        evidence.append(consent_result)
        if not consent_result.allowed:
            return PolicyDecision(operation, False, _reason_for(consent_result), tuple(evidence))

    return PolicyDecision(operation, True, "allowed", tuple(evidence))


def is_agent_disabled(db: RdsData, agent_id: str) -> bool:
    agent_id = _required_text(agent_id, field_name="agent_id")
    result = _agent_check(db, agent_id=agent_id)
    if not result.fields["found"]:
        raise LookupError(f"Agent not found: {agent_id}")
    return not result.allowed


def is_privacy_mode(db: RdsData, space_id: str) -> bool:
    space_id = _required_text(space_id, field_name="space_id")
    rows = db.query(
        """
        SELECT privacy_mode
        FROM spaces
        WHERE space_id = :space_id::uuid
        LIMIT 1
        """,
        {"space_id": space_id},
    )
    if not rows:
        raise LookupError(f"Space not found: {space_id}")
    return _policy_bool(
        rows[0].get("privacy_mode"),
        field_name="privacy_mode",
        state_name="space policy state",
    )
