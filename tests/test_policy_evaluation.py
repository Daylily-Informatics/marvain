from __future__ import annotations

from unittest import mock

import pytest
from agent_hub.policy import (
    ConsentCheckRequest,
    PolicyStateError,
    PrivacyCheckRequest,
    evaluate_policy,
    is_agent_disabled,
    is_privacy_mode,
)

AGENT_ID = "00000000-0000-0000-0000-000000000101"
SPACE_ID = "00000000-0000-0000-0000-000000000201"
PERSON_ID = "00000000-0000-0000-0000-000000000301"


def test_policy_evidence_contains_only_checks_actually_performed() -> None:
    db = mock.Mock()
    db.query.side_effect = [
        [{"disabled": False}],
        [{"agent_id": AGENT_ID, "privacy_mode": False}],
    ]

    decision = evaluate_policy(
        db,
        operation="memory_recall",
        agent_id=AGENT_ID,
        privacy=PrivacyCheckRequest(space_id=SPACE_ID),
        consent=None,
    )

    assert decision.allowed is True
    assert decision.reason == "allowed"
    assert [item.check for item in decision.evidence] == ["agent_enabled", "space_privacy"]
    assert "active_consent" not in {item.check for item in decision.evidence}
    assert len(db.query.call_args_list) == 2


def test_privacy_denial_short_circuits_consent_and_reports_observed_state() -> None:
    db = mock.Mock()
    db.query.side_effect = [
        [{"disabled": False}],
        [{"agent_id": AGENT_ID, "privacy_mode": True}],
    ]

    decision = evaluate_policy(
        db,
        operation="memory_recall",
        agent_id=AGENT_ID,
        privacy=PrivacyCheckRequest(space_id=SPACE_ID),
        consent=ConsentCheckRequest(person_id=PERSON_ID, consent_type="recording"),
    )

    assert decision.allowed is False
    assert decision.reason == "privacy_mode_enabled"
    assert [item.check for item in decision.evidence] == ["agent_enabled", "space_privacy"]
    assert decision.evidence[-1].fields["privacy_mode"] is True
    assert len(db.query.call_args_list) == 2


def test_active_global_consent_records_exact_match_evidence() -> None:
    db = mock.Mock()
    db.query.side_effect = [
        [{"disabled": False}],
        [
            {
                "consent_id": "00000000-0000-0000-0000-000000000401",
                "consent_type": "global",
                "scope_json": '{"disclosure": "memory_recall"}',
                "granted_at": "2026-07-10T01:00:00+00:00",
                "expires_at": None,
            }
        ],
    ]

    decision = evaluate_policy(
        db,
        operation="memory_recall",
        agent_id=AGENT_ID,
        privacy=None,
        consent=ConsentCheckRequest(person_id=PERSON_ID, consent_type="recording"),
    )

    assert decision.allowed is True
    assert [item.check for item in decision.evidence] == ["agent_enabled", "active_consent"]
    consent_evidence = decision.evidence[-1].fields
    assert consent_evidence["requested_consent_type"] == "recording"
    assert consent_evidence["matched_consent_type"] == "global"
    assert consent_evidence["scope"] == {"disclosure": "memory_recall"}
    assert "space_id" not in consent_evidence


def test_missing_active_consent_is_an_explicit_denial() -> None:
    db = mock.Mock()
    db.query.side_effect = [[{"disabled": False}], []]

    decision = evaluate_policy(
        db,
        operation="memory_recall",
        agent_id=AGENT_ID,
        privacy=None,
        consent=ConsentCheckRequest(person_id=PERSON_ID, consent_type="recording"),
    )

    assert decision.allowed is False
    assert decision.reason == "no_active_consent"
    assert decision.evidence[-1].fields == {
        "agent_id": AGENT_ID,
        "person_id": PERSON_ID,
        "requested_consent_type": "recording",
        "found": False,
    }


def test_malformed_policy_state_fails_instead_of_coercing() -> None:
    db = mock.Mock()
    db.query.return_value = [{"disabled": "false"}]

    with pytest.raises(PolicyStateError, match="disabled must be a boolean"):
        evaluate_policy(
            db,
            operation="memory_recall",
            agent_id=AGENT_ID,
            privacy=None,
            consent=None,
        )


def test_legacy_boolean_helpers_fail_when_subject_is_missing_or_malformed() -> None:
    db = mock.Mock()
    db.query.side_effect = [[], [{"privacy_mode": "false"}]]

    with pytest.raises(LookupError, match="Agent not found"):
        is_agent_disabled(db, AGENT_ID)
    with pytest.raises(PolicyStateError, match="privacy_mode must be a boolean"):
        is_privacy_mode(db, SPACE_ID)
