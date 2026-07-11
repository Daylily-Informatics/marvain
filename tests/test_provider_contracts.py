from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from agent_hub.integrations import IntegrationAccountRecord
from agent_hub.provider_contracts import (
    ProviderContractError,
    ProviderIngressReceipt,
    require_outbound_destination,
)


def _account(*, provider: str, destination: str, scope: str) -> IntegrationAccountRecord:
    return IntegrationAccountRecord(
        integration_account_id=f"{provider}-account",
        agent_id="agent-1",
        provider=provider,
        display_name=f"{provider} test account",
        credentials_secret_arn=f"arn:aws:secretsmanager:us-east-1:123:secret:{provider}",
        created_at="2026-07-11T00:00:00Z",
        updated_at="2026-07-11T00:00:00Z",
        default_space_id="space-1",
        scopes=[scope],
        config={"allowed_destinations": [destination]},
        status="active",
    )


@pytest.mark.parametrize(
    ("kind", "provider", "field", "destination", "scope"),
    [
        ("slack_post_message", "slack", "channel_id", "C-TEST", "slack:message:write"),
        ("twilio_send_sms", "twilio", "to", "+15550001111", "twilio:sms:send"),
        ("github_issue_comment", "github", "repository", "daylily/test-repo", "github:issue:write"),
        ("gmail_send_message", "gmail", "to", "test@example.com", "gmail:message:send"),
    ],
)
def test_provider_destination_requires_exact_account_allowlist(
    kind: str,
    provider: str,
    field: str,
    destination: str,
    scope: str,
) -> None:
    action = {
        "action_id": "action-1",
        "agent_id": "agent-1",
        "space_id": "space-1",
        "kind": kind,
        "payload": {"integration_account_id": f"{provider}-account", field: destination},
    }
    with patch(
        "agent_hub.provider_contracts.get_integration_account",
        return_value=_account(provider=provider, destination=destination, scope=scope),
    ):
        receipt = require_outbound_destination(MagicMock(), action=action)

    assert receipt is not None
    assert receipt.provider == provider
    assert receipt.destination == destination
    assert receipt.as_dict()["approval_state"] == "approved_and_reserved"


def test_provider_destination_rejects_arbitrary_payload_destination() -> None:
    account = _account(provider="slack", destination="C-ALLOWED", scope="slack:message:write")
    action = {
        "action_id": "action-1",
        "agent_id": "agent-1",
        "space_id": "space-1",
        "kind": "slack_post_message",
        "payload": {"integration_account_id": account.integration_account_id, "channel_id": "C-OTHER"},
    }
    with (
        patch("agent_hub.provider_contracts.get_integration_account", return_value=account),
        pytest.raises(ProviderContractError) as exc_info,
    ):
        require_outbound_destination(MagicMock(), action=action)
    assert exc_info.value.code == "provider_destination_not_allowed"


def test_provider_account_without_explicit_destinations_fails_hard() -> None:
    account = _account(provider="github", destination="daylily/test-repo", scope="github:issue:write")
    account = IntegrationAccountRecord(**{**account.__dict__, "config": {}})
    action = {
        "action_id": "action-1",
        "agent_id": "agent-1",
        "space_id": "space-1",
        "kind": "github_issue_comment",
        "payload": {"integration_account_id": account.integration_account_id, "repository": "daylily/test-repo"},
    }
    with (
        patch("agent_hub.provider_contracts.get_integration_account", return_value=account),
        pytest.raises(ProviderContractError) as exc_info,
    ):
        require_outbound_destination(MagicMock(), action=action)
    assert exc_info.value.code == "provider_destinations_not_configured"


def test_ingress_receipt_requires_verified_signature() -> None:
    with pytest.raises(ProviderContractError) as exc_info:
        ProviderIngressReceipt(
            provider="github",
            integration_account_id="github-account",
            external_delivery_id="delivery-1",
            dedupe_key="github:delivery-1",
            signature_verified=False,
        )
    assert exc_info.value.code == "provider_ingress_signature_unverified"
