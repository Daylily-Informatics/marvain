from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_hub.integrations.store import get_integration_account
from agent_hub.rds_data import RdsData


class ProviderContractError(RuntimeError):
    def __init__(self, code: str, *, detail: str | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class _OutboundContract:
    provider: str
    destination_field: str
    required_scope: str


_OUTBOUND_CONTRACTS = {
    "slack_post_message": _OutboundContract("slack", "channel_id", "slack:message:write"),
    "twilio_send_sms": _OutboundContract("twilio", "to", "twilio:sms:send"),
    "github_issue_comment": _OutboundContract("github", "repository", "github:issue:write"),
    "gmail_send_message": _OutboundContract("gmail", "to", "gmail:message:send"),
}


def _required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProviderContractError("provider_contract_invalid", detail=f"{field_name} is required")
    return text


def _allowed_destinations(config: dict[str, Any]) -> tuple[str, ...]:
    values = config.get("allowed_destinations")
    if not isinstance(values, list) or not values:
        raise ProviderContractError(
            "provider_destinations_not_configured",
            detail="integration account config.allowed_destinations must be a non-empty list",
        )
    normalized = tuple(_required_text(value, "allowed_destination") for value in values)
    if len(set(normalized)) != len(normalized):
        raise ProviderContractError("provider_contract_invalid", detail="allowed destinations must be unique")
    return normalized


@dataclass(frozen=True)
class ProviderDestinationReceipt:
    action_id: str
    agent_id: str
    space_id: str
    integration_account_id: str
    provider: str
    destination: str
    required_scope: str

    def as_dict(self) -> dict[str, str]:
        return {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "space_id": self.space_id,
            "integration_account_id": self.integration_account_id,
            "provider": self.provider,
            "destination": self.destination,
            "required_scope": self.required_scope,
            "approval_state": "approved_and_reserved",
        }


def require_outbound_destination(db: RdsData, *, action: dict[str, Any]) -> ProviderDestinationReceipt | None:
    kind = _required_text(action.get("kind"), "kind")
    contract = _OUTBOUND_CONTRACTS.get(kind)
    if contract is None:
        return None
    payload = action.get("payload")
    if not isinstance(payload, dict):
        raise ProviderContractError("provider_contract_invalid", detail="action payload must be an object")
    action_id = _required_text(action.get("action_id"), "action_id")
    agent_id = _required_text(action.get("agent_id"), "agent_id")
    space_id = _required_text(action.get("space_id"), "space_id")
    account_id = _required_text(payload.get("integration_account_id"), "integration_account_id")
    destination = _required_text(payload.get(contract.destination_field), contract.destination_field)

    account = get_integration_account(db, integration_account_id=account_id)
    if account is None:
        raise ProviderContractError("integration_account_not_found")
    if account.agent_id != agent_id:
        raise ProviderContractError("integration_account_not_owned_by_agent")
    if account.provider != contract.provider:
        raise ProviderContractError("integration_account_provider_mismatch")
    if account.status != "active":
        raise ProviderContractError("integration_account_inactive")
    if account.default_space_id != space_id:
        raise ProviderContractError("integration_account_space_mismatch")
    if contract.required_scope not in account.scopes:
        raise ProviderContractError("integration_account_scope_missing")
    if destination not in _allowed_destinations(account.config):
        raise ProviderContractError("provider_destination_not_allowed")

    return ProviderDestinationReceipt(
        action_id=action_id,
        agent_id=agent_id,
        space_id=space_id,
        integration_account_id=account.integration_account_id,
        provider=contract.provider,
        destination=destination,
        required_scope=contract.required_scope,
    )


@dataclass(frozen=True)
class ProviderIngressReceipt:
    provider: str
    integration_account_id: str
    external_delivery_id: str
    dedupe_key: str
    signature_verified: bool

    def __post_init__(self) -> None:
        _required_text(self.provider, "provider")
        _required_text(self.integration_account_id, "integration_account_id")
        _required_text(self.external_delivery_id, "external_delivery_id")
        _required_text(self.dedupe_key, "dedupe_key")
        if not self.signature_verified:
            raise ProviderContractError("provider_ingress_signature_unverified")

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "integration_account_id": self.integration_account_id,
            "external_delivery_id": self.external_delivery_id,
            "dedupe_key": self.dedupe_key,
            "signature_verified": self.signature_verified,
        }


__all__ = [
    "ProviderContractError",
    "ProviderDestinationReceipt",
    "ProviderIngressReceipt",
    "require_outbound_destination",
]
