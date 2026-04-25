"""Shared helpers for outbound integration tools."""

from __future__ import annotations

from typing import Any

from agent_hub.integrations import get_integration_account
from agent_hub.integrations.models import IntegrationAccountRecord
from agent_hub.rds_data import RdsData
from agent_hub.secrets import get_secret_json


def load_outbound_integration_account(
    db: RdsData,
    *,
    integration_account_id: str,
    provider: str,
) -> tuple[IntegrationAccountRecord, dict[str, Any]]:
    account = get_integration_account(db, integration_account_id=integration_account_id)
    if account is None:
        raise LookupError("integration account not found")
    if account.provider != provider:
        raise RuntimeError(f"integration_account_provider_mismatch: expected {provider}")
    if account.status != "active":
        raise RuntimeError(f"integration_account_inactive: {account.status}")
    secret_data = get_secret_json(account.credentials_secret_arn)
    return account, secret_data
