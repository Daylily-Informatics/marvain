from __future__ import annotations

import hashlib
import hmac
import sys
from base64 import b64encode
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
shared = repo_root / "layers" / "shared" / "python"
if str(shared) not in sys.path:
    sys.path.insert(0, str(shared))

from agent_hub.integrations.github import normalize_github_webhook, verify_github_request  # noqa: E402
from agent_hub.integrations.slack import normalize_slack_webhook, verify_slack_request  # noqa: E402
from agent_hub.integrations.twilio import normalize_twilio_webhook, verify_twilio_request  # noqa: E402


def _slack_signature(timestamp: str, body: str, signing_secret: str) -> str:
    base = f"v0:{timestamp}:{body}"
    digest = hmac.new(signing_secret.encode("utf-8"), base.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"v0={digest}"


def _github_signature(body: str, webhook_secret: str) -> str:
    digest = hmac.new(webhook_secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _twilio_signature(url: str, payload: dict[str, str], auth_token: str) -> str:
    base = url
    for key in sorted(set(payload)):
        base += f"{key}{payload[key]}"
    digest = hmac.new(auth_token.encode("utf-8"), base.encode("utf-8"), hashlib.sha1).digest()
    return b64encode(digest).decode("utf-8")


def test_slack_normalize_is_account_aware_and_provider_stable() -> None:
    payload = {
        "type": "event_callback",
        "team_id": "T111",
        "event_id": "Ev111",
        "event": {
            "type": "message",
            "channel": "D111",
            "user": "U111",
            "text": "hello from slack",
            "ts": "1712345678.000100",
        },
    }

    normalized = normalize_slack_webhook(
        payload,
        agent_id="agent-1",
        space_id="space-1",
        integration_account_id="acct-1",
    )

    assert normalized.integration_account_id == "acct-1"
    assert normalized.integration_message is not None
    assert normalized.integration_message.integration_account_id == "acct-1"
    assert normalized.integration_message.dedupe_key == "slack:T111:Ev111"
    assert normalized.event_payload["integration_account_id"] == "acct-1"


def test_slack_signature_verification_accepts_valid_request() -> None:
    body = '{"type":"url_verification","challenge":"token"}'
    timestamp = "1712345678"
    secret = "slack-signing-secret"

    verify_slack_request(
        secret,
        timestamp=timestamp,
        signature=_slack_signature(timestamp, body, secret),
        body=body.encode("utf-8"),
        now=int(timestamp),
    )


def test_github_normalize_is_account_aware_and_provider_stable() -> None:
    payload = {
        "action": "created",
        "repository": {"full_name": "octo/repo"},
        "sender": {"login": "octocat", "id": 42},
        "issue": {"number": 7, "title": "Need help"},
        "comment": {"id": 9001, "body": "hello from github"},
    }

    normalized = normalize_github_webhook(
        payload,
        event_name="issue_comment",
        delivery_id="delivery-1",
        agent_id="agent-1",
        space_id="space-1",
        integration_account_id="acct-2",
    )

    assert normalized.integration_account_id == "acct-2"
    assert normalized.integration_message is not None
    assert normalized.integration_message.integration_account_id == "acct-2"
    assert normalized.integration_message.dedupe_key == "github:delivery-1"
    assert normalized.event_payload["integration_account_id"] == "acct-2"


def test_github_signature_verification_accepts_valid_request() -> None:
    body = '{"zen":"keep it logically awesome"}'
    secret = "github-webhook-secret"

    verify_github_request(
        secret,
        signature=_github_signature(body, secret),
        body=body.encode("utf-8"),
    )


def test_twilio_normalize_is_account_aware_and_provider_stable() -> None:
    payload = {
        "AccountSid": "AC123",
        "MessageSid": "SM123",
        "From": "+15551230001",
        "To": "+15551239999",
        "Body": "hello from twilio",
        "NumMedia": "0",
    }

    normalized = normalize_twilio_webhook(
        payload,
        agent_id="agent-1",
        space_id="space-1",
        integration_account_id="acct-3",
    )

    assert normalized.integration_account_id == "acct-3"
    assert normalized.integration_message is not None
    assert normalized.integration_message.integration_account_id == "acct-3"
    assert normalized.integration_message.dedupe_key == "twilio:AC123:SM123"
    assert normalized.event_payload["integration_account_id"] == "acct-3"


def test_twilio_signature_verification_accepts_valid_request() -> None:
    payload = {
        "AccountSid": "AC123",
        "MessageSid": "SM123",
        "From": "+15551230001",
        "To": "+15551239999",
        "Body": "hello from twilio",
    }
    url = "http://testserver/v1/integrations/twilio/webhook/acct-3"
    secret = "twilio-auth-token"

    verify_twilio_request(
        secret,
        url=url,
        params=payload,
        signature=_twilio_signature(url, payload, secret),
    )
