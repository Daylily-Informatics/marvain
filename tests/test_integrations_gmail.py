from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest import mock

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.integrations.gmail import (  # noqa: E402
    list_gmail_message_refs,
    normalize_gmail_message,
)


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")


class TestGmailIntegrationModule(unittest.TestCase):
    def test_normalize_gmail_message_extracts_body_and_headers(self) -> None:
        normalized = normalize_gmail_message(
            {
                "id": "gmail-msg-1",
                "threadId": "gmail-thread-1",
                "historyId": "200",
                "snippet": "snippet body",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "Sender <sender@example.com>"},
                        {"name": "To", "value": "Receiver <receiver@example.com>"},
                        {"name": "Subject", "value": "Hello"},
                    ],
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {"mimeType": "text/plain", "body": {"data": _b64("plain body")}},
                        {"mimeType": "text/html", "body": {"data": _b64("<p>html body</p>")}},
                    ],
                },
            },
            agent_id="agent-1",
            space_id="space-1",
            integration_account_id="acct-1",
            user_email="owner@example.com",
        )

        message = normalized.integration_message
        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message.provider, "gmail")
        self.assertEqual(message.integration_account_id, "acct-1")
        self.assertEqual(message.external_thread_id, "gmail-thread-1")
        self.assertEqual(message.external_message_id, "gmail-msg-1")
        self.assertEqual(message.subject, "Hello")
        self.assertEqual(message.body_text, "plain body")
        self.assertEqual(message.body_html, "<p>html body</p>")
        self.assertEqual(message.sender["email"], "sender@example.com")
        self.assertEqual(message.recipients[0]["email"], "receiver@example.com")

    def test_list_gmail_message_refs_uses_history_cursor_when_present(self) -> None:
        with mock.patch(
            "agent_hub.integrations.gmail._gmail_api_request",
            return_value={
                "historyId": "300",
                "history": [
                    {"messagesAdded": [{"message": {"id": "m1"}}, {"message": {"id": "m2"}}]},
                    {"messagesAdded": [{"message": {"id": "m1"}}]},
                ],
            },
        ):
            refs, cursor = list_gmail_message_refs("token", history_id="200", max_results=10)

        self.assertEqual([item.message_id for item in refs], ["m1", "m2"])
        self.assertEqual(cursor, "300")


if __name__ == "__main__":
    unittest.main()
