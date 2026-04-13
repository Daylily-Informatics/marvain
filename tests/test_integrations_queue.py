from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.config import load_config
from agent_hub.integrations.queue import (
    IntegrationQueueMessage,
    enqueue_integration_event,
    parse_integration_queue_message,
)


class TestIntegrationQueueMessage(unittest.TestCase):
    def test_round_trip_message_body(self) -> None:
        message = IntegrationQueueMessage(
            event_id="event-1",
            agent_id="agent-1",
            space_id="space-1",
            integration_message_id="msg-1",
        )

        parsed = parse_integration_queue_message(message.to_message_body())

        self.assertEqual(parsed.event_id, "event-1")
        self.assertEqual(parsed.agent_id, "agent-1")
        self.assertEqual(parsed.space_id, "space-1")
        self.assertEqual(parsed.integration_message_id, "msg-1")
        self.assertEqual(parsed.event_type, "integration.event.received")

    def test_enqueue_integration_event_sends_expected_body(self) -> None:
        sqs = mock.Mock()
        message = IntegrationQueueMessage(
            event_id="event-1",
            agent_id="agent-1",
            integration_message_id="msg-1",
        )

        enqueue_integration_event(
            sqs,
            queue_url="https://sqs.us-east-1.amazonaws.com/123/integration-queue",
            message=message,
        )

        sqs.send_message.assert_called_once_with(
            QueueUrl="https://sqs.us-east-1.amazonaws.com/123/integration-queue",
            MessageBody=message.to_message_body(),
        )

    def test_invalid_event_type_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "integration.event.received"):
            IntegrationQueueMessage(
                event_id="event-1",
                agent_id="agent-1",
                event_type="transcript_chunk",
            )


class TestIntegrationQueueConfig(unittest.TestCase):
    def test_load_config_reads_integration_queue_url(self) -> None:
        env = {
            "DB_RESOURCE_ARN": "arn:aws:rds:us-east-1:123:cluster:db",
            "DB_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:db",
            "DB_NAME": "marvain",
            "INTEGRATION_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/123/integration-queue",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = load_config()

        self.assertEqual(cfg.integration_queue_url, env["INTEGRATION_QUEUE_URL"])


class TestIntegrationQueueWiring(unittest.TestCase):
    def test_template_and_ops_include_integration_queue_wiring(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        template_text = (repo_root / "template.yaml").read_text(encoding="utf-8")
        ops_text = (repo_root / "marvain_cli" / "ops.py").read_text(encoding="utf-8")

        self.assertIn("IntegrationQueue:", template_text)
        self.assertIn("INTEGRATION_QUEUE_URL: !Ref IntegrationQueue", template_text)
        self.assertIn("IntegrationQueueEvent:", template_text)
        self.assertIn("Queue: !GetAtt IntegrationQueue.Arn", template_text)
        self.assertIn("IntegrationQueueUrl:", template_text)
        self.assertIn('"IntegrationQueueUrl": "INTEGRATION_QUEUE_URL"', ops_text)

    def test_template_includes_gmail_poll_and_retention_functions(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        template_text = (repo_root / "template.yaml").read_text(encoding="utf-8")

        self.assertIn("GmailPollFunction:", template_text)
        self.assertIn("CodeUri: functions/gmail_poll/", template_text)
        self.assertIn("GmailPollSchedule:", template_text)
        self.assertIn("RetentionSweeperFunction:", template_text)
        self.assertIn("CodeUri: functions/retention_sweeper/", template_text)
        self.assertIn("RetentionSweepSchedule:", template_text)


if __name__ == "__main__":
    unittest.main()
