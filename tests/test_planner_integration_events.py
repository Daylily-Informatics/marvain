from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


AGENT_ID = "11111111-1111-1111-1111-111111111111"
SPACE_ID = "22222222-2222-2222-2222-222222222222"
EVENT_ID = "44444444-4444-4444-4444-444444444444"
INTEGRATION_MESSAGE_ID = "33333333-3333-3333-3333-333333333333"


def _load_planner_handler_module():
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    planner_dir = repo_root / "functions" / "planner"
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")

    package_name = "planner_handler_for_tests"
    for mod_name in [package_name, f"{package_name}.validation", f"{package_name}.handler"]:
        sys.modules.pop(mod_name, None)

    package_mod = types.ModuleType(package_name)
    package_mod.__path__ = [str(planner_dir)]
    sys.modules[package_name] = package_mod

    validation_py = planner_dir / "validation.py"
    validation_spec = importlib.util.spec_from_file_location(f"{package_name}.validation", validation_py)
    assert validation_spec and validation_spec.loader
    validation_mod = importlib.util.module_from_spec(validation_spec)
    sys.modules[validation_spec.name] = validation_mod
    validation_spec.loader.exec_module(validation_mod)

    handler_py = planner_dir / "handler.py"
    handler_spec = importlib.util.spec_from_file_location(f"{package_name}.handler", handler_py)
    assert handler_spec and handler_spec.loader
    handler_mod = importlib.util.module_from_spec(handler_spec)
    sys.modules[handler_spec.name] = handler_mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        handler_spec.loader.exec_module(handler_mod)
    return handler_mod


class TestPlannerIntegrationEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_planner_handler_module()
        from agent_hub.integrations.models import IntegrationMessageRecord

        cls.IntegrationMessageRecord = IntegrationMessageRecord
        cls._orig_cfg = cls.mod._cfg
        cls._orig_db = cls.mod._db
        cls._orig_sqs = cls.mod._sqs
        cls._orig_processed = cls.mod._PROCESSED_EVENTS
        cls._orig_is_already_processed = cls.mod._is_already_processed
        cls._orig_load_event = cls.mod._load_event
        cls._orig_vector_recall = cls.mod._vector_recall
        cls._orig_get_integration_message = cls.mod.get_integration_message
        cls._orig_call_responses = cls.mod.call_responses
        cls._orig_extract_output_text = cls.mod.extract_output_text
        cls._orig_create_action = cls.mod.create_action
        cls._orig_insert_memory = cls.mod._insert_memory
        cls._orig_mark_processed = cls.mod._mark_processed
        cls._orig_broadcast_event = cls.mod.broadcast_event
        cls._orig_append_audit_entry = cls.mod.append_audit_entry
        cls._orig_is_agent_disabled = cls.mod.is_agent_disabled
        cls._orig_is_privacy_mode = cls.mod.is_privacy_mode

    def setUp(self) -> None:
        self.mod._cfg = types.SimpleNamespace(
            openai_secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:openai",
            planner_model="gpt-test",
            audit_bucket=None,
            action_queue_url=None,
        )
        self.mod._db = mock.Mock()
        self.mod._sqs = mock.Mock()
        self.mod._PROCESSED_EVENTS = set()
        self.mod._is_already_processed = mock.Mock(return_value=False)
        self.mod._load_event = mock.Mock(
            return_value={
                "event_id": EVENT_ID,
                "agent_id": AGENT_ID,
                "space_id": SPACE_ID,
                "person_id": None,
                "type": "integration.event.received",
                "payload": {"provider": "slack"},
            }
        )
        self.mod._vector_recall = mock.Mock(return_value=[])
        self.mod.broadcast_event = mock.Mock()
        self.mod.append_audit_entry = mock.Mock()
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.is_privacy_mode = mock.Mock(return_value=False)
        self.mod._insert_memory = mock.Mock(side_effect=AssertionError("_insert_memory should not be called"))
        self.mod._mark_processed = mock.Mock()

    def tearDown(self) -> None:
        self.mod._cfg = self.__class__._orig_cfg
        self.mod._db = self.__class__._orig_db
        self.mod._sqs = self.__class__._orig_sqs
        self.mod._PROCESSED_EVENTS = self.__class__._orig_processed
        self.mod._is_already_processed = self.__class__._orig_is_already_processed
        self.mod._load_event = self.__class__._orig_load_event
        self.mod._vector_recall = self.__class__._orig_vector_recall
        self.mod.get_integration_message = self.__class__._orig_get_integration_message
        self.mod.call_responses = self.__class__._orig_call_responses
        self.mod.extract_output_text = self.__class__._orig_extract_output_text
        self.mod.create_action = self.__class__._orig_create_action
        self.mod._insert_memory = self.__class__._orig_insert_memory
        self.mod._mark_processed = self.__class__._orig_mark_processed
        self.mod.broadcast_event = self.__class__._orig_broadcast_event
        self.mod.append_audit_entry = self.__class__._orig_append_audit_entry
        self.mod.is_agent_disabled = self.__class__._orig_is_agent_disabled
        self.mod.is_privacy_mode = self.__class__._orig_is_privacy_mode

    def _integration_message(self) -> object:
        return self.IntegrationMessageRecord(
            integration_message_id=INTEGRATION_MESSAGE_ID,
            agent_id=AGENT_ID,
            space_id=SPACE_ID,
            event_id=EVENT_ID,
            provider="slack",
            direction="inbound",
            channel_type="dm",
            object_type="message",
            external_thread_id="1712345678.000100",
            external_message_id="1712345678.000100",
            dedupe_key="slack:T111:Ev111",
            sender={"team_id": "T111", "user_id": "U111"},
            recipients=[{"channel_id": "D111"}],
            subject=None,
            body_text="hello from slack",
            body_html=None,
            payload={"raw": True},
            status="received",
            created_at="2026-04-13T00:00:00+00:00",
            updated_at="2026-04-13T00:00:00+00:00",
        )

    def test_integration_event_passes_message_text_and_metadata_to_planner(self) -> None:
        self.mod.get_integration_message = mock.Mock(return_value=self._integration_message())
        self.mod.call_responses = mock.Mock(return_value={"ok": True})
        self.mod.extract_output_text = mock.Mock(return_value='{"episodic":[],"semantic":[],"actions":[]}')
        self.mod.create_action = mock.Mock()

        result = self.mod.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {
                                "event_id": EVENT_ID,
                                "event_type": "integration.event.received",
                                "agent_id": AGENT_ID,
                                "space_id": SPACE_ID,
                                "integration_message_id": INTEGRATION_MESSAGE_ID,
                            }
                        )
                    }
                ]
            },
            context=None,
        )

        self.assertEqual(result["processed"], 1)
        self.mod.call_responses.assert_called_once()
        planner_user = json.loads(self.mod.call_responses.call_args.kwargs["user"])
        self.assertEqual(planner_user["event"]["type"], "integration.event.received")
        self.assertEqual(planner_user["event"]["text"], "hello from slack")
        self.assertEqual(planner_user["event"]["integration"]["provider"], "slack")
        self.assertEqual(planner_user["event"]["integration"]["channel_type"], "dm")
        self.assertEqual(planner_user["event"]["integration"]["object_type"], "message")
        self.assertEqual(planner_user["event"]["integration"]["sender"]["user_id"], "U111")
        self.assertEqual(planner_user["event"]["integration"]["recipients"][0]["channel_id"], "D111")
        self.mod.get_integration_message.assert_called_once_with(
            self.mod._db,
            integration_message_id=INTEGRATION_MESSAGE_ID,
        )

    def test_integration_event_without_message_id_is_skipped(self) -> None:
        self.mod.get_integration_message = mock.Mock()
        self.mod.call_responses = mock.Mock()
        self.mod.extract_output_text = mock.Mock()
        self.mod.create_action = mock.Mock()

        result = self.mod.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {
                                "event_id": EVENT_ID,
                                "event_type": "integration.event.received",
                                "agent_id": AGENT_ID,
                                "space_id": SPACE_ID,
                            }
                        )
                    }
                ]
            },
            context=None,
        )

        self.assertEqual(result["processed"], 0)
        self.mod.call_responses.assert_not_called()
        self.mod.get_integration_message.assert_not_called()

    def test_planner_actions_use_deterministic_idempotency_fields(self) -> None:
        self.mod.get_integration_message = mock.Mock(return_value=self._integration_message())
        self.mod.call_responses = mock.Mock(return_value={"ok": True})
        self.mod.extract_output_text = mock.Mock(
            return_value=json.dumps(
                {
                    "episodic": [],
                    "semantic": [],
                    "actions": [
                        {
                            "kind": "send_message",
                            "payload": {
                                "recipient_type": "space",
                                "recipient_id": SPACE_ID,
                                "content": "reply",
                            },
                            "required_scopes": ["message:send"],
                            "auto_approve": False,
                        }
                    ],
                }
            )
        )
        self.mod.create_action = mock.Mock(return_value={"action_id": "act-1", "status": "proposed"})

        result = self.mod.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {
                                "event_id": EVENT_ID,
                                "event_type": "integration.event.received",
                                "agent_id": AGENT_ID,
                                "space_id": SPACE_ID,
                                "integration_message_id": INTEGRATION_MESSAGE_ID,
                            }
                        )
                    }
                ]
            },
            context=None,
        )

        self.assertEqual(result["processed"], 1)
        self.mod.create_action.assert_called_once()
        create_kwargs = self.mod.create_action.call_args.kwargs
        self.assertEqual(create_kwargs["request_actor_type"], "planner")
        self.assertEqual(create_kwargs["request_actor_id"], AGENT_ID)
        self.assertEqual(create_kwargs["request_origin"], self.mod._planner_request_origin(EVENT_ID))
        self.assertEqual(
            create_kwargs["idempotency_key"],
            self.mod._compute_action_idempotency_key(EVENT_ID, 0, "send_message"),
        )

    def test_duplicate_action_only_event_is_skipped_without_llm_call(self) -> None:
        self.mod._db = mock.Mock()
        self.mod._db.query.side_effect = [
            [],
            [{"exists": 1}],
        ]
        self.mod._is_already_processed = self.__class__._orig_is_already_processed
        self.mod.call_responses = mock.Mock()
        self.mod._load_event = mock.Mock()

        result = self.mod.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {
                                "event_id": EVENT_ID,
                                "event_type": "integration.event.received",
                                "agent_id": AGENT_ID,
                                "space_id": SPACE_ID,
                                "integration_message_id": INTEGRATION_MESSAGE_ID,
                            }
                        )
                    }
                ]
            },
            context=None,
        )

        self.assertEqual(result["processed"], 0)
        self.assertEqual(result["skipped_idempotent"], 1)
        self.mod.call_responses.assert_not_called()
        self.mod._load_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
