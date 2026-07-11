from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest
import yaml

from functions.semantic_outbox_dispatcher import handler as dispatcher

OUTBOX_ID = "11111111-1111-4111-8111-111111111111"
SYNC_ID = "22222222-2222-4222-8222-222222222222"
AGENT_ID = "33333333-3333-4333-8333-333333333333"
IDEMPOTENCY_KEY = "44444444-4444-4444-8444-444444444444"
REPO_ROOT = Path(__file__).resolve().parents[1]


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_cloudformation_tag(
    loader: _CloudFormationLoader,
    _tag_suffix: str,
    node: yaml.Node,
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


_CloudFormationLoader.add_multi_constructor("!", _construct_cloudformation_tag)


def _payload() -> dict[str, Any]:
    return {
        "action": "record",
        "agent_id": AGENT_ID,
        "external_reference": {
            "agent_id": AGENT_ID,
            "foreign_uid": f"agent/{AGENT_ID}/recognition_observations/{OUTBOX_ID}",
            "source_id": OUTBOX_ID,
            "source_table": "recognition_observations",
            "system": "marvain-postgres",
        },
        "idempotency_key": IDEMPOTENCY_KEY,
        "lifecycle_state": "embedded",
        "name": f"recognition-observation:{OUTBOX_ID}",
        "properties": {"agent_id": AGENT_ID, "modality": "voice"},
        "template_code": "MVN/recognition/observation/1.0/",
    }


def _body(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _config() -> dispatcher.DispatcherConfig:
    return dispatcher.DispatcherConfig(
        db_resource_arn="arn:aws:rds:us-east-1:123456789012:cluster:cleanroom",
        db_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:cleanroom",
        db_name="marvain",
        queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/tapdb-writer",
        dispatcher_id="semantic-outbox-cleanroom",
        batch_size=10,
        lease_seconds=60,
        max_attempts=3,
        retry_seconds=30,
    )


class FakeDatabase:
    def __init__(self, *, failure_status: str = "failed", invalid_checksum: bool = False) -> None:
        self.failure_status = failure_status
        self.invalid_checksum = invalid_checksum
        self.calls: list[tuple[str, Mapping[str, Any], str | None]] = []
        self.commits: list[str] = []
        self.rollbacks: list[str] = []
        self._transaction_count = 0

    def begin(self) -> str:
        self._transaction_count += 1
        return f"transaction-{self._transaction_count}"

    def query(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        params = params or {}
        self.calls.append((sql, params, transaction_id))
        if "WITH candidates AS" in sql:
            body = _body(_payload())
            digest = "0" * 64 if self.invalid_checksum else hashlib.sha256(body.encode()).hexdigest()
            return [
                {
                    "semantic_outbox_id": OUTBOX_ID,
                    "semantic_sync_id": SYNC_ID,
                    "agent_id": AGENT_ID,
                    "idempotency_key": IDEMPOTENCY_KEY,
                    "payload_json": body,
                    "payload_sha256": digest,
                    "claim_token": params["claim_token"],
                    "attempt_count": 1,
                    "dispatch_cycle_attempt_count": 1,
                }
            ]
        if "SET status = 'published'" in sql:
            return [{"semantic_outbox_id": OUTBOX_ID}]
        if "dispatch_cycle_attempt_count >= :max_attempts" in sql:
            return [{"semantic_outbox_id": OUTBOX_ID, "status": self.failure_status}]
        if "INSERT INTO semantic_outbox_reconciliations" in sql:
            return [{"semantic_outbox_id": str(params["semantic_outbox_id"])}]
        raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self, transaction_id: str) -> None:
        self.commits.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self.rollbacks.append(transaction_id)


class FakeQueue:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return {"MessageId": f"message-{len(self.calls)}"}


def test_dispatcher_config_hard_fails_instead_of_inferring_values() -> None:
    with pytest.raises(dispatcher.SemanticOutboxDispatcherError, match="Missing required env vars") as exc_info:
        dispatcher.load_dispatcher_config({"DB_NAME": "marvain"})

    message = str(exc_info.value)
    assert "DB_RESOURCE_ARN" in message
    assert "TAPDB_WRITER_QUEUE_URL" in message
    assert "SEMANTIC_OUTBOX_MAX_ATTEMPTS" in message


def test_dispatcher_is_wired_to_the_deployed_tapdb_queue_with_explicit_failure_controls() -> None:
    template = yaml.load(
        (REPO_ROOT / "template.yaml").read_text(encoding="utf-8"),
        Loader=_CloudFormationLoader,
    )
    resources = template["Resources"]
    outputs = template["Outputs"]

    function = resources["SemanticOutboxDispatcherFunction"]
    assert function["Type"] == "AWS::Serverless::Function"
    properties = function["Properties"]
    assert properties["CodeUri"] == "functions/semantic_outbox_dispatcher/"
    assert properties["Handler"] == "handler.handler"
    assert properties["Timeout"] == 60
    assert properties["Layers"] == ["SharedLayer"]
    assert properties["Environment"]["Variables"] == {
        "DB_RESOURCE_ARN": "AuroraCluster.DBClusterArn",
        "DB_SECRET_ARN": "DbCredentialsSecret",
        "DB_NAME": "DbName",
        "TAPDB_WRITER_QUEUE_URL": "TapdbWriterQueue",
        "SEMANTIC_OUTBOX_DISPATCHER_ID": "${AWS::StackName}-semantic-outbox-dispatcher",
        "SEMANTIC_OUTBOX_BATCH_SIZE": "25",
        "SEMANTIC_OUTBOX_LEASE_SECONDS": "120",
        "SEMANTIC_OUTBOX_MAX_ATTEMPTS": "5",
        "SEMANTIC_OUTBOX_RETRY_SECONDS": "60",
    }

    statements = properties["Policies"][1]["Statement"]
    assert statements == [
        {
            "Effect": "Allow",
            "Action": [
                "rds-data:ExecuteStatement",
                "rds-data:BeginTransaction",
                "rds-data:CommitTransaction",
                "rds-data:RollbackTransaction",
            ],
            "Resource": ["AuroraCluster.DBClusterArn"],
        },
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": ["DbCredentialsSecret"],
        },
        {
            "Effect": "Allow",
            "Action": ["sqs:SendMessage"],
            "Resource": ["TapdbWriterQueue.Arn"],
        },
    ]

    assert "Events" not in properties
    schedule = resources["SemanticOutboxDispatcherSchedule"]
    assert schedule == {
        "Type": "AWS::Events::Rule",
        "Properties": {
            "Description": "Drain committed semantic outbox rows into the TapDB writer queue.",
            "ScheduleExpression": "rate(1 minute)",
            "State": "ENABLED",
            "Targets": [
                {
                    "Arn": "SemanticOutboxDispatcherFunction.Arn",
                    "Id": "SemanticOutboxDispatcher",
                    "Input": '{"action":"dispatch"}',
                    "RetryPolicy": {
                        "MaximumEventAgeInSeconds": 3600,
                        "MaximumRetryAttempts": 2,
                    },
                    "DeadLetterConfig": {
                        "Arn": "SemanticOutboxDispatcherInvocationDlq.Arn",
                    },
                }
            ],
        },
    }
    assert resources["SemanticOutboxDispatcherSchedulePermission"] == {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": "SemanticOutboxDispatcherFunction",
            "Principal": "events.amazonaws.com",
            "SourceArn": "SemanticOutboxDispatcherSchedule.Arn",
        },
    }
    assert resources["SemanticOutboxDispatcherInvocationDlqPolicy"] == {
        "Type": "AWS::SQS::QueuePolicy",
        "Properties": {
            "Queues": ["SemanticOutboxDispatcherInvocationDlq"],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowSemanticOutboxDispatcherSchedule",
                        "Effect": "Allow",
                        "Principal": {"Service": "events.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": "SemanticOutboxDispatcherInvocationDlq.Arn",
                        "Condition": {
                            "ArnEquals": {
                                "aws:SourceArn": "SemanticOutboxDispatcherSchedule.Arn",
                            }
                        },
                    }
                ],
            },
        },
    }

    dlq = resources["SemanticOutboxDispatcherInvocationDlq"]
    assert dlq["Type"] == "AWS::SQS::Queue"
    assert dlq["Properties"] == {
        "MessageRetentionPeriod": 1209600,
        "SqsManagedSseEnabled": True,
    }
    assert resources["SemanticOutboxDispatcherErrorsAlarm"]["Properties"]["MetricName"] == "Errors"
    assert (
        resources["SemanticOutboxDispatcherDlqAlarm"]["Properties"]["MetricName"]
        == "ApproximateNumberOfMessagesVisible"
    )
    assert resources["TapdbWriterDlqAlarm"]["Properties"]["MetricName"] == "ApproximateNumberOfMessagesVisible"
    assert resources["TapdbWriterQueueAgeAlarm"]["Properties"]["MetricName"] == "ApproximateAgeOfOldestMessage"
    assert outputs["SemanticOutboxDispatcherFunctionName"]["Value"] == "SemanticOutboxDispatcherFunction"
    assert outputs["SemanticOutboxDispatcherInvocationDlqUrl"]["Value"] == "SemanticOutboxDispatcherInvocationDlq"


def test_claim_is_atomic_lease_with_expired_dispatch_recovery_and_attempt_record() -> None:
    db = FakeDatabase()

    claims = dispatcher.claim_pending(db, _config())

    assert len(claims) == 1
    sql, params, transaction_id = db.calls[0]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "status = 'dispatching' AND lease_expires_at <= now()" in sql
    assert "INSERT INTO semantic_outbox_dispatch_attempts" in sql
    assert "attempt_count = outbox.attempt_count + 1" in sql
    assert "dispatch_cycle_attempt_count = outbox.dispatch_cycle_attempt_count + 1" in sql
    assert params["dispatcher_id"] == _config().dispatcher_id
    assert transaction_id == "transaction-1"
    assert db.commits == ["transaction-1"]
    assert db.rollbacks == []


def test_dispatch_sends_exact_persisted_body_and_records_queue_receipt() -> None:
    db = FakeDatabase()
    queue = FakeQueue()

    result = dispatcher.dispatch_once(db, queue, _config())

    assert result == dispatcher.DispatchBatchResult(claimed=1, published=1, failed=0, dead_lettered=0)
    assert queue.calls == [{"QueueUrl": _config().queue_url, "MessageBody": _body(_payload())}]
    publish_sql, publish_params, _ = db.calls[1]
    assert "semantic_outbox_dispatch_attempts" in publish_sql
    assert publish_params["queue_message_id"] == "message-1"
    assert json.loads(queue.calls[0]["MessageBody"])["idempotency_key"] == IDEMPOTENCY_KEY


@pytest.mark.parametrize("status", ["failed", "dead_lettered"])
def test_dispatch_failure_records_retry_or_dead_letter_state(status: str) -> None:
    db = FakeDatabase(failure_status=status)
    queue = FakeQueue(RuntimeError("SQS unavailable"))

    with pytest.raises(dispatcher.DispatchBatchError) as exc_info:
        dispatcher.dispatch_once(db, queue, _config())

    result = exc_info.value.result
    assert result.failed == (1 if status == "failed" else 0)
    assert result.dead_lettered == (1 if status == "dead_lettered" else 0)
    failure_sql, failure_params, _ = db.calls[1]
    assert "semantic_outbox_dispatch_attempts" in failure_sql
    assert "semantic_sync_status" in failure_sql
    assert failure_params["last_error"] == "RuntimeError: SQS unavailable"


def test_corrupt_persisted_payload_rolls_back_claim_transaction() -> None:
    db = FakeDatabase(invalid_checksum=True)

    with pytest.raises(dispatcher.SemanticOutboxDispatcherError, match="checksum mismatch"):
        dispatcher.claim_pending(db, _config())

    assert db.commits == []
    assert db.rollbacks == ["transaction-1"]


def test_dead_letter_reconciliation_is_explicit_audited_and_atomic() -> None:
    db = FakeDatabase()

    count = dispatcher.reconcile_dead_letters(
        db,
        semantic_outbox_ids=[OUTBOX_ID],
        requested_by="operator-subject",
        reason="Owning TapDB service recovered",
    )

    assert count == 1
    sql, params, transaction_id = db.calls[0]
    assert "status = 'dead_lettered'" in sql
    assert "INSERT INTO semantic_outbox_reconciliations" in sql
    assert "dispatch_cycle_attempt_count = 0" in sql
    assert "SET status = 'pending'" in sql
    assert params["requested_by"] == "operator-subject"
    assert transaction_id == "transaction-1"
    assert db.commits == ["transaction-1"]


def test_handler_rejects_implicit_or_unknown_invocations() -> None:
    with pytest.raises(dispatcher.SemanticOutboxDispatcherError, match="must request"):
        dispatcher.handler({}, None, config=_config(), db=FakeDatabase(), queue=FakeQueue())
