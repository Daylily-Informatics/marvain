from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Protocol

import boto3
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SemanticOutboxDispatcherError(RuntimeError):
    pass


class DispatcherDatabase(Protocol):
    def begin(self) -> str: ...

    def query(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]: ...

    def commit(self, transaction_id: str) -> None: ...

    def rollback(self, transaction_id: str) -> None: ...


class QueueClient(Protocol):
    def send_message(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass(frozen=True)
class DispatcherConfig:
    db_resource_arn: str
    db_secret_arn: str
    db_name: str
    queue_url: str
    dispatcher_id: str
    batch_size: int
    lease_seconds: int
    max_attempts: int
    retry_seconds: int


@dataclass(frozen=True)
class OutboxClaim:
    semantic_outbox_id: str
    semantic_sync_id: str
    agent_id: str
    idempotency_key: str
    claim_token: str
    attempt_number: int
    cycle_attempt_number: int
    payload_sha256: str
    message_body: str


@dataclass(frozen=True)
class DispatchBatchResult:
    claimed: int
    published: int
    failed: int
    dead_lettered: int

    def as_dict(self) -> dict[str, int | str]:
        return {
            "status": "complete" if self.failed == 0 and self.dead_lettered == 0 else "partial_failure",
            "claimed": self.claimed,
            "published": self.published,
            "failed": self.failed,
            "dead_lettered": self.dead_lettered,
        }


class DispatchBatchError(SemanticOutboxDispatcherError):
    def __init__(self, result: DispatchBatchResult) -> None:
        self.result = result
        super().__init__(
            f"semantic outbox dispatch failed: failed={result.failed} dead_lettered={result.dead_lettered}"
        )


_CLAIM_SQL = """
WITH candidates AS (
  SELECT semantic_outbox_id
  FROM semantic_outbox
  WHERE (
      (status IN ('pending', 'failed') AND dispatch_cycle_attempt_count < :max_attempts)
      OR (status = 'dispatching' AND lease_expires_at <= now())
    )
    AND next_attempt_at <= now()
  ORDER BY next_attempt_at ASC, created_at ASC, semantic_outbox_id ASC
  FOR UPDATE SKIP LOCKED
  LIMIT :batch_size
),
claimed AS (
  UPDATE semantic_outbox AS outbox
  SET status = 'dispatching',
      attempt_count = outbox.attempt_count + 1,
      dispatch_cycle_attempt_count = outbox.dispatch_cycle_attempt_count + 1,
      claim_token = CAST(:claim_token AS uuid),
      claimed_by = :dispatcher_id,
      claimed_at = now(),
      lease_expires_at = now() + make_interval(secs => CAST(:lease_seconds AS int)),
      updated_at = now()
  FROM candidates
  WHERE outbox.semantic_outbox_id = candidates.semantic_outbox_id
  RETURNING outbox.semantic_outbox_id,
            outbox.semantic_sync_id,
            outbox.agent_id,
            outbox.idempotency_key,
            outbox.payload::text AS payload_json,
            outbox.payload_sha256,
            outbox.claim_token,
            outbox.attempt_count,
            outbox.dispatch_cycle_attempt_count,
            outbox.claimed_at
),
attempts AS (
  INSERT INTO semantic_outbox_dispatch_attempts(
    semantic_outbox_id,
    agent_id,
    attempt_number,
    claim_token,
    dispatcher_id,
    status,
    claimed_at
  )
  SELECT semantic_outbox_id,
         agent_id,
         attempt_count,
         claim_token,
         :dispatcher_id,
         'claimed',
         claimed_at
  FROM claimed
  RETURNING semantic_outbox_id, attempt_number
)
SELECT claimed.semantic_outbox_id::text AS semantic_outbox_id,
       claimed.semantic_sync_id::text AS semantic_sync_id,
       claimed.agent_id::text AS agent_id,
       claimed.idempotency_key::text AS idempotency_key,
       claimed.payload_json,
       claimed.payload_sha256,
       claimed.claim_token::text AS claim_token,
       claimed.attempt_count,
       claimed.dispatch_cycle_attempt_count
FROM claimed
JOIN attempts
  ON attempts.semantic_outbox_id = claimed.semantic_outbox_id
 AND attempts.attempt_number = claimed.attempt_count
ORDER BY claimed.semantic_outbox_id
"""

_MARK_PUBLISHED_SQL = """
WITH outbox_update AS (
  UPDATE semantic_outbox
  SET status = 'published',
      published_at = now(),
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      lease_expires_at = NULL,
      last_error = NULL,
      updated_at = now()
  WHERE semantic_outbox_id = CAST(:semantic_outbox_id AS uuid)
    AND claim_token = CAST(:claim_token AS uuid)
    AND status = 'dispatching'
  RETURNING semantic_outbox_id, attempt_count
),
attempt_update AS (
  UPDATE semantic_outbox_dispatch_attempts AS attempt
  SET status = 'published',
      queue_message_id = :queue_message_id,
      error = NULL,
      completed_at = now()
  FROM outbox_update
  WHERE attempt.semantic_outbox_id = outbox_update.semantic_outbox_id
    AND attempt.attempt_number = outbox_update.attempt_count
    AND attempt.claim_token = CAST(:claim_token AS uuid)
  RETURNING attempt.semantic_outbox_id
)
SELECT outbox_update.semantic_outbox_id::text AS semantic_outbox_id
FROM outbox_update
JOIN attempt_update USING (semantic_outbox_id)
"""

_MARK_FAILED_SQL = """
WITH outbox_update AS (
  UPDATE semantic_outbox
  SET status = CASE
        WHEN dispatch_cycle_attempt_count >= :max_attempts THEN 'dead_lettered'
        ELSE 'failed'
      END,
      next_attempt_at = CASE
        WHEN dispatch_cycle_attempt_count >= :max_attempts THEN next_attempt_at
        ELSE now() + make_interval(secs => CAST(:retry_seconds AS int))
      END,
      dead_lettered_at = CASE
        WHEN dispatch_cycle_attempt_count >= :max_attempts THEN now()
        ELSE NULL
      END,
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      lease_expires_at = NULL,
      last_error = :last_error,
      updated_at = now()
  WHERE semantic_outbox_id = CAST(:semantic_outbox_id AS uuid)
    AND claim_token = CAST(:claim_token AS uuid)
    AND status = 'dispatching'
  RETURNING semantic_outbox_id, semantic_sync_id, attempt_count, status
),
attempt_update AS (
  UPDATE semantic_outbox_dispatch_attempts AS attempt
  SET status = outbox_update.status,
      error = :last_error,
      completed_at = now()
  FROM outbox_update
  WHERE attempt.semantic_outbox_id = outbox_update.semantic_outbox_id
    AND attempt.attempt_number = outbox_update.attempt_count
    AND attempt.claim_token = CAST(:claim_token AS uuid)
  RETURNING attempt.semantic_outbox_id
),
sync_update AS (
  UPDATE semantic_sync_status AS sync
  SET status = 'dead_lettered',
      last_error = :last_error,
      updated_at = now()
  FROM outbox_update
  WHERE sync.semantic_sync_id = outbox_update.semantic_sync_id
    AND outbox_update.status = 'dead_lettered'
  RETURNING sync.semantic_sync_id
)
SELECT outbox_update.semantic_outbox_id::text AS semantic_outbox_id,
       outbox_update.status
FROM outbox_update
JOIN attempt_update USING (semantic_outbox_id)
"""

_RECONCILE_SQL = """
WITH eligible AS (
  SELECT semantic_outbox_id,
         semantic_sync_id,
         agent_id,
         attempt_count
  FROM semantic_outbox
  WHERE semantic_outbox_id = CAST(:semantic_outbox_id AS uuid)
    AND status = 'dead_lettered'
  FOR UPDATE
),
audit_insert AS (
  INSERT INTO semantic_outbox_reconciliations(
    semantic_outbox_id,
    agent_id,
    requested_by,
    reason,
    previous_attempt_count
  )
  SELECT semantic_outbox_id,
         agent_id,
         :requested_by,
         :reason,
         attempt_count
  FROM eligible
  RETURNING semantic_outbox_id
),
outbox_update AS (
  UPDATE semantic_outbox AS outbox
  SET status = 'pending',
      dispatch_cycle_attempt_count = 0,
      next_attempt_at = now(),
      claim_token = NULL,
      claimed_by = NULL,
      claimed_at = NULL,
      lease_expires_at = NULL,
      dead_lettered_at = NULL,
      reconciliation_count = outbox.reconciliation_count + 1,
      last_error = NULL,
      updated_at = now()
  FROM eligible, audit_insert
  WHERE outbox.semantic_outbox_id = eligible.semantic_outbox_id
    AND audit_insert.semantic_outbox_id = eligible.semantic_outbox_id
  RETURNING outbox.semantic_outbox_id, outbox.semantic_sync_id
),
sync_update AS (
  UPDATE semantic_sync_status AS sync
  SET status = 'pending',
      last_error = NULL,
      updated_at = now()
  FROM outbox_update
  WHERE sync.semantic_sync_id = outbox_update.semantic_sync_id
  RETURNING sync.semantic_sync_id
)
SELECT outbox_update.semantic_outbox_id::text AS semantic_outbox_id
FROM outbox_update
JOIN sync_update USING (semantic_sync_id)
"""


def _required_text(value: Any, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise SemanticOutboxDispatcherError(f"{field} is required")
    return normalized


def _positive_int(value: Any, field: str, *, maximum: int | None = None) -> int:
    try:
        parsed = int(str(value).strip())
    except (AttributeError, TypeError, ValueError) as exc:
        raise SemanticOutboxDispatcherError(f"{field} must be an integer") from exc
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        suffix = f" between 1 and {maximum}" if maximum else " positive"
        raise SemanticOutboxDispatcherError(f"{field} must be{suffix}")
    return parsed


def _required_uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(_required_text(value, field)))
    except ValueError as exc:
        raise SemanticOutboxDispatcherError(f"{field} must be a UUID") from exc


def load_dispatcher_config(env: Mapping[str, str] | None = None) -> DispatcherConfig:
    values = os.environ if env is None else env
    required = (
        "DB_RESOURCE_ARN",
        "DB_SECRET_ARN",
        "DB_NAME",
        "TAPDB_WRITER_QUEUE_URL",
        "SEMANTIC_OUTBOX_DISPATCHER_ID",
        "SEMANTIC_OUTBOX_BATCH_SIZE",
        "SEMANTIC_OUTBOX_LEASE_SECONDS",
        "SEMANTIC_OUTBOX_MAX_ATTEMPTS",
        "SEMANTIC_OUTBOX_RETRY_SECONDS",
    )
    missing = [name for name in required if not str(values.get(name) or "").strip()]
    if missing:
        raise SemanticOutboxDispatcherError(f"Missing required env vars: {', '.join(missing)}")
    return DispatcherConfig(
        db_resource_arn=_required_text(values["DB_RESOURCE_ARN"], "DB_RESOURCE_ARN"),
        db_secret_arn=_required_text(values["DB_SECRET_ARN"], "DB_SECRET_ARN"),
        db_name=_required_text(values["DB_NAME"], "DB_NAME"),
        queue_url=_required_text(values["TAPDB_WRITER_QUEUE_URL"], "TAPDB_WRITER_QUEUE_URL"),
        dispatcher_id=_required_text(values["SEMANTIC_OUTBOX_DISPATCHER_ID"], "SEMANTIC_OUTBOX_DISPATCHER_ID"),
        batch_size=_positive_int(values["SEMANTIC_OUTBOX_BATCH_SIZE"], "SEMANTIC_OUTBOX_BATCH_SIZE", maximum=100),
        lease_seconds=_positive_int(values["SEMANTIC_OUTBOX_LEASE_SECONDS"], "SEMANTIC_OUTBOX_LEASE_SECONDS"),
        max_attempts=_positive_int(values["SEMANTIC_OUTBOX_MAX_ATTEMPTS"], "SEMANTIC_OUTBOX_MAX_ATTEMPTS"),
        retry_seconds=_positive_int(values["SEMANTIC_OUTBOX_RETRY_SECONDS"], "SEMANTIC_OUTBOX_RETRY_SECONDS"),
    )


@contextmanager
def _transaction(db: DispatcherDatabase) -> Iterator[str]:
    transaction_id = db.begin()
    try:
        yield transaction_id
        db.commit(transaction_id)
    except Exception:
        db.rollback(transaction_id)
        raise


def _canonical_message_body(payload: Any, expected_sha256: str) -> str:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise SemanticOutboxDispatcherError("persisted semantic payload is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SemanticOutboxDispatcherError("persisted semantic payload must be an object")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    actual_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if actual_sha256 != _required_text(expected_sha256, "payload_sha256"):
        raise SemanticOutboxDispatcherError("persisted semantic payload checksum mismatch")
    return body


def _claim_from_row(row: Mapping[str, Any]) -> OutboxClaim:
    semantic_outbox_id = _required_uuid(row.get("semantic_outbox_id"), "semantic_outbox_id")
    semantic_sync_id = _required_uuid(row.get("semantic_sync_id"), "semantic_sync_id")
    agent_id = _required_uuid(row.get("agent_id"), "agent_id")
    idempotency_key = _required_uuid(row.get("idempotency_key"), "idempotency_key")
    claim_token = _required_uuid(row.get("claim_token"), "claim_token")
    message_body = _canonical_message_body(row.get("payload_json"), str(row.get("payload_sha256") or ""))
    payload = json.loads(message_body)
    if str(payload.get("agent_id") or "") != agent_id:
        raise SemanticOutboxDispatcherError("persisted semantic payload agent_id does not match its outbox row")
    if str(payload.get("idempotency_key") or "") != idempotency_key:
        raise SemanticOutboxDispatcherError("persisted semantic payload idempotency_key does not match its outbox row")
    return OutboxClaim(
        semantic_outbox_id=semantic_outbox_id,
        semantic_sync_id=semantic_sync_id,
        agent_id=agent_id,
        idempotency_key=idempotency_key,
        claim_token=claim_token,
        attempt_number=_positive_int(row.get("attempt_count"), "attempt_count"),
        cycle_attempt_number=_positive_int(row.get("dispatch_cycle_attempt_count"), "dispatch_cycle_attempt_count"),
        payload_sha256=str(row["payload_sha256"]),
        message_body=message_body,
    )


def claim_pending(db: DispatcherDatabase, config: DispatcherConfig, *, semantic_outbox_id: str | None = None) -> list[OutboxClaim]:
    claim_token = str(uuid.uuid4())
    sql = _CLAIM_SQL
    parameters = {
        "batch_size": config.batch_size, "claim_token": claim_token,
        "dispatcher_id": config.dispatcher_id, "lease_seconds": config.lease_seconds,
        "max_attempts": config.max_attempts,
    }
    if semantic_outbox_id is not None:
        parameters["semantic_outbox_id"] = _required_uuid(semantic_outbox_id, "semantic_outbox_id")
        sql = sql.replace("AND next_attempt_at <= now()",
                          "AND next_attempt_at <= now() AND semantic_outbox_id = CAST(:semantic_outbox_id AS uuid)")
    with _transaction(db) as transaction_id:
        rows = db.query(
            sql, parameters,
            transaction_id=transaction_id,
        )
        claims = [_claim_from_row(row) for row in rows]
        if any(claim.claim_token != claim_token for claim in claims):
            raise SemanticOutboxDispatcherError("database returned a mismatched semantic outbox claim token")
        return claims


def _require_single_row(rows: list[dict[str, Any]], operation: str) -> dict[str, Any]:
    if len(rows) != 1:
        raise SemanticOutboxDispatcherError(f"{operation} lost its semantic outbox lease")
    return rows[0]


def mark_published(
    db: DispatcherDatabase,
    *,
    claim: OutboxClaim,
    queue_message_id: str,
) -> None:
    queue_message_id = _required_text(queue_message_id, "queue_message_id")
    with _transaction(db) as transaction_id:
        rows = db.query(
            _MARK_PUBLISHED_SQL,
            {
                "semantic_outbox_id": claim.semantic_outbox_id,
                "claim_token": claim.claim_token,
                "queue_message_id": queue_message_id,
            },
            transaction_id=transaction_id,
        )
        _require_single_row(rows, "publish completion")


def mark_failed(
    db: DispatcherDatabase,
    *,
    claim: OutboxClaim,
    error: Exception,
    config: DispatcherConfig,
) -> str:
    last_error = _required_text(f"{type(error).__name__}: {error}", "dispatch error")[:2000]
    with _transaction(db) as transaction_id:
        rows = db.query(
            _MARK_FAILED_SQL,
            {
                "semantic_outbox_id": claim.semantic_outbox_id,
                "claim_token": claim.claim_token,
                "last_error": last_error,
                "max_attempts": config.max_attempts,
                "retry_seconds": config.retry_seconds,
            },
            transaction_id=transaction_id,
        )
        row = _require_single_row(rows, "dispatch failure recording")
        status = str(row.get("status") or "")
        if status not in {"failed", "dead_lettered"}:
            raise SemanticOutboxDispatcherError(f"unexpected semantic outbox failure status: {status!r}")
        return status


def dispatch_once(
    db: DispatcherDatabase,
    queue: QueueClient,
    config: DispatcherConfig,
    *,
    raise_on_failure: bool = True,
    semantic_outbox_id: str | None = None,
) -> DispatchBatchResult:
    claims = claim_pending(db, config, semantic_outbox_id=semantic_outbox_id)
    published = 0
    failed = 0
    dead_lettered = 0
    for claim in claims:
        try:
            response = queue.send_message(QueueUrl=config.queue_url, MessageBody=claim.message_body)
            message_id = _required_text(response.get("MessageId"), "SQS MessageId")
            mark_published(db, claim=claim, queue_message_id=message_id)
            published += 1
        except Exception as exc:
            status = mark_failed(db, claim=claim, error=exc, config=config)
            if status == "dead_lettered":
                dead_lettered += 1
            else:
                failed += 1
            logger.exception("Semantic outbox dispatch failed outbox_id=%s", claim.semantic_outbox_id)
    result = DispatchBatchResult(
        claimed=len(claims),
        published=published,
        failed=failed,
        dead_lettered=dead_lettered,
    )
    if raise_on_failure and (failed or dead_lettered):
        raise DispatchBatchError(result)
    return result


def reconcile_dead_letters(
    db: DispatcherDatabase,
    *,
    semantic_outbox_ids: list[str],
    requested_by: str,
    reason: str,
) -> int:
    if not semantic_outbox_ids:
        raise SemanticOutboxDispatcherError("semantic_outbox_ids is required")
    normalized_ids = [_required_uuid(value, "semantic_outbox_id") for value in semantic_outbox_ids]
    if len(set(normalized_ids)) != len(normalized_ids):
        raise SemanticOutboxDispatcherError("semantic_outbox_ids must be unique")
    requested_by = _required_text(requested_by, "requested_by")
    reason = _required_text(reason, "reason")
    with _transaction(db) as transaction_id:
        for semantic_outbox_id in normalized_ids:
            rows = db.query(
                _RECONCILE_SQL,
                {
                    "semantic_outbox_id": semantic_outbox_id,
                    "requested_by": requested_by,
                    "reason": reason,
                },
                transaction_id=transaction_id,
            )
            if len(rows) != 1:
                raise SemanticOutboxDispatcherError(f"semantic outbox row is not dead-lettered: {semantic_outbox_id}")
    return len(normalized_ids)


def _database(config: DispatcherConfig) -> RdsData:
    return RdsData(
        RdsDataEnv(
            resource_arn=config.db_resource_arn,
            secret_arn=config.db_secret_arn,
            database=config.db_name,
        )
    )


def handler(
    event: dict[str, Any],
    context: Any,
    *,
    config: DispatcherConfig | None = None,
    db: DispatcherDatabase | None = None,
    queue: QueueClient | None = None,
) -> dict[str, Any]:
    del context
    config = config or load_dispatcher_config()
    db = db or _database(config)
    action = str(event.get("action") or "").strip()
    is_scheduled_event = event.get("source") == "aws.events" and event.get("detail-type") == "Scheduled Event"
    if action == "dispatch" or is_scheduled_event:
        queue = queue or boto3.client("sqs")
        return dispatch_once(db, queue, config).as_dict()
    if action == "dispatch_one":
        queue = queue or boto3.client("sqs")
        return dispatch_once(db, queue, config,
                             semantic_outbox_id=_required_uuid(event.get("semantic_outbox_id"), "semantic_outbox_id")).as_dict()
    if action == "reconcile_dead_letter":
        raw_ids = event.get("semantic_outbox_ids")
        if not isinstance(raw_ids, list):
            raise SemanticOutboxDispatcherError("semantic_outbox_ids must be a list")
        reconciled = reconcile_dead_letters(
            db,
            semantic_outbox_ids=[str(value) for value in raw_ids],
            requested_by=str(event.get("requested_by") or ""),
            reason=str(event.get("reason") or ""),
        )
        return {"status": "reconciled", "reconciled": reconciled}
    raise SemanticOutboxDispatcherError("event must request dispatch or reconcile_dead_letter")
