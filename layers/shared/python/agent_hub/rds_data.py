from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

import boto3

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RdsDataEnv:
    resource_arn: str
    secret_arn: str
    database: str


class RdsData:
    """Tiny wrapper around the Aurora/RDS Data API.

    We use this so Lambdas don't need VPC networking to reach Postgres.
    """

    def __init__(self, env: RdsDataEnv):
        self.env = env
        self.client = boto3.client("rds-data")

    @staticmethod
    def _param_value(value: Any) -> dict:
        if value is None:
            return {"isNull": True}
        if isinstance(value, bool):
            return {"booleanValue": value}
        if isinstance(value, int):
            return {"longValue": value}
        if isinstance(value, float):
            return {"doubleValue": value}
        if isinstance(value, (dict, list)):
            # store JSON as string; cast in SQL if needed
            return {"stringValue": json.dumps(value)}
        return {"stringValue": str(value)}

    @classmethod
    def build_parameters(cls, params: Mapping[str, Any] | None) -> list[dict]:
        if not params:
            return []
        out: list[dict] = []
        for k, v in params.items():
            out.append({"name": k, "value": cls._param_value(v)})
        return out

    @staticmethod
    def _field_to_python(field: dict) -> Any:
        # Data API returns one of these keys.
        for k in (
            "isNull",
            "stringValue",
            "longValue",
            "doubleValue",
            "booleanValue",
            "blobValue",
        ):
            if k in field:
                if k == "isNull":
                    return None
                return field[k]
        return None

    def execute(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
        include_result_metadata: bool = False,
    ) -> dict:
        req: dict[str, Any] = {
            "resourceArn": self.env.resource_arn,
            "secretArn": self.env.secret_arn,
            "database": self.env.database,
            "sql": sql,
            "parameters": self.build_parameters(params),
            "includeResultMetadata": include_result_metadata,
        }
        if transaction_id:
            req["transactionId"] = transaction_id
        return self.client.execute_statement(**req)

    def query(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        resp = self.execute(sql, params, transaction_id=transaction_id, include_result_metadata=True)
        meta = resp.get("columnMetadata", [])
        col_names = [m.get("name") for m in meta]
        rows: list[dict[str, Any]] = []
        for rec in resp.get("records", []) or []:
            row: dict[str, Any] = {}
            for idx, field in enumerate(rec):
                name = col_names[idx] if idx < len(col_names) else str(idx)
                row[name] = self._field_to_python(field)
            rows.append(row)
        return rows

    def begin(self) -> str:
        resp = self.client.begin_transaction(
            resourceArn=self.env.resource_arn,
            secretArn=self.env.secret_arn,
            database=self.env.database,
        )
        return resp["transactionId"]

    def commit(self, transaction_id: str) -> None:
        self.client.commit_transaction(
            resourceArn=self.env.resource_arn,
            secretArn=self.env.secret_arn,
            transactionId=transaction_id,
        )

    def rollback(self, transaction_id: str) -> None:
        self.client.rollback_transaction(
            resourceArn=self.env.resource_arn,
            secretArn=self.env.secret_arn,
            transactionId=transaction_id,
        )
