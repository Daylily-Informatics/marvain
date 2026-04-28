"""Marvain-owned TapDB semantic boundary.

All Marvain code outside this module should treat TapDB as a semantic object
and lineage service through this adapter or the mounted TapDB web/DAG APIs.
This adapter intentionally uses the established TapDB/Bloom package patterns
for template-backed instance creation, linking, ORM queries, template seeding,
EUID lookup, and graph payloads.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote_plus

MARVAIN_TAPDB_DOMAIN_CODE = "M"
MARVAIN_TAPDB_OWNER_REPO = "marvain"
_MERIDIAN_PREFIX_RE = re.compile(r"^[0-9A-HJ-KMNP-TV-Z]{1,4}$")


def _find_template_root() -> Path:
    here = Path(__file__).resolve()
    candidates: list[Path] = []
    env_root = os.getenv("MARVAIN_TAPDB_TEMPLATE_ROOT")
    if env_root:
        candidates.append(Path(env_root))
    candidates.extend(parent / "tapdb_templates" for parent in (here.parent, *here.parents))
    for candidate in candidates:
        if (candidate / "MVN" / "marvain.json").exists():
            return candidate
    return candidates[0] if candidates else here.parent / "tapdb_templates"


MARVAIN_TAPDB_TEMPLATE_ROOT = _find_template_root()
MARVAIN_TAPDB_TEMPLATE_DIR = MARVAIN_TAPDB_TEMPLATE_ROOT
MARVAIN_TAPDB_DOMAIN_REGISTRY = MARVAIN_TAPDB_TEMPLATE_ROOT / "domain_code_registry.json"
MARVAIN_TAPDB_PREFIX_REGISTRY = MARVAIN_TAPDB_TEMPLATE_ROOT / "prefix_ownership_registry.json"

TEMPLATE_CODES: dict[str, str] = {
    "agent": "MVN/agent/companion/1.0/",
    "person": "MVN/person/human/1.0/",
    "account": "MVN/account/user/1.0/",
    "location": "MVN/location/physical_site/1.0/",
    "space": "MVN/space/physical_room/1.0/",
    "device": "MVN/device/satellite/1.0/",
    "capability": "MVN/device/capability/1.0/",
    "session": "MVN/session/conversation/1.0/",
    "event_transcript": "MVN/event/transcript/1.0/",
    "event_sensor": "MVN/event/sensor/1.0/",
    "memory_candidate": "MVN/memory/candidate/1.0/",
    "memory_committed": "MVN/memory/committed/1.0/",
    "memory_tombstone": "MVN/memory/tombstone/1.0/",
    "recognition_observation": "MVN/recognition/observation/1.0/",
    "recognition_hypothesis": "MVN/recognition/identity_hypothesis/1.0/",
    "presence_assertion": "MVN/presence/assertion/1.0/",
    "consent_grant": "MVN/policy/consent_grant/1.0/",
    "artifact_reference": "MVN/artifact/reference/1.0/",
    "action_proposal": "MVN/action/proposal/1.0/",
    "action_approval": "MVN/action/approval/1.0/",
    "action_execution": "MVN/action/execution/1.0/",
    "action_result": "MVN/action/result/1.0/",
    "persona": "MVN/persona/agent_persona/1.0/",
}


@dataclass(frozen=True)
class SemanticObject:
    """TapDB semantic instance summary returned to Marvain callers."""

    semantic_id: str
    template_code: str
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    lifecycle_state: str = "created"


@dataclass(frozen=True)
class SemanticEdge:
    """TapDB lineage edge summary returned to Marvain callers."""

    edge_id: str
    parent_semantic_id: str
    child_semantic_id: str
    relationship_type: str


@dataclass(frozen=True)
class TemplateValidationResult:
    templates_loaded: int
    issues: list[str]


@dataclass(frozen=True)
class TemplateSeedResult:
    templates_loaded: int
    inserted: int
    updated: int
    skipped: int
    prefixes_ensured: int


class TapdbSemanticStore(Protocol):
    """Narrow interface used by Marvain domain services."""

    def create_object(
        self,
        *,
        template_code: str,
        name: str,
        properties: dict[str, Any],
        lifecycle_state: str,
    ) -> SemanticObject: ...

    def link_objects(
        self,
        *,
        parent_semantic_id: str,
        child_semantic_id: str,
        relationship_type: str,
    ) -> SemanticEdge: ...

    def graph_for(self, semantic_id: str, *, max_depth: int = 3) -> dict[str, Any]: ...


def validate_marvain_template_pack() -> TemplateValidationResult:
    from daylily_tapdb.templates.loader import validate_template_configs

    templates, issues = validate_template_configs(MARVAIN_TAPDB_TEMPLATE_DIR, strict=True)
    return TemplateValidationResult(
        templates_loaded=len(templates),
        issues=[
            f"{issue.level}: {issue.source_file or '<unknown>'}: {issue.template_code or '<pack>'}: {issue.message}"
            for issue in issues
        ],
    )


def _build_secret_db_url(*, secret_arn: str, host: str, port: int, database: str, region: str) -> str:
    import json

    import boto3

    client = boto3.client("secretsmanager", region_name=region)
    payload = client.get_secret_value(SecretId=secret_arn)
    secret = json.loads(payload["SecretString"])
    username = str(secret.get("username") or "agenthub")
    password = str(secret["password"])
    return (
        f"postgresql+psycopg2://{quote_plus(username)}:{quote_plus(password)}"
        f"@{host}:{int(port)}/{database}?sslmode=require"
    )


class DaylilyTapdbSemanticStore:
    """Production TapDB repository boundary using established TapDB/Bloom patterns."""

    def __init__(
        self,
        *,
        db_url: str,
        domain_code: str = MARVAIN_TAPDB_DOMAIN_CODE,
        owner_repo_name: str = MARVAIN_TAPDB_OWNER_REPO,
        template_dir: Path = MARVAIN_TAPDB_TEMPLATE_DIR,
    ) -> None:
        from daylily_tapdb.connection import TAPDBConnection
        from daylily_tapdb.factory.instance import InstanceFactory
        from daylily_tapdb.templates.manager import TemplateManager

        self.domain_code = domain_code
        self.owner_repo_name = owner_repo_name
        self.template_dir = template_dir
        self.connection = TAPDBConnection(
            db_url=db_url,
            domain_code=domain_code,
            owner_repo_name=owner_repo_name,
            app_username="marvain.tapdb_writer",
        )
        self.template_manager = TemplateManager(config_path=template_dir)
        self.factory = InstanceFactory(self.template_manager, domain_code=domain_code)

    @staticmethod
    def _template_code(obj: Any) -> str:
        return (
            "/".join(
                str(getattr(obj, field_name, "") or "").strip("/")
                for field_name in ("category", "type", "subtype", "version")
            )
            + "/"
        )

    @classmethod
    def _semantic_object_from_instance(cls, instance: Any) -> SemanticObject:
        json_addl = getattr(instance, "json_addl", None) or {}
        properties = json_addl.get("properties") if isinstance(json_addl, dict) else {}
        if not isinstance(properties, dict):
            properties = {}
        return SemanticObject(
            semantic_id=str(getattr(instance, "euid", "")),
            template_code=cls._template_code(instance),
            name=str(getattr(instance, "name", "")),
            properties=dict(properties),
            lifecycle_state=str(getattr(instance, "bstatus", "") or properties.get("lifecycle_state") or "created"),
        )

    @classmethod
    def from_environment(cls) -> "DaylilyTapdbSemanticStore":
        db_url = str(os.getenv("TAPDB_DATABASE_URL") or "").strip()
        if not db_url:
            secret_arn = str(os.environ["TAPDB_DB_SECRET_ARN"])
            host = str(os.environ["TAPDB_DB_HOST"])
            port = int(os.getenv("TAPDB_DB_PORT", "5432"))
            database = str(os.environ["TAPDB_DB_NAME"])
            region = str(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1")
            db_url = _build_secret_db_url(
                secret_arn=secret_arn,
                host=host,
                port=port,
                database=database,
                region=region,
            )
        return cls(
            db_url=db_url,
            domain_code=str(os.getenv("MERIDIAN_DOMAIN_CODE") or MARVAIN_TAPDB_DOMAIN_CODE),
            owner_repo_name=str(os.getenv("TAPDB_OWNER_REPO") or MARVAIN_TAPDB_OWNER_REPO),
        )

    def seed_templates(self, *, overwrite: bool) -> TemplateSeedResult:
        from daylily_tapdb.templates.loader import find_tapdb_core_config_dir, load_template_configs, seed_templates

        templates = load_template_configs(self.template_dir)
        with self.connection.session_scope(commit=True) as session:
            summary = seed_templates(
                session,
                templates,
                overwrite=overwrite,
                core_config_dir=find_tapdb_core_config_dir(),
                domain_code=self.domain_code,
                owner_repo_name=self.owner_repo_name,
                domain_registry_path=MARVAIN_TAPDB_DOMAIN_REGISTRY,
                prefix_registry_path=MARVAIN_TAPDB_PREFIX_REGISTRY,
            )
        return TemplateSeedResult(
            templates_loaded=summary.templates_loaded,
            inserted=summary.inserted,
            updated=summary.updated,
            skipped=summary.skipped,
            prefixes_ensured=summary.prefixes_ensured,
        )

    def ensure_schema(self) -> bool:
        raise RuntimeError("TapDB schema initialization must be performed by TapDB public CLI/API before Marvain use")

    def ensure_identity_prefixes(self, *, template_categories: set[str]) -> int:
        for item in template_categories:
            self._validate_prefix(item)
        raise RuntimeError("TapDB identity prefix initialization must be performed by TapDB public CLI/API")

    @staticmethod
    def _validate_prefix(value: str) -> str:
        normalized = str(value).strip().upper()
        if not _MERIDIAN_PREFIX_RE.fullmatch(normalized):
            raise ValueError(f"TapDB instance prefix is not Meridian-safe: {value!r}")
        return normalized

    def create_object(
        self,
        *,
        template_code: str,
        name: str,
        properties: dict[str, Any],
        lifecycle_state: str,
    ) -> SemanticObject:
        with self.connection.session_scope(commit=True) as session:
            instance = self.factory.create_instance(
                session,
                template_code=template_code,
                name=name,
                properties={**properties, "lifecycle_state": lifecycle_state},
                create_children=False,
            )
            instance.bstatus = lifecycle_state
            session.flush()
            return SemanticObject(
                semantic_id=str(instance.euid),
                template_code=self._template_code(instance),
                name=str(instance.name),
                properties=dict((instance.json_addl or {}).get("properties") or {}),
                lifecycle_state=str(instance.bstatus),
            )

    def link_objects(
        self,
        *,
        parent_semantic_id: str,
        child_semantic_id: str,
        relationship_type: str,
    ) -> SemanticEdge:
        from daylily_tapdb.services.object_lookup import find_object_by_euid

        with self.connection.session_scope(commit=True) as session:
            parent, parent_type = find_object_by_euid(session, parent_semantic_id)
            child, child_type = find_object_by_euid(session, child_semantic_id)
            if parent is None or parent_type != "instance":
                raise KeyError(f"unknown TapDB parent instance: {parent_semantic_id}")
            if child is None or child_type != "instance":
                raise KeyError(f"unknown TapDB child instance: {child_semantic_id}")
            lineage = self.factory.link_instances(session, parent, child, relationship_type=relationship_type)
        return SemanticEdge(
            edge_id=str(lineage.euid),
            parent_semantic_id=parent_semantic_id,
            child_semantic_id=child_semantic_id,
            relationship_type=relationship_type,
        )

    def get_object(self, semantic_id: str) -> SemanticObject | None:
        """Look up a TapDB instance EUID through TapDB's reusable object lookup service."""

        from daylily_tapdb.services.object_lookup import find_object_by_euid

        with self.connection.session_scope(commit=False) as session:
            obj, record_type = find_object_by_euid(session, semantic_id)
            if obj is None:
                return None
            if record_type != "instance":
                raise TypeError(f"TapDB EUID {semantic_id!r} is a {record_type}, not an instance")
            return self._semantic_object_from_instance(obj)

    def query_objects(
        self,
        *,
        template_code: str | None = None,
        category: str | None = None,
        type_name: str | None = None,
        subtype: str | None = None,
        version: str | None = None,
        name_like: str | None = None,
        euid_like: str | None = None,
        limit: int = 50,
    ) -> list[SemanticObject]:
        """Query TapDB instances using the same SQLAlchemy ORM pattern Bloom uses."""

        from daylily_tapdb.models.instance import generic_instance

        filters: dict[str, str] = {}
        if template_code:
            parts = [part for part in str(template_code).strip("/").split("/") if part]
            if len(parts) != 4:
                raise ValueError("template_code must have category/type/subtype/version")
            filters.update(dict(zip(("category", "type", "subtype", "version"), parts, strict=True)))
        for key, value in (
            ("category", category),
            ("type", type_name),
            ("subtype", subtype),
            ("version", version),
        ):
            if value is not None:
                filters[key] = str(value).strip()

        max_rows = max(1, min(int(limit), 200))
        with self.connection.session_scope(commit=False) as session:
            query = session.query(generic_instance).filter(
                generic_instance.is_deleted.is_(False),
                generic_instance.domain_code == self.domain_code,
            )
            for field_name, value in filters.items():
                query = query.filter(getattr(generic_instance, field_name) == value)
            if name_like:
                query = query.filter(generic_instance.name.ilike(f"%{name_like}%"))
            if euid_like:
                query = query.filter(generic_instance.euid.ilike(f"%{euid_like}%"))
            rows = query.order_by(generic_instance.created_dt.desc()).limit(max_rows).all()
            return [self._semantic_object_from_instance(row) for row in rows]

    def graph_for(self, semantic_id: str, *, max_depth: int = 3) -> dict[str, Any]:
        from daylily_tapdb.services.graph_payloads import build_graph_payload
        from daylily_tapdb.services.object_lookup import find_object_by_euid

        with self.connection.session_scope(commit=False) as session:
            obj, record_type = find_object_by_euid(session, semantic_id)
            if obj is None:
                raise KeyError(f"unknown TapDB EUID: {semantic_id}")
            return build_graph_payload(obj, record_type=str(record_type), service_name="marvain", depth=max_depth)
