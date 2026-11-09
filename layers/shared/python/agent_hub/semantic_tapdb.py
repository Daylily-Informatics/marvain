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
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Protocol
from urllib.parse import quote_plus
from uuid import UUID

MARVAIN_TAPDB_DOMAIN_CODE = "V"
MARVAIN_TAPDB_OWNER_REPO = "marvain"
_MERIDIAN_PREFIX_RE = re.compile(r"^[0-9A-HJ-KMNP-TV-Z]{1,4}$")
EXTERNAL_REFERENCE_TEMPLATE = "reference/external_identifier/tapdb_object/1.0/"
INBOX_RECEIPT_REFERENCE_SYSTEM = "marvain-tapdb-inbox"


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
    "animal": "MVN/actor/animal/1.0/",
    "actor_association": "MVN/recognition/actor_association/1.0/",
    "principal": "MVN/identity/principal/1.0/",
    "agent_run": "MVN/identity/agent_run/1.0/",
    "embodiment": "MVN/identity/embodiment/1.0/",
    "episode": "MVN/episode/encounter/1.0/",
    "memory_correction": "MVN/memory/correction/1.0/",
    "work_handoff": "MVN/work/handoff/1.0/",
    "account": "MVN/account/user/1.0/",
    "location": "MVN/location/physical_site/1.0/",
    "space": "MVN/space/physical_room/1.0/",
    "scene": "MVN/scene/situated/1.0/",
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
class GraphObjectWrite:
    key: str
    template_code: str
    name: str
    properties: dict[str, Any]
    lifecycle_state: str


@dataclass(frozen=True)
class GraphObjectRef:
    key: str | None = None
    semantic_id: str | None = None

    def __post_init__(self) -> None:
        if bool(self.key) == bool(self.semantic_id):
            raise ValueError("graph reference requires exactly one new key or persisted semantic_id")


@dataclass(frozen=True)
class GraphLinkWrite:
    parent: GraphObjectRef
    child: GraphObjectRef
    relationship_type: str


class SemanticReadView(Protocol):
    def get_object(self, semantic_id: str) -> SemanticObject: ...
    def linked_objects(self, semantic_id: str, *, relationship_type: str,
                       incoming: bool = False) -> tuple[SemanticObject, ...]: ...
    def operational_session_status(self, *, session_id: str, agent_id: str, space_id: str) -> str | None: ...


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

    def create_graph(self, *, objects: tuple[GraphObjectWrite, ...],
                     links: tuple[GraphLinkWrite, ...]) -> dict[str, SemanticObject]: ...

    def read_view(self) -> Any: ...


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


def initialize_aurora_schema(
    *, config_path: Path, host: str, port: int, username: str, password: str,
    database: str, region: str,
) -> None:
    """Apply the owning 6.0.8 schema, prefix setup and migration baseline once.

    The schema locator and two post-apply TapDB helpers are the exact private
    functions used by the 6.0.8 CLI and are version-coupled; no schema is copied here.
    """
    from daylily_tapdb.aurora.schema_deployer import AuroraSchemaDeployer
    from daylily_tapdb.cli.context import clear_cli_context, set_cli_context
    from daylily_tapdb.cli.db import (Environment, _find_schema_file,
                                      _sync_identity_prefix_config, _write_migration_baseline)

    set_cli_context(config_path=config_path, env_name="prod")
    try:
        success, output = AuroraSchemaDeployer.deploy_schema(
            host=host, port=port, user=username, database=database, region=region,
            schema_file=_find_schema_file(), iam_auth=False, password=password,
        )
        if not success:
            raise RuntimeError(f"TapDB owner schema apply failed: {output}")
        try:
            _sync_identity_prefix_config(Environment.prod)
        except Exception as exc:
            raise RuntimeError(f"TapDB schema applied, but owner prefix setup failed: {exc}") from exc
        try:
            _write_migration_baseline(Environment.prod)
        except Exception as exc:
            raise RuntimeError(f"TapDB schema and prefixes applied, but owner migration baseline failed: {exc}") from exc
    finally:
        clear_cli_context()


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

    def create_graph_in_session(
        self, session: Any, *, objects: tuple[GraphObjectWrite, ...], links: tuple[GraphLinkWrite, ...],
    ) -> dict[str, SemanticObject]:
        """Write a semantic graph in the caller's TapDB transaction.

        Keys are operation-local symbols, never canonical identifiers. The
        caller owns commit and, when retried, idempotency. Existing endpoints
        are resolved through TapDB's object lookup service.
        """
        from daylily_tapdb.services.object_lookup import find_object_by_euid

        keys = [item.key for item in objects]
        if not keys or any(not key.strip() for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("graph requires unique nonempty object keys")
        instances: dict[str, Any] = {}
        for item in objects:
            instance = self.factory.create_instance(
                session, template_code=item.template_code, name=item.name,
                properties={**item.properties, "lifecycle_state": item.lifecycle_state}, create_children=False,
            )
            instance.bstatus = item.lifecycle_state
            instances[item.key] = instance

        def resolve(ref: GraphObjectRef) -> Any:
            if ref.key is not None:
                if ref.key not in instances:
                    raise KeyError(f"unknown graph object key: {ref.key}")
                return instances[ref.key]
            obj, record_type = find_object_by_euid(session, ref.semantic_id)
            if obj is None or record_type != "instance":
                raise KeyError(f"unknown TapDB instance: {ref.semantic_id}")
            return obj

        for link in links:
            if not link.relationship_type.strip():
                raise ValueError("graph relationship_type is required")
            self.factory.link_instances(session, resolve(link.parent), resolve(link.child),
                                        relationship_type=link.relationship_type)
        session.flush()
        return {key: self._semantic_object_from_instance(instance) for key, instance in instances.items()}

    def create_graph(
        self, *, objects: tuple[GraphObjectWrite, ...], links: tuple[GraphLinkWrite, ...],
    ) -> dict[str, SemanticObject]:
        """Commit one graph atomically; callers handle retry idempotency."""
        with self.connection.session_scope(commit=True) as session:
            return self.create_graph_in_session(session, objects=objects, links=links)

    def commit_inbox_graph(
        self,
        *,
        tenant_id: UUID,
        command_id: UUID,
        command_fingerprint: str,
        build: Callable[[SemanticReadView], tuple[GraphObjectWrite, tuple[GraphLinkWrite, ...]]],
    ) -> SemanticObject:
        """Authorize and commit one command graph, returning its durable primary result."""
        from daylily_tapdb.outbox.inbox import (
            get_inbox_message_by_machine_uuid,
            mark_inbox_processed,
            mark_inbox_processing,
            receive_message,
        )

        payload = {"command_fingerprint": command_fingerprint}
        with self.connection.session_scope(commit=True) as session:
            primary, links = build(self._read_view_for_session(session))
            receipt = receive_message(
                session,
                message_machine_uuid=command_id,
                payload=payload,
                tenant_id=tenant_id,
                domain_code=self.domain_code,
                issuer_app_code=self.owner_repo_name,
                source_domain_code=self.domain_code,
                source_issuer_app_code=self.owner_repo_name,
                source_destination="marvain_dot_mcp",
            )
            receipt_id = str(receipt.receipt_machine_uuid)
            name = f"{INBOX_RECEIPT_REFERENCE_SYSTEM}:{receipt_id}"
            if receipt.status == "processed":
                existing = get_inbox_message_by_machine_uuid(session, command_id)
                if existing is None:
                    raise RuntimeError("TapDB inbox receipt is missing its command record")
                if existing.tenant_id != tenant_id or existing.payload != payload:
                    raise ValueError("The request key belongs to a different command")
                return self._inbox_graph_result(session, receipt_id=receipt_id)
            if receipt.status != "received":
                raise RuntimeError(f"TapDB inbox command has non-retryable status: {receipt.status}")

            # This command namespace commits receipt, graph and processed state together.
            mark_inbox_processing(session, command_id)
            reference = GraphObjectWrite(
                key="inbox_receipt", template_code=EXTERNAL_REFERENCE_TEMPLATE, name=name,
                properties={"root_euid": receipt_id, "external_identifier": {
                    "system": INBOX_RECEIPT_REFERENCE_SYSTEM, "target_euid": receipt_id, "href": None,
                    "base_url": None, "graph_data_path": None, "object_detail_path_template": None,
                    "auth_mode": "none",
                }}, lifecycle_state="recorded",
            )
            reference_link = GraphLinkWrite(GraphObjectRef(key=primary.key), GraphObjectRef(key=reference.key),
                                            "has_external_reference")
            result = self.create_graph_in_session(session, objects=(primary, reference), links=(*links, reference_link))
            mark_inbox_processed(session, command_id)
            return result[primary.key]

    def _inbox_graph_result(self, session: Any, *, receipt_id: str) -> SemanticObject:
        """Resolve the result of a processed command through its exact receipt reference."""
        from daylily_tapdb.models.instance import generic_instance

        reference = session.query(generic_instance).filter_by(
            is_deleted=False, domain_code=self.domain_code,
            category="reference", type="external_identifier", subtype="tapdb_object", version="1.0",
        ).filter(generic_instance.json_addl["properties"]["external_identifier"].contains({
            "system": INBOX_RECEIPT_REFERENCE_SYSTEM, "target_euid": receipt_id,
        })).one()
        edge = reference.child_of_lineages.filter_by(is_deleted=False, relationship_type="has_external_reference").one()
        return self._semantic_object_from_instance(edge.parent_instance)

    @contextmanager
    def read_view(self) -> Iterator[SemanticReadView]:
        """Read related canonical instances through TapDB in one transaction."""
        with self.connection.session_scope(commit=False) as session:
            yield self._read_view_for_session(session)

    def _read_view_for_session(self, session: Any) -> SemanticReadView:
        from daylily_tapdb.services.object_lookup import find_object_by_euid

        store = self
        class View:
            def _find(self, semantic_id: str) -> Any:
                obj, record_type = find_object_by_euid(session, semantic_id)
                if obj is None or record_type != "instance":
                    raise KeyError(f"unknown TapDB instance: {semantic_id}")
                return obj

            def get_object(self, semantic_id: str) -> SemanticObject:
                return store._semantic_object_from_instance(self._find(semantic_id))

            def linked_objects(self, semantic_id: str, *, relationship_type: str,
                               incoming: bool = False) -> tuple[SemanticObject, ...]:
                instance = self._find(semantic_id)
                relation = instance.child_of_lineages if incoming else instance.parent_of_lineages
                edges = relation.filter_by(is_deleted=False, relationship_type=relationship_type)
                attr = "parent_instance" if incoming else "child_instance"
                return tuple(store._semantic_object_from_instance(getattr(edge, attr)) for edge in edges)

            def operational_session_status(self, *, session_id: str, agent_id: str, space_id: str) -> str | None:
                from sqlalchemy import text

                # The Marvain-owned runtime row is authoritative for live session state.
                return session.execute(text("""
                    SELECT status FROM sessions
                    WHERE session_id = CAST(:session_id AS uuid)
                      AND agent_id = CAST(:agent_id AS uuid)
                      AND space_id = CAST(:space_id AS uuid)
                """), {"session_id": session_id, "agent_id": agent_id, "space_id": space_id}).scalar_one_or_none()

        return View()

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
