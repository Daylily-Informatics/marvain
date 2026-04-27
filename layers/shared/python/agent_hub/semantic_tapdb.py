"""Marvain-owned TapDB semantic boundary.

All Marvain code outside this module should treat TapDB as a semantic object
and lineage service through this adapter or the mounted TapDB web/DAG APIs.
The adapter delegates canonical object and graph work to supported daylily-tapdb
interfaces and fails loudly when a required public interface is unavailable.
"""

from __future__ import annotations

import copy
import os
import re
import uuid
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


class InMemoryTapdbSemanticStore:
    """Deterministic TapDB semantic store for local tests and mocked smoke runs."""

    def __init__(self) -> None:
        self.objects: dict[str, SemanticObject] = {}
        self.edges: list[SemanticEdge] = []

    def create_object(
        self,
        *,
        template_code: str,
        name: str,
        properties: dict[str, Any],
        lifecycle_state: str,
    ) -> SemanticObject:
        semantic_id = f"MVN-{uuid.uuid4()}"
        payload = copy.deepcopy(properties)
        payload["lifecycle_state"] = lifecycle_state
        obj = SemanticObject(
            semantic_id=semantic_id,
            template_code=template_code,
            name=name,
            properties=payload,
            lifecycle_state=lifecycle_state,
        )
        self.objects[semantic_id] = obj
        return obj

    def link_objects(
        self,
        *,
        parent_semantic_id: str,
        child_semantic_id: str,
        relationship_type: str,
    ) -> SemanticEdge:
        if parent_semantic_id not in self.objects:
            raise KeyError(f"unknown parent semantic object: {parent_semantic_id}")
        if child_semantic_id not in self.objects:
            raise KeyError(f"unknown child semantic object: {child_semantic_id}")
        edge = SemanticEdge(
            edge_id=f"MVN-EDGE-{uuid.uuid4()}",
            parent_semantic_id=parent_semantic_id,
            child_semantic_id=child_semantic_id,
            relationship_type=relationship_type,
        )
        self.edges.append(edge)
        return edge

    def graph_for(self, semantic_id: str, *, max_depth: int = 3) -> dict[str, Any]:
        if semantic_id not in self.objects:
            raise KeyError(f"unknown semantic object: {semantic_id}")
        seen = {semantic_id}
        frontier = {semantic_id}
        selected_edges: list[SemanticEdge] = []
        for _ in range(max(0, int(max_depth))):
            next_frontier: set[str] = set()
            for edge in self.edges:
                if edge.parent_semantic_id in frontier or edge.child_semantic_id in frontier:
                    selected_edges.append(edge)
                    if edge.parent_semantic_id not in seen:
                        next_frontier.add(edge.parent_semantic_id)
                    if edge.child_semantic_id not in seen:
                        next_frontier.add(edge.child_semantic_id)
            if not next_frontier:
                break
            seen.update(next_frontier)
            frontier = next_frontier
        return {
            "nodes": [self.objects[item].__dict__ for item in sorted(seen)],
            "edges": [edge.__dict__ for edge in selected_edges],
        }


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
    """Production TapDB adapter using public daylily-tapdb APIs."""

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
                template_code=template_code,
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
        link_by_euid = getattr(self.factory, "link_instances_by_euid", None)
        if link_by_euid is None:
            raise RuntimeError("daylily-tapdb public API missing: InstanceFactory.link_instances_by_euid")
        with self.connection.session_scope(commit=True) as session:
            lineage = link_by_euid(
                session,
                parent_euid=parent_semantic_id,
                child_euid=child_semantic_id,
                relationship_type=relationship_type,
            )
        return SemanticEdge(
            edge_id=str(lineage.euid),
            parent_semantic_id=parent_semantic_id,
            child_semantic_id=child_semantic_id,
            relationship_type=relationship_type,
        )

    def graph_for(self, semantic_id: str, *, max_depth: int = 3) -> dict[str, Any]:
        from daylily_tapdb.lineage import get_lineage_graph

        with self.connection.session_scope(commit=False) as session:
            graph = get_lineage_graph(session, semantic_id, max_depth=max_depth)
            return {
                "nodes": [node.__dict__ for node in graph.nodes],
                "edges": [edge.__dict__ for edge in graph.edges],
            }
