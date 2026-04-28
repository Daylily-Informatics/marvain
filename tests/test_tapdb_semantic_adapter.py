from __future__ import annotations

import sys
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore


class FakeColumn:
    def __init__(self, name: str) -> None:
        self.name = name

    def __eq__(self, other: object) -> tuple[str, str, object]:  # type: ignore[override]
        return ("eq", self.name, other)

    def is_(self, other: object) -> tuple[str, str, object]:
        return ("is", self.name, other)

    def ilike(self, other: object) -> tuple[str, str, object]:
        return ("ilike", self.name, other)

    def desc(self) -> tuple[str, str]:
        return ("desc", self.name)


class FakeGenericInstance:
    is_deleted = FakeColumn("is_deleted")
    domain_code = FakeColumn("domain_code")
    category = FakeColumn("category")
    type = FakeColumn("type")
    subtype = FakeColumn("subtype")
    version = FakeColumn("version")
    name = FakeColumn("name")
    euid = FakeColumn("euid")
    created_dt = FakeColumn("created_dt")


class FakeInstance:
    def __init__(
        self,
        *,
        euid: str,
        name: str,
        category: str = "MVN",
        type_name: str = "agent",
        subtype: str = "companion",
        version: str = "1.0",
        properties: dict[str, object] | None = None,
    ) -> None:
        self.euid = euid
        self.uid = abs(hash(euid)) % 100000
        self.name = name
        self.category = category
        self.type = type_name
        self.subtype = subtype
        self.version = version
        self.bstatus = str((properties or {}).get("lifecycle_state") or "created")
        self.json_addl = {"properties": dict(properties or {})}


class FakeLineage:
    def __init__(self, euid: str) -> None:
        self.euid = euid


class FakeQuery:
    def __init__(self, rows: list[FakeInstance], recorder: list[object]) -> None:
        self.rows = rows
        self.recorder = recorder

    def filter(self, *criteria: object) -> "FakeQuery":
        self.recorder.extend(criteria)
        return self

    def order_by(self, *criteria: object) -> "FakeQuery":
        self.recorder.extend(criteria)
        return self

    def limit(self, value: int) -> "FakeQuery":
        self.recorder.append(("limit", value))
        return self

    def all(self) -> list[FakeInstance]:
        return list(self.rows)


class FakeSession:
    def __init__(self) -> None:
        self.instances_by_euid: dict[str, FakeInstance] = {}
        self.query_filters: list[object] = []
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1

    def query(self, model: object) -> FakeQuery:
        assert model is FakeGenericInstance
        return FakeQuery(list(self.instances_by_euid.values()), self.query_filters)


class FakeConnection:
    last: "FakeConnection | None" = None

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.session = FakeSession()
        self.commits: list[bool] = []
        FakeConnection.last = self

    @contextmanager
    def session_scope(self, *, commit: bool = False):
        self.commits.append(commit)
        yield self.session


class FakeTemplateManager:
    def __init__(self, *, config_path: Path) -> None:
        self.config_path = config_path


class FakeFactory:
    last: "FakeFactory | None" = None

    def __init__(self, template_manager: FakeTemplateManager, *, domain_code: str) -> None:
        self.template_manager = template_manager
        self.domain_code = domain_code
        self.created: list[dict[str, object]] = []
        self.linked: list[dict[str, object]] = []
        FakeFactory.last = self

    def create_instance(
        self,
        session: FakeSession,
        *,
        template_code: str,
        name: str,
        properties: dict[str, object],
        create_children: bool,
    ) -> FakeInstance:
        self.created.append(
            {
                "template_code": template_code,
                "name": name,
                "properties": properties,
                "create_children": create_children,
            }
        )
        category, type_name, subtype, version = template_code.strip("/").split("/")
        instance = FakeInstance(
            euid=f"EUID-{len(session.instances_by_euid) + 1}",
            name=name,
            category=category,
            type_name=type_name,
            subtype=subtype,
            version=version,
            properties=properties,
        )
        session.instances_by_euid[instance.euid] = instance
        return instance

    def link_instances(
        self,
        session: FakeSession,
        parent: FakeInstance,
        child: FakeInstance,
        *,
        relationship_type: str,
    ) -> FakeLineage:
        self.linked.append({"parent": parent.euid, "child": child.euid, "relationship_type": relationship_type})
        return FakeLineage(f"LIN-{len(self.linked)}")


@pytest.fixture
def fake_tapdb_modules(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    seed_calls: list[dict[str, object]] = []
    graph_calls: list[dict[str, object]] = []

    def find_object_by_euid(session: FakeSession, euid: str) -> tuple[FakeInstance | None, str | None]:
        instance = session.instances_by_euid.get(euid)
        return instance, "instance" if instance is not None else None

    def build_graph_payload(obj: FakeInstance, *, record_type: str, service_name: str, depth: int) -> dict[str, object]:
        graph_calls.append(
            {
                "euid": obj.euid,
                "record_type": record_type,
                "service_name": service_name,
                "depth": depth,
            }
        )
        return {"schema": "dag:v1", "nodes": [{"id": obj.euid}], "edges": []}

    def load_template_configs(template_dir: Path) -> list[dict[str, str]]:
        return [{"template_dir": str(template_dir)}]

    def find_tapdb_core_config_dir() -> Path:
        return Path("/tapdb/core")

    def seed_templates(session: FakeSession, templates: list[dict[str, str]], **kwargs: object) -> SimpleNamespace:
        seed_calls.append({"templates": templates, **kwargs})
        return SimpleNamespace(templates_loaded=1, inserted=1, updated=2, skipped=3, prefixes_ensured=4)

    modules = {
        "daylily_tapdb.connection": types.SimpleNamespace(TAPDBConnection=FakeConnection),
        "daylily_tapdb.factory.instance": types.SimpleNamespace(InstanceFactory=FakeFactory),
        "daylily_tapdb.templates.manager": types.SimpleNamespace(TemplateManager=FakeTemplateManager),
        "daylily_tapdb.models.instance": types.SimpleNamespace(generic_instance=FakeGenericInstance),
        "daylily_tapdb.services.object_lookup": types.SimpleNamespace(find_object_by_euid=find_object_by_euid),
        "daylily_tapdb.services.graph_payloads": types.SimpleNamespace(build_graph_payload=build_graph_payload),
        "daylily_tapdb.templates.loader": types.SimpleNamespace(
            find_tapdb_core_config_dir=find_tapdb_core_config_dir,
            load_template_configs=load_template_configs,
            seed_templates=seed_templates,
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return {"seed_calls": seed_calls, "graph_calls": graph_calls}


def test_daylily_tapdb_store_uses_factory_lookup_query_seed_and_graph_patterns(
    fake_tapdb_modules: dict[str, object],
) -> None:
    store = DaylilyTapdbSemanticStore(
        db_url="postgresql+psycopg2://user:pass@example.test/tapdb",
        domain_code="M",
        owner_repo_name="marvain",
        template_dir=Path("/templates"),
    )

    seed_result = store.seed_templates(overwrite=True)
    agent = store.create_object(
        template_code="MVN/agent/companion/1.0/",
        name="agent-one",
        properties={"agent_id": "agent-1"},
        lifecycle_state="active",
    )
    memory = store.create_object(
        template_code="MVN/memory/committed/1.0/",
        name="memory-one",
        properties={"memory_id": "memory-1"},
        lifecycle_state="committed",
    )
    edge = store.link_objects(
        parent_semantic_id=agent.semantic_id,
        child_semantic_id=memory.semantic_id,
        relationship_type="REMEMBERS",
    )
    lookup = store.get_object(agent.semantic_id)
    query_results = store.query_objects(
        template_code="MVN/agent/companion/1.0/",
        name_like="agent",
        euid_like="EUID",
        limit=999,
    )
    graph = store.graph_for(agent.semantic_id, max_depth=2)

    assert seed_result.inserted == 1
    assert fake_tapdb_modules["seed_calls"]
    assert agent.template_code == "MVN/agent/companion/1.0/"
    assert agent.lifecycle_state == "active"
    assert memory.template_code == "MVN/memory/committed/1.0/"
    assert edge.relationship_type == "REMEMBERS"
    assert lookup == agent
    assert query_results
    assert graph["schema"] == "dag:v1"

    connection = FakeConnection.last
    factory = FakeFactory.last
    assert connection is not None
    assert factory is not None
    assert connection.kwargs["app_username"] == "marvain.tapdb_writer"
    assert connection.commits == [True, True, True, True, False, False, False]
    assert factory.created[0]["create_children"] is False
    assert factory.linked == [
        {"parent": agent.semantic_id, "child": memory.semantic_id, "relationship_type": "REMEMBERS"}
    ]
    assert ("eq", "domain_code", "M") in connection.session.query_filters
    assert ("eq", "category", "MVN") in connection.session.query_filters
    assert ("eq", "type", "agent") in connection.session.query_filters
    assert ("eq", "subtype", "companion") in connection.session.query_filters
    assert ("eq", "version", "1.0") in connection.session.query_filters
    assert ("ilike", "name", "%agent%") in connection.session.query_filters
    assert ("ilike", "euid", "%EUID%") in connection.session.query_filters
    assert ("limit", 200) in connection.session.query_filters
    assert fake_tapdb_modules["graph_calls"] == [
        {"euid": agent.semantic_id, "record_type": "instance", "service_name": "marvain", "depth": 2}
    ]


def test_daylily_tapdb_store_rejects_invalid_template_code(fake_tapdb_modules: dict[str, object]) -> None:
    store = DaylilyTapdbSemanticStore(db_url="postgresql+psycopg2://user:pass@example.test/tapdb")

    with pytest.raises(ValueError, match="template_code"):
        store.query_objects(template_code="MVN/agent")
