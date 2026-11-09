"""Greenfield semantic lifecycle helpers for Marvain domain objects."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_hub.memory_service import (
    MemoryAccessPolicy, MemoryLayer, MemoryPolicyConstraint, MemoryPurpose, RetentionDecision,
    TemporalMemoryCorrection, TemporalMemoryVersion, select_temporal_memory, permits_scoped_memory,
)
from agent_hub.memory_taxonomy import normalize_memory_kind
from agent_hub.semantic_tapdb import (
    EXTERNAL_REFERENCE_TEMPLATE, TEMPLATE_CODES, GraphLinkWrite, GraphObjectRef, GraphObjectWrite, SemanticObject, TapdbSemanticStore,
)


class LifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class MemoryLifecycleRecord:
    evidence: SemanticObject
    candidate: SemanticObject
    committed: SemanticObject
    recall_projection: dict[str, Any]


@dataclass(frozen=True)
class SemanticRecallRecord:
    memory: SemanticObject
    episode: SemanticObject
    evidence: tuple[SemanticObject, ...]
    superseded_by: tuple[str, ...]
    is_superseded: bool


@dataclass(frozen=True)
class ScopedMemoryExport:
    """Authorized semantic selection; artifact bytes and full graph backup are separate."""

    scene_semantic_id: str
    session_semantic_id: str
    access_at: datetime
    records: tuple[SemanticRecallRecord, ...]


@dataclass(frozen=True)
class ScopedMemoryRecoveryPlan:
    """Non-executing recovery requirements, not a restore or deletion receipt."""

    semantic_ids: tuple[str, ...]
    requires_tapdb_backup: bool = True
    requires_artifact_backup: bool = True


@dataclass(frozen=True)
class RecognitionLifecycleRecord:
    artifact: SemanticObject
    observation: SemanticObject
    hypothesis: SemanticObject
    presence_assertion: SemanticObject | None


@dataclass(frozen=True)
class ActionLifecycleRecord:
    proposal: SemanticObject
    approval: SemanticObject | None = None
    execution: SemanticObject | None = None
    result: SemanticObject | None = None


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise LifecycleError(f"{field} is required")
    return text


def _timestamp(value: datetime, field: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise LifecycleError(f"{field} must be a timezone-aware datetime")
    return value.isoformat()


def _parse_timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_require_text(value, field))
    except ValueError as exc:
        raise LifecycleError(f"{field} must be an ISO timestamp") from exc
    _timestamp(parsed, field)
    return parsed


class MarvainSemanticLifecycle:
    """High-level semantic object graph recorder.

    The service records canonical TapDB semantic objects and lineage. Fast SQL
    projections remain separate and rebuildable from these records plus source
    events/artifacts.
    """

    def __init__(self, store: TapdbSemanticStore) -> None:
        self.store = store

    def _link(self, parent: SemanticObject, child: SemanticObject, relationship: str) -> None:
        self.store.link_objects(parent_semantic_id=parent.semantic_id, child_semantic_id=child.semantic_id,
                                relationship_type=relationship)

    @staticmethod
    def _policy_links(policy: MemoryAccessPolicy, owner: SemanticObject,
                      readers: tuple[SemanticObject, ...]) -> list[tuple[SemanticObject, str]]:
        if owner.template_code != TEMPLATE_CODES["principal"] or owner.semantic_id != policy.owner_principal_id:
            raise LifecycleError("policy owner must be the referenced principal")
        if any(reader.template_code != TEMPLATE_CODES["principal"] for reader in readers):
            raise LifecycleError("policy readers must be principals")
        if {reader.semantic_id for reader in readers} != set(policy.reader_principal_ids):
            raise LifecycleError("policy readers must match the explicit audience")
        return [(owner, "OWNER_PRINCIPAL"), *((reader, "READER_PRINCIPAL") for reader in readers)]

    def _create_linked(self, *, template_code: str, name: str, properties: dict[str, Any],
                       lifecycle_state: str, edges: list[tuple[SemanticObject, str, bool]]) -> SemanticObject:
        item = GraphObjectWrite(key="object", template_code=template_code, name=name,
                                properties=properties, lifecycle_state=lifecycle_state)
        new = GraphObjectRef(key="object")
        links = []
        for endpoint, relationship, reverse in edges:
            existing = GraphObjectRef(semantic_id=endpoint.semantic_id)
            links.append(GraphLinkWrite(parent=existing if reverse else new, child=new if reverse else existing,
                                        relationship_type=relationship))
        return self.store.create_graph(objects=(item,), links=tuple(links))["object"]

    def create_actor(self, *, kind: str, name: str, properties: dict[str, Any]) -> SemanticObject:
        """Create an explicitly established actor, never an observation-derived identity."""
        templates = {"human": "person", "animal": "animal", "software_agent": "agent"}
        if kind not in templates:
            raise LifecycleError("actor kind must be human, animal, or software_agent")
        return self.store.create_object(template_code=TEMPLATE_CODES[templates[kind]],
                                        name=_require_text(name, "name"), properties=dict(properties),
                                        lifecycle_state="active")

    def record_principal(self, *, actor: SemanticObject, issuer: str, subject: str, name: str) -> SemanticObject:
        """Bind a configured authenticated subject through a typed external reference."""
        issuer = _require_text(issuer, "issuer")
        subject = _require_text(subject, "subject")
        if actor.template_code not in {TEMPLATE_CODES["person"], TEMPLATE_CODES["animal"], TEMPLATE_CODES["agent"]}:
            raise LifecycleError("principal requires an established actor")
        objects = (
            GraphObjectWrite("principal", TEMPLATE_CODES["principal"], _require_text(name, "name"), {}, "active"),
            GraphObjectWrite("external_reference", EXTERNAL_REFERENCE_TEMPLATE,
                             f"{issuer}:{subject}", {"root_euid": subject, "external_identifier": {
                                 "system": issuer, "target_euid": subject, "href": None, "base_url": None,
                                 "graph_data_path": None, "object_detail_path_template": None, "auth_mode": "none",
                             }}, "active"),
        )
        links = (
            GraphLinkWrite(GraphObjectRef(semantic_id=actor.semantic_id), GraphObjectRef(key="principal"), "AUTHENTICATED_AS"),
            GraphLinkWrite(GraphObjectRef(key="principal"), GraphObjectRef(key="external_reference"), "has_external_reference"),
        )
        return self.store.create_graph(objects=objects, links=links)["principal"]

    def record_run(self, *, actor: SemanticObject, principal: SemanticObject, run_key: str,
                   started_at: datetime, scene: SemanticObject | None = None,
                   session: SemanticObject | None = None) -> SemanticObject:
        if actor.template_code != TEMPLATE_CODES["agent"] or principal.template_code != TEMPLATE_CODES["principal"]:
            raise LifecycleError("run requires a software actor and authenticated principal")
        edges = [(actor, "HAS_RUN", True), (principal, "AUTHENTICATED_BY", False)]
        if scene is not None:
            edges.append((scene, "IN_SCENE", False))
        if session is not None:
            edges.append((session, "IN_SESSION", False))
        return self._create_linked(template_code=TEMPLATE_CODES["agent_run"], name=_require_text(run_key, "run_key"),
                                   properties={"run_key": run_key, "started_at": _timestamp(started_at, "started_at")},
                                   lifecycle_state="running", edges=edges)

    def scene_session_graph(
        self, *, space: SemanticObject, device: SemanticObject, session_key: str,
        started_at: datetime, policy: MemoryAccessPolicy, owner: SemanticObject,
        readers: tuple[SemanticObject, ...],
    ) -> tuple[tuple[GraphObjectWrite, ...], tuple[GraphLinkWrite, ...]]:
        """Build a scene and session graph for the transactional outbox writer."""
        if space.template_code != TEMPLATE_CODES["space"] or device.template_code != TEMPLATE_CODES["device"]:
            raise LifecycleError("scene requires an established space and device")
        session_key = _require_text(session_key, "session_key")
        timestamp = _timestamp(started_at, "started_at")
        policy_edges = self._policy_links(policy, owner, readers)
        objects = (
            GraphObjectWrite("scene", TEMPLATE_CODES["scene"], f"scene:{session_key}",
                             {"started_at": timestamp, "access_policy": policy.as_properties()}, "active"),
            GraphObjectWrite("session", TEMPLATE_CODES["session"], f"session:{session_key}",
                             {"started_at": timestamp}, "open"),
        )
        scene, session = GraphObjectRef(key="scene"), GraphObjectRef(key="session")
        links = [
            GraphLinkWrite(scene, GraphObjectRef(semantic_id=space.semantic_id), "IN_SPACE"),
            GraphLinkWrite(session, scene, "IN_SCENE"),
            GraphLinkWrite(session, GraphObjectRef(semantic_id=device.semantic_id), "USES_DEVICE"),
        ]
        links.extend(GraphLinkWrite(scene, GraphObjectRef(semantic_id=obj.semantic_id), relation)
                     for obj, relation in policy_edges)
        return objects, tuple(links)

    def record_embodiment(self, *, actor: SemanticObject, device: SemanticObject, name: str) -> SemanticObject:
        if actor.template_code not in {TEMPLATE_CODES["person"], TEMPLATE_CODES["animal"], TEMPLATE_CODES["agent"]}:
            raise LifecycleError("embodiment requires an established actor")
        if device.template_code != TEMPLATE_CODES["device"]:
            raise LifecycleError("embodiment requires an existing device")
        return self._create_linked(template_code=TEMPLATE_CODES["embodiment"], name=_require_text(name, "name"),
                                   properties={}, lifecycle_state="active",
                                   edges=[(actor, "HAS_EMBODIMENT", True), (device, "USES_DEVICE", False)])

    def record_situated_evidence(
        self, *, event_id: str, event_type: str, observed_at: datetime, received_at: datetime,
        scene: SemanticObject, session: SemanticObject, device: SemanticObject | None,
        attributed_actor: SemanticObject | None, detail: dict[str, Any], policy: MemoryAccessPolicy,
        owner: SemanticObject, readers: tuple[SemanticObject, ...], run: SemanticObject | None = None,
        source_principal: SemanticObject | None = None,
    ) -> SemanticObject:
        if device is None and source_principal is None:
            raise LifecycleError("evidence requires a device or authenticated source principal")
        template = TEMPLATE_CODES["event_transcript"] if event_type == "transcript_chunk" else TEMPLATE_CODES["event_sensor"]
        edges = [(scene, "IN_SCENE", False), (session, "IN_SESSION", False)]
        for endpoint, relationship in ((device, "FROM_DEVICE"), (source_principal, "AUTHENTICATED_BY"),
                                       (run, "FROM_RUN"), (attributed_actor, "ATTRIBUTED_TO")):
            if endpoint is not None:
                edges.append((endpoint, relationship, False))
        edges.extend((endpoint, relationship, False) for endpoint, relationship in self._policy_links(policy, owner, readers))
        return self._create_linked(template_code=template, name=f"event:{_require_text(event_id, 'event_id')}",
            lifecycle_state="recorded", properties={"event_id": event_id,
                "event_type": _require_text(event_type, "event_type"),
                "observed_at": _timestamp(observed_at, "observed_at"),
                "received_at": _timestamp(received_at, "received_at"), "detail": dict(detail),
                "access_policy": policy.as_properties()}, edges=edges)

    def record_episode(
        self, *, name: str, scene: SemanticObject, session: SemanticObject, participants: tuple[SemanticObject, ...],
        evidence: tuple[SemanticObject, ...], occurred_at: datetime, policy: MemoryAccessPolicy,
        owner: SemanticObject, readers: tuple[SemanticObject, ...], detail: dict[str, Any],
    ) -> SemanticObject:
        if not evidence:
            raise LifecycleError("episode requires source evidence")
        edges = [(scene, "IN_SCENE", False), (session, "IN_SESSION", False)]
        edges.extend((actor, "PARTICIPANT", False) for actor in participants)
        edges.extend((source, "DERIVED_FROM", False) for source in evidence)
        edges.extend((endpoint, relationship, False) for endpoint, relationship in self._policy_links(policy, owner, readers))
        return self._create_linked(template_code=TEMPLATE_CODES["episode"], name=_require_text(name, "name"),
            lifecycle_state="recorded", properties={"occurred_at": _timestamp(occurred_at, "occurred_at"),
                "detail": dict(detail), "access_policy": policy.as_properties()}, edges=edges)

    def actor_association_graph(
        self, *, evidence: SemanticObject, actor: SemanticObject, author_actor: SemanticObject,
        author_principal: SemanticObject, basis: str, decided_at: datetime,
        policy: MemoryAccessPolicy, owner: SemanticObject, readers: tuple[SemanticObject, ...],
        association_key: str,
    ) -> tuple[tuple[GraphObjectWrite, ...], tuple[GraphLinkWrite, ...]]:
        """Prepare an explicit animal association for the transactional writer."""
        if actor.template_code != TEMPLATE_CODES["animal"]:
            raise LifecycleError("caretaker association requires an established animal actor")
        if author_actor.template_code != TEMPLATE_CODES["person"] or author_principal.template_code != TEMPLATE_CODES["principal"]:
            raise LifecycleError("caretaker association requires a human author and authenticated principal")
        if evidence.template_code not in {TEMPLATE_CODES["recognition_observation"], TEMPLATE_CODES["event_sensor"]}:
            raise LifecycleError("association requires source observation evidence")
        edges = [(evidence, "BASED_ON"), (actor, "ASSOCIATES_ACTOR"),
                 (author_actor, "AUTHORED_BY"), (author_principal, "AUTHENTICATED_BY"),
                 *self._policy_links(policy, owner, readers)]
        item = GraphObjectWrite("association", TEMPLATE_CODES["actor_association"],
            f"actor-association:{_require_text(association_key, 'association_key')}", {"basis": _require_text(basis, "basis"),
            "decided_at": _timestamp(decided_at, "decided_at"), "access_policy": policy.as_properties()}, "asserted")
        links = tuple(GraphLinkWrite(GraphObjectRef(key="association"), GraphObjectRef(semantic_id=obj.semantic_id), relation)
                      for obj, relation in edges)
        return (item,), links

    def record_actor_association(
        self, *, evidence: SemanticObject, actor: SemanticObject, author_actor: SemanticObject,
        author_principal: SemanticObject, basis: str, decided_at: datetime,
        policy: MemoryAccessPolicy, owner: SemanticObject, readers: tuple[SemanticObject, ...],
    ) -> SemanticObject:
        """Record an explicitly authorized caretaker association as one graph."""
        objects, links = self.actor_association_graph(evidence=evidence, actor=actor, author_actor=author_actor,
            author_principal=author_principal, basis=basis, decided_at=decided_at, policy=policy, owner=owner, readers=readers,
            association_key=str(uuid.uuid4()))
        return self.store.create_graph(objects=objects, links=links)["association"]

    def correct_memory(
        self, *, original: SemanticObject, replacement: SemanticObject, author: SemanticObject,
        principal: SemanticObject, evidence: tuple[SemanticObject, ...], reason: str,
        recorded_at: datetime, effective_at: datetime, policy: MemoryAccessPolicy,
        owner: SemanticObject, readers: tuple[SemanticObject, ...],
    ) -> SemanticObject:
        if original.template_code != TEMPLATE_CODES["memory_committed"] or replacement.template_code != TEMPLATE_CODES["memory_committed"]:
            raise LifecycleError("correction requires committed original and replacement assertions")
        if original.semantic_id == replacement.semantic_id or not evidence:
            raise LifecycleError("correction requires distinct replacement and supporting evidence")
        if principal.template_code != TEMPLATE_CODES["principal"]:
            raise LifecycleError("correction requires an authenticated principal")
        policy_edges = self._policy_links(policy, owner, readers)
        new = GraphObjectRef(key="correction")
        item = GraphObjectWrite("correction", TEMPLATE_CODES["memory_correction"], f"correction:{uuid.uuid4()}",
            {"reason": _require_text(reason, "reason"), "recorded_at": _timestamp(recorded_at, "recorded_at"),
             "effective_at": _timestamp(effective_at, "effective_at"), "access_policy": policy.as_properties()}, "recorded")
        edges = [(original, "CORRECTS"), (replacement, "REPLACEMENT"), (author, "AUTHORED_BY"),
                 (principal, "AUTHENTICATED_BY"), *((source, "DERIVED_FROM") for source in evidence), *policy_edges]
        links = [GraphLinkWrite(new, GraphObjectRef(semantic_id=obj.semantic_id), relation) for obj, relation in edges]
        links.append(GraphLinkWrite(GraphObjectRef(semantic_id=replacement.semantic_id),
                                    GraphObjectRef(semantic_id=original.semantic_id), "SUPERSEDES"))
        return self.store.create_graph(objects=(item,), links=tuple(links))["correction"]

    def commit_scoped_memory(
        self, *, evidence: tuple[SemanticObject, ...], episode: SemanticObject,
        participants: tuple[SemanticObject, ...], content: str, kind: str,
        recorded_at: datetime, effective_at: datetime, policy: MemoryAccessPolicy,
        owner: SemanticObject, readers: tuple[SemanticObject, ...],
    ) -> MemoryLifecycleRecord:
        """Commit rich content and its provenance in one TapDB transaction.

        Readers must also apply the policies of every linked evidence and
        episode; this memory's audience does not widen its sources' audience.
        """
        if not evidence:
            raise LifecycleError("memory requires source evidence")
        if episode.template_code != TEMPLATE_CODES["episode"]:
            raise LifecycleError("memory requires a canonical episode")
        content = _require_text(content, "content")
        kind = normalize_memory_kind(kind)
        properties = {"content": content, "tier": kind, "recorded_at": _timestamp(recorded_at, "recorded_at"),
                      "effective_at": _timestamp(effective_at, "effective_at"), "access_policy": policy.as_properties()}
        policy_edges = self._policy_links(policy, owner, readers)
        objects = (
            GraphObjectWrite("candidate", TEMPLATE_CODES["memory_candidate"], f"candidate:{uuid.uuid4()}",
                             dict(properties), "candidate"),
            GraphObjectWrite("memory", TEMPLATE_CODES["memory_committed"], f"memory:{uuid.uuid4()}",
                             dict(properties), "committed"),
        )
        candidate, memory = GraphObjectRef(key="candidate"), GraphObjectRef(key="memory")
        links = [GraphLinkWrite(candidate, memory, "COMMITTED_AS"),
                 GraphLinkWrite(memory, GraphObjectRef(semantic_id=episode.semantic_id), "IN_EPISODE")]
        links.extend(GraphLinkWrite(candidate, GraphObjectRef(semantic_id=source.semantic_id), "DERIVED_FROM")
                     for source in evidence)
        links.extend(GraphLinkWrite(memory, GraphObjectRef(semantic_id=actor.semantic_id), "ABOUT_ACTOR")
                     for actor in participants)
        links.extend(GraphLinkWrite(memory, GraphObjectRef(semantic_id=obj.semantic_id), relation)
                     for obj, relation in policy_edges)
        links.extend(GraphLinkWrite(candidate, GraphObjectRef(semantic_id=obj.semantic_id), relation)
                     for obj, relation in policy_edges)
        result = self.store.create_graph(objects=objects, links=tuple(links))
        return MemoryLifecycleRecord(evidence=evidence[0], candidate=result["candidate"], committed=result["memory"],
                                     recall_projection={"tapdb_euid": result["memory"].semantic_id,
                                                        "tier": kind, "content": content})

    @staticmethod
    def _read_policy(view: Any, obj: SemanticObject) -> MemoryAccessPolicy:
        properties = obj.properties.get("access_policy")
        if not isinstance(properties, dict):
            raise LifecycleError(f"missing access policy on {obj.semantic_id}")
        owners = view.linked_objects(obj.semantic_id, relationship_type="OWNER_PRINCIPAL")
        readers = view.linked_objects(obj.semantic_id, relationship_type="READER_PRINCIPAL")
        if len(owners) != 1 or not readers or any(
            principal.template_code != TEMPLATE_CODES["principal"] for principal in (*owners, *readers)
        ):
            raise LifecycleError(f"missing principal policy lineage on {obj.semantic_id}")
        retention = properties.get("retention")
        purposes = properties.get("allowed_purposes")
        if not isinstance(retention, dict) or not isinstance(purposes, list):
            raise LifecycleError(f"invalid access policy on {obj.semantic_id}")
        decisions = []
        for layer in MemoryLayer:
            raw = retention.get(layer.value)
            if not isinstance(raw, dict):
                raise LifecycleError(f"missing {layer.value} retention on {obj.semantic_id}")
            expires = raw.get("expires_at")
            decisions.append((layer, RetentionDecision(
                expires_at=_parse_timestamp(expires, "expires_at") if expires is not None else None,
                retain_until_revoked=raw.get("retain_until_revoked"),
            )))
        revoked = properties.get("revoked_at")
        return MemoryAccessPolicy(owner_principal_id=owners[0].semantic_id,
            reader_principal_ids=tuple(reader.semantic_id for reader in readers),
            allowed_purposes=frozenset(MemoryPurpose(value) for value in purposes),
            raw_capture_allowed=properties.get("raw_capture_allowed"), retention=tuple(decisions),
            revoked_at=_parse_timestamp(revoked, "revoked_at") if revoked is not None else None)

    def recall_scene(
        self, *, scene_semantic_id: str, session_semantic_id: str, authenticated_principal_id: str,
        access_at: datetime, as_of: datetime, historical: bool = False,
        require_export: bool = False,
    ) -> tuple[SemanticRecallRecord, ...]:
        """Read scene/session memory, resolving policy and corrections from lineage.

        Authentication and authorization to enter the scene are established by
        the caller; this method checks the principal and every governing source
        policy for each disclosed memory at access time.
        """
        with self.store.read_view() as view:
            view.get_object(scene_semantic_id)
            view.get_object(session_semantic_id)
            principal = view.get_object(authenticated_principal_id)
            if principal.template_code != TEMPLATE_CODES["principal"] or principal.lifecycle_state != "active":
                raise LifecycleError("recall requires an active authenticated principal")
            episodes = view.linked_objects(scene_semantic_id, relationship_type="IN_SCENE", incoming=True)
            output: list[SemanticRecallRecord] = []
            for episode in episodes:
                if episode.template_code != TEMPLATE_CODES["episode"]:
                    continue
                sessions = view.linked_objects(episode.semantic_id, relationship_type="IN_SESSION")
                if not any(item.semantic_id == session_semantic_id for item in sessions):
                    continue
                episode_sources = view.linked_objects(episode.semantic_id, relationship_type="DERIVED_FROM")
                if not episode_sources:
                    raise LifecycleError(f"episode {episode.semantic_id} has no source evidence")
                memories = view.linked_objects(episode.semantic_id, relationship_type="IN_EPISODE", incoming=True)
                for memory in memories:
                    if memory.template_code != TEMPLATE_CODES["memory_committed"]:
                        continue
                    candidates = view.linked_objects(memory.semantic_id, relationship_type="COMMITTED_AS", incoming=True)
                    if len(candidates) != 1:
                        raise LifecycleError(f"memory {memory.semantic_id} requires one candidate")
                    sources = view.linked_objects(candidates[0].semantic_id, relationship_type="DERIVED_FROM")
                    if not sources:
                        raise LifecycleError(f"memory {memory.semantic_id} has no source evidence")
                    constraints = [MemoryPolicyConstraint(self._read_policy(view, memory), MemoryLayer.KNOWLEDGE),
                                   MemoryPolicyConstraint(self._read_policy(view, candidates[0]), MemoryLayer.KNOWLEDGE),
                                   MemoryPolicyConstraint(self._read_policy(view, episode), MemoryLayer.EPISODE)]
                    all_sources = {source.semantic_id: source for source in (*episode_sources, *sources)}
                    for source in all_sources.values():
                        constraints.append(MemoryPolicyConstraint(self._read_policy(view, source), MemoryLayer.ATTRIBUTED_EVENT))
                    # Replacement assertions inherit original and correction source restrictions.
                    pending = [memory]
                    seen: set[str] = set()
                    while pending:
                        current = pending.pop()
                        if current.semantic_id in seen:
                            raise LifecycleError("cyclic or repeated correction lineage")
                        seen.add(current.semantic_id)
                        incoming = view.linked_objects(current.semantic_id, relationship_type="REPLACEMENT", incoming=True)
                        for correction in incoming:
                            originals = view.linked_objects(correction.semantic_id, relationship_type="CORRECTS")
                            supporting = view.linked_objects(correction.semantic_id, relationship_type="DERIVED_FROM")
                            if len(originals) != 1 or not supporting:
                                raise LifecycleError("correction has incomplete source lineage")
                            constraints.append(MemoryPolicyConstraint(self._read_policy(view, correction), MemoryLayer.KNOWLEDGE))
                            constraints.append(MemoryPolicyConstraint(self._read_policy(view, originals[0]), MemoryLayer.KNOWLEDGE))
                            original_episodes = view.linked_objects(originals[0].semantic_id, relationship_type="IN_EPISODE")
                            original_candidates = view.linked_objects(originals[0].semantic_id,
                                                                      relationship_type="COMMITTED_AS", incoming=True)
                            if len(original_episodes) != 1 or len(original_candidates) != 1:
                                raise LifecycleError("original memory has incomplete episode or candidate lineage")
                            constraints.append(MemoryPolicyConstraint(self._read_policy(view, original_episodes[0]), MemoryLayer.EPISODE))
                            constraints.append(MemoryPolicyConstraint(self._read_policy(view, original_candidates[0]), MemoryLayer.KNOWLEDGE))
                            original_sources = (
                                *view.linked_objects(original_episodes[0].semantic_id, relationship_type="DERIVED_FROM"),
                                *view.linked_objects(original_candidates[0].semantic_id, relationship_type="DERIVED_FROM"),
                            )
                            if not original_sources:
                                raise LifecycleError("original memory has no source evidence")
                            for source in original_sources:
                                constraints.append(MemoryPolicyConstraint(self._read_policy(view, source), MemoryLayer.ATTRIBUTED_EVENT))
                            for source in supporting:
                                constraints.append(MemoryPolicyConstraint(self._read_policy(view, source), MemoryLayer.ATTRIBUTED_EVENT))
                            pending.append(originals[0])
                    tombstones = view.linked_objects(memory.semantic_id, relationship_type="TOMBSTONED_BY")
                    retracted_at = None
                    if tombstones:
                        retracted_at = min(_parse_timestamp(item.properties.get("recorded_at"), "recorded_at")
                                           for item in tombstones)
                    version = TemporalMemoryVersion(memory.semantic_id,
                        _parse_timestamp(memory.properties.get("recorded_at"), "recorded_at"),
                        _parse_timestamp(memory.properties.get("effective_at"), "effective_at"),
                        tuple(constraints), retracted_at)
                    if require_export and not permits_scoped_memory(
                        authenticated_principal_id=authenticated_principal_id, purpose=MemoryPurpose.EXPORT,
                        layer=MemoryLayer.KNOWLEDGE, policies=constraints, at=access_at,
                    ):
                        continue
                    corrections = []
                    visible_corrections = set()
                    for correction in view.linked_objects(memory.semantic_id, relationship_type="CORRECTS", incoming=True):
                        replacements = view.linked_objects(correction.semantic_id, relationship_type="REPLACEMENT")
                        if len(replacements) != 1:
                            raise LifecycleError("correction requires one replacement")
                        corrections.append(TemporalMemoryCorrection(correction.semantic_id, memory.semantic_id,
                            replacements[0].semantic_id, _parse_timestamp(correction.properties.get("recorded_at"), "recorded_at"),
                            _parse_timestamp(correction.properties.get("effective_at"), "effective_at")))
                        correction_policy = MemoryPolicyConstraint(self._read_policy(view, correction), MemoryLayer.KNOWLEDGE)
                        purpose = MemoryPurpose.HISTORY if historical else MemoryPurpose.RECALL
                        if permits_scoped_memory(authenticated_principal_id=authenticated_principal_id, purpose=purpose,
                                                 layer=MemoryLayer.KNOWLEDGE, policies=(correction_policy,), at=access_at):
                            visible_corrections.add(correction.semantic_id)
                    selected = select_temporal_memory(versions=(version,), corrections=corrections,
                        authenticated_principal_id=authenticated_principal_id, as_of=as_of,
                        access_at=access_at, historical=historical)
                    for item in selected:
                        output.append(SemanticRecallRecord(memory, episode, tuple(all_sources.values()),
                            tuple(key for key in item.superseded_by if key in visible_corrections),
                            bool(item.superseded_by)))
            return tuple(output)

    def prepare_scoped_export(
        self, *, scene_semantic_id: str, session_semantic_id: str, authenticated_principal_id: str,
        access_at: datetime, as_of: datetime, historical: bool = False,
    ) -> ScopedMemoryExport:
        records = self.recall_scene(scene_semantic_id=scene_semantic_id, session_semantic_id=session_semantic_id,
                                    authenticated_principal_id=authenticated_principal_id, access_at=access_at,
                                    as_of=as_of, historical=historical, require_export=True)
        return ScopedMemoryExport(scene_semantic_id, session_semantic_id, access_at, records)

    @staticmethod
    def plan_scoped_recovery(export: ScopedMemoryExport) -> ScopedMemoryRecoveryPlan:
        """Describe needed owning-store recovery; this selection is not a complete backup."""
        ids = {export.scene_semantic_id, export.session_semantic_id}
        for record in export.records:
            ids.update((record.memory.semantic_id, record.episode.semantic_id))
            ids.update(source.semantic_id for source in record.evidence)
        return ScopedMemoryRecoveryPlan(tuple(sorted(ids)))

    def record_event_evidence(
        self,
        *,
        event_id: str,
        agent_id: str,
        space_id: str,
        session_id: str | None,
        device_id: str | None,
        person_id: str | None,
        event_type: str,
        text: str | None = None,
    ) -> SemanticObject:
        template = (
            TEMPLATE_CODES["event_transcript"] if event_type == "transcript_chunk" else TEMPLATE_CODES["event_sensor"]
        )
        return self.store.create_object(
            template_code=template,
            name=f"event:{_require_text(event_id, 'event_id')}",
            lifecycle_state="recorded",
            properties={
                "event_id": event_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "space_id": _require_text(space_id, "space_id"),
                "session_id": session_id or "",
                "device_id": device_id or "",
                "person_id": person_id or "",
                "event_type": event_type,
                "text": text or "",
            },
        )

    def commit_memory_from_evidence(
        self,
        *,
        evidence: SemanticObject,
        agent_id: str,
        content: str,
        tier: str,
        participants: list[str] | None = None,
        subject_person_id: str | None = None,
        subject_person: SemanticObject | None = None,
        confidence: float = 1.0,
    ) -> MemoryLifecycleRecord:
        if subject_person_id and (subject_person is None or subject_person.template_code != TEMPLATE_CODES["person"]):
            raise LifecycleError("subject_person_id requires an existing canonical person")
        source_event_id = str(evidence.properties.get("event_id") or "").strip()
        if not source_event_id:
            raise LifecycleError("memory requires source event evidence")
        content_n = _require_text(content, "content")
        tier_n = normalize_memory_kind(tier)
        candidate_id = str(uuid.uuid4())
        memory_id = str(uuid.uuid4())
        candidate = self.store.create_object(
            template_code=TEMPLATE_CODES["memory_candidate"],
            name=f"memory-candidate:{candidate_id}",
            lifecycle_state="candidate",
            properties={
                "memory_candidate_id": candidate_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "source_event_id": source_event_id,
                "content": content_n,
                "tier": tier_n,
                "participants": participants or [],
                "subject_person_id": subject_person_id or "",
                "confidence": float(confidence),
            },
        )
        self.store.link_objects(
            parent_semantic_id=evidence.semantic_id,
            child_semantic_id=candidate.semantic_id,
            relationship_type="DERIVED_FROM",
        )
        committed = self.store.create_object(
            template_code=TEMPLATE_CODES["memory_committed"],
            name=f"memory:{memory_id}",
            lifecycle_state="committed",
            properties={
                "memory_id": memory_id,
                "memory_candidate_id": candidate_id,
                "agent_id": agent_id,
                "content": content_n,
                "tier": tier_n,
                "participants": participants or [],
                "subject_person_id": subject_person_id or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=candidate.semantic_id,
            child_semantic_id=committed.semantic_id,
            relationship_type="COMMITTED_AS",
        )
        if subject_person_id:
            self.store.link_objects(
                parent_semantic_id=committed.semantic_id,
                child_semantic_id=subject_person.semantic_id,
                relationship_type="ABOUT_PERSON",
            )
        recall_projection = {
            "memory_id": memory_id,
            "tier": tier_n,
            "tapdb_euid": committed.semantic_id,
            "source_event_id": source_event_id,
            "explanation": f"Memory was committed from source event {source_event_id}.",
        }
        return MemoryLifecycleRecord(
            evidence=evidence, candidate=candidate, committed=committed, recall_projection=recall_projection
        )

    def tombstone_memory(
        self,
        *,
        committed_memory: SemanticObject,
        agent_id: str,
        reason: str,
        recorded_at: datetime,
        principal: SemanticObject,
        policy: MemoryAccessPolicy,
        owner: SemanticObject,
        readers: tuple[SemanticObject, ...],
    ) -> SemanticObject:
        memory_id = _require_text(committed_memory.semantic_id, "committed_memory.semantic_id")
        if principal.template_code != TEMPLATE_CODES["principal"]:
            raise LifecycleError("tombstone requires an authenticated principal")
        edges = [(committed_memory, "TOMBSTONED_BY", True), (principal, "AUTHENTICATED_BY", False)]
        edges.extend((obj, relation, False) for obj, relation in self._policy_links(policy, owner, readers))
        return self._create_linked(
            template_code=TEMPLATE_CODES["memory_tombstone"],
            name=f"memory-tombstone:{memory_id}",
            lifecycle_state="tombstoned",
            properties={
                "memory_tombstone_id": str(uuid.uuid4()),
                "agent_id": _require_text(agent_id, "agent_id"),
                "reason": _require_text(reason, "reason"),
                "recorded_at": _timestamp(recorded_at, "recorded_at"),
                "access_policy": policy.as_properties(),
            },
            edges=edges,
        )

    def record_recognition_path(
        self,
        *,
        agent_id: str,
        space_id: str,
        device_id: str,
        artifact_ref: dict[str, Any],
        modality: str,
        candidate_person_id: str | None,
        consent_id: str | None,
        confidence: float,
        matched: bool,
    ) -> RecognitionLifecycleRecord:
        artifact_id = str(artifact_ref.get("artifact_id") or uuid.uuid4())
        artifact = self.store.create_object(
            template_code=TEMPLATE_CODES["artifact_reference"],
            name=f"artifact:{artifact_id}",
            lifecycle_state="available",
            properties={
                "artifact_id": artifact_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "bucket": str(artifact_ref.get("bucket") or ""),
                "key": str(artifact_ref.get("key") or ""),
                "media_type": str(artifact_ref.get("media_type") or modality),
            },
        )
        observation_id = str(uuid.uuid4())
        observation = self.store.create_object(
            template_code=TEMPLATE_CODES["recognition_observation"],
            name=f"recognition-observation:{observation_id}",
            lifecycle_state="observed",
            properties={
                "recognition_observation_id": observation_id,
                "agent_id": agent_id,
                "space_id": _require_text(space_id, "space_id"),
                "device_id": _require_text(device_id, "device_id"),
                "artifact_id": artifact_id,
                "modality": _require_text(modality, "modality"),
            },
        )
        self.store.link_objects(
            parent_semantic_id=artifact.semantic_id,
            child_semantic_id=observation.semantic_id,
            relationship_type="DERIVED_FROM",
        )
        if matched and not candidate_person_id:
            raise LifecycleError("matched recognition requires candidate_person_id")
        hypothesis = self.store.create_object(
            template_code=TEMPLATE_CODES["recognition_hypothesis"],
            name=f"identity-hypothesis:{uuid.uuid4()}",
            lifecycle_state="accepted" if matched else "no_match",
            properties={
                "identity_hypothesis_id": str(uuid.uuid4()),
                "recognition_observation_id": observation_id,
                "candidate_person_id": candidate_person_id or "",
                "consent_id": consent_id or "",
                "confidence": float(confidence),
            },
        )
        self.store.link_objects(
            parent_semantic_id=observation.semantic_id,
            child_semantic_id=hypothesis.semantic_id,
            relationship_type="BASED_ON",
        )
        presence = None
        if matched:
            presence = self.store.create_object(
                template_code=TEMPLATE_CODES["presence_assertion"],
                name=f"presence:{uuid.uuid4()}",
                lifecycle_state="asserted",
                properties={
                    "presence_assertion_id": str(uuid.uuid4()),
                    "agent_id": agent_id,
                    "space_id": space_id,
                    "person_id": candidate_person_id,
                    "confidence": float(confidence),
                },
            )
            self.store.link_objects(
                parent_semantic_id=hypothesis.semantic_id,
                child_semantic_id=presence.semantic_id,
                relationship_type="BASED_ON",
            )
        return RecognitionLifecycleRecord(
            artifact=artifact, observation=observation, hypothesis=hypothesis, presence_assertion=presence
        )

    def record_action_proposal(
        self,
        *,
        action_id: str,
        agent_id: str,
        space_id: str | None,
        kind: str,
        source_event: SemanticObject | None = None,
        target_device_id: str | None = None,
    ) -> ActionLifecycleRecord:
        proposal = self.store.create_object(
            template_code=TEMPLATE_CODES["action_proposal"],
            name=f"action-proposal:{_require_text(action_id, 'action_id')}",
            lifecycle_state="proposed",
            properties={
                "action_id": action_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "space_id": space_id or "",
                "kind": _require_text(kind, "kind"),
                "target_device_id": target_device_id or "",
            },
        )
        if source_event is not None:
            self.store.link_objects(
                parent_semantic_id=source_event.semantic_id,
                child_semantic_id=proposal.semantic_id,
                relationship_type="CAUSED_BY",
            )
        return ActionLifecycleRecord(proposal=proposal)

    def record_action_approval(
        self, record: ActionLifecycleRecord, *, approval_source: str, approved_by: str | None
    ) -> ActionLifecycleRecord:
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        approval = self.store.create_object(
            template_code=TEMPLATE_CODES["action_approval"],
            name=f"action-approval:{action_id}",
            lifecycle_state="approved",
            properties={
                "action_approval_id": str(uuid.uuid4()),
                "action_id": action_id,
                "approval_source": _require_text(approval_source, "approval_source"),
                "approved_by": approved_by or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=record.proposal.semantic_id,
            child_semantic_id=approval.semantic_id,
            relationship_type="APPROVED_BY",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=approval, execution=record.execution, result=record.result
        )

    def record_action_execution(
        self,
        record: ActionLifecycleRecord,
        *,
        target_device_id: str | None,
        correlation_id: str | None,
        state: str,
    ) -> ActionLifecycleRecord:
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        execution = self.store.create_object(
            template_code=TEMPLATE_CODES["action_execution"],
            name=f"action-execution:{action_id}",
            lifecycle_state=_require_text(state, "state"),
            properties={
                "action_execution_id": str(uuid.uuid4()),
                "action_id": action_id,
                "target_device_id": target_device_id or "",
                "correlation_id": correlation_id or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=(record.approval or record.proposal).semantic_id,
            child_semantic_id=execution.semantic_id,
            relationship_type="DISPATCHED_AS",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=record.approval, execution=execution, result=record.result
        )

    def record_action_result(
        self, record: ActionLifecycleRecord, *, status: str, error: str | None = None
    ) -> ActionLifecycleRecord:
        if record.execution is None:
            raise LifecycleError("action result requires execution")
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        result = self.store.create_object(
            template_code=TEMPLATE_CODES["action_result"],
            name=f"action-result:{action_id}",
            lifecycle_state="failed" if error else "recorded",
            properties={
                "action_result_id": str(uuid.uuid4()),
                "action_id": action_id,
                "status": _require_text(status, "status"),
                "error": error or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=record.execution.semantic_id,
            child_semantic_id=result.semantic_id,
            relationship_type="FULFILLS",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=record.approval, execution=record.execution, result=result
        )
