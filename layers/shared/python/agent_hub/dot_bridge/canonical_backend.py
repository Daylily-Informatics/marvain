"""TapDB persistence and authorized lexical recall for the linked dot tools."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from agent_hub.agent_lifecycle import SoftwareAgentRun
from agent_hub.dot_bridge.service import DotBinding, DotMemoryHit, DotScene
from agent_hub.memory_service import MemoryAccessPolicy, MemoryLayer, MemoryPurpose, _tokenize
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.semantic_outbox import PersistedExternalReference, SemanticOutboxError
from agent_hub.semantic_tapdb import (
    EXTERNAL_REFERENCE_TEMPLATE,
    TEMPLATE_CODES,
    DaylilyTapdbSemanticStore,
    GraphLinkWrite,
    GraphObjectRef,
    GraphObjectWrite,
    SemanticObject,
    SemanticReadView,
)
from agent_hub.session_lifecycle import SessionLifecycleState

RECALL_ALGORITHM = "canonical_lexical_v1"
_RUN_ORIGIN = "marvain.dot_mcp"
_LIVE_SESSION_STATES = frozenset({SessionLifecycleState.OPENING, SessionLifecycleState.ACTIVE,
                                  SessionLifecycleState.RECONNECTING})


class TapdbDotCanonicalBackend:
    def __init__(self, store: DaylilyTapdbSemanticStore) -> None:
        self.store = store
        self.lifecycle = MarvainSemanticLifecycle(store)

    def begin_run(
        self, *, binding: DotBinding, scene: DotScene, request_key: str, started_at: datetime,
    ) -> SoftwareAgentRun:
        tenant_id = UUID(binding.agent_id)
        command_id = _command_id(tenant_id, "begin_run", binding.principal_euid, scene.scene_euid, request_key)

        def build(view: SemanticReadView) -> tuple[GraphObjectWrite, tuple[GraphLinkWrite, ...]]:
            _authorized_scene(view, binding=binding, scene=scene, at=started_at, layer=MemoryLayer.EPISODE,
                              require_live_session=True)
            item = GraphObjectWrite(
                "run", TEMPLATE_CODES["agent_run"], f"dot-run:{command_id}",
                {"run_key": str(command_id), "started_at": started_at.isoformat(), "origin": _RUN_ORIGIN}, "running",
            )
            run_ref = GraphObjectRef(key=item.key)
            links = (
                GraphLinkWrite(GraphObjectRef(semantic_id=binding.actor_euid), run_ref, "HAS_RUN"),
                _outgoing(run_ref, binding.principal_euid, "AUTHENTICATED_BY"),
                _outgoing(run_ref, scene.scene_euid, "IN_SCENE"),
                _outgoing(run_ref, scene.session_euid, "IN_SESSION"),
            )
            return item, links

        run = self.store.commit_inbox_graph(
            tenant_id=tenant_id, command_id=command_id,
            command_fingerprint=_fingerprint(binding.actor_euid, scene.session_euid), build=build,
        )
        return SoftwareAgentRun(run.semantic_id, binding.actor_euid, binding.principal_euid,
                                scene.scene_euid, scene.session_euid)

    def load_run(self, run_euid: str) -> SoftwareAgentRun | None:
        with self.store.read_view() as view:
            try:
                run = view.get_object(run_euid)
            except KeyError:
                return None
            if run.template_code != TEMPLATE_CODES["agent_run"] or run.properties.get("origin") != _RUN_ORIGIN:
                return None
            return _read_run(view, run)

    def recall(
        self, *, binding: DotBinding, scene: DotScene, source_scene: DotScene, run: SoftwareAgentRun,
        query: str, access_at: datetime,
    ) -> tuple[DotMemoryHit, ...]:
        if (run.scene_euid, run.session_euid) != (scene.scene_euid, scene.session_euid):
            raise PermissionError("The run has no access to the configured request scene")
        with self.store.read_view() as view:
            request_policy = _authorized_scene(view, binding=binding, scene=scene, at=access_at,
                                               layer=MemoryLayer.EPISODE, allow_closed_scene=True)
            same_source = (scene.scene_euid, scene.session_euid) == (source_scene.scene_euid, source_scene.session_euid)
            source_policy = request_policy if same_source else _authorized_scene(
                view, binding=binding, scene=source_scene, at=access_at, layer=MemoryLayer.EPISODE,
                allow_closed_scene=True,
            )
            if MemoryPurpose.RECALL not in source_policy.allowed_purposes:
                raise PermissionError("The source scene has no recall grant for this linked account")
        records = self.lifecycle.recall_scene(
            scene_semantic_id=source_scene.scene_euid, session_semantic_id=source_scene.session_euid,
            authenticated_principal_id=binding.principal_euid, access_at=access_at, as_of=access_at,
        )
        query_terms = set(_tokenize(query))
        episode_matches: dict[str, tuple[datetime, list[tuple[int, str, str]]]] = {}
        for record in records:
            content = record.memory.properties["content"]
            matched = len(query_terms.intersection(_tokenize(content)))
            if matched == 0:
                continue
            episode_id = record.episode.semantic_id
            occurred_at = datetime.fromisoformat(record.episode.properties["occurred_at"])
            _, matches = episode_matches.setdefault(episode_id, (occurred_at, []))
            matches.append((matched, record.memory.semantic_id, content))

        ranked = []
        for episode_id, (occurred_at, matches) in episode_matches.items():
            matches.sort(reverse=True)
            detail = "\n".join(content for _, _, content in matches)
            ranked.append((matches[0][0], occurred_at, episode_id, detail))
        ranked.sort(reverse=True)
        return tuple(DotMemoryHit(episode_id, occurred_at, detail) for _, occurred_at, episode_id, detail in ranked)

    def record_update(
        self, *, binding: DotBinding, scene: DotScene, run: SoftwareAgentRun, request_key: str,
        text: str, received_at: datetime,
    ) -> str:
        tenant_id = UUID(binding.agent_id)
        command_id = _command_id(tenant_id, "record_update", binding.principal_euid, run.run_euid, request_key)

        def build(view: SemanticReadView) -> tuple[GraphObjectWrite, tuple[GraphLinkWrite, ...]]:
            policy = _authorized_scene(view, binding=binding, scene=scene, at=received_at,
                                       layer=MemoryLayer.ATTRIBUTED_EVENT, require_live_session=True)
            configured = scene.update_policy
            if (configured.owner_principal_id != policy.owner_principal_id
                    or set(configured.reader_principal_ids) != set(policy.reader_principal_ids)
                    or configured.as_properties() != policy.as_properties()):
                raise PermissionError("The current scene policy differs from the configured update policy")
            try:
                current_run = view.get_object(run.run_euid)
            except KeyError as exc:
                raise PermissionError("The linked run is no longer available") from exc
            if current_run.lifecycle_state != "running" or _read_run(view, current_run) != run:
                raise PermissionError("The linked run is no longer active in its configured scene")

            item = GraphObjectWrite(
                "evidence", TEMPLATE_CODES["event_sensor"], f"dot-update:{command_id}",
                {"event_id": str(command_id), "event_type": "dot_update", "observed_at": received_at.isoformat(),
                 "received_at": received_at.isoformat(), "detail": {"text": text, "modality": "text"},
                 "access_policy": policy.as_properties()}, "recorded",
            )
            evidence = GraphObjectRef(key=item.key)
            links = (
                _outgoing(evidence, scene.scene_euid, "IN_SCENE"),
                _outgoing(evidence, scene.session_euid, "IN_SESSION"),
                _outgoing(evidence, binding.principal_euid, "AUTHENTICATED_BY"),
                _outgoing(evidence, run.run_euid, "FROM_RUN"),
                _outgoing(evidence, binding.actor_euid, "ATTRIBUTED_TO"),
                _outgoing(evidence, policy.owner_principal_id, "OWNER_PRINCIPAL"),
                *(_outgoing(evidence, key, "READER_PRINCIPAL") for key in policy.reader_principal_ids),
            )
            return item, links

        result = self.store.commit_inbox_graph(
            tenant_id=tenant_id, command_id=command_id,
            command_fingerprint=_fingerprint(binding.actor_euid, scene.scene_euid, scene.session_euid, text),
            build=build,
        )
        return result.semantic_id


def _command_id(tenant_id: UUID, operation: str, principal: str, target: str, request_key: str) -> UUID:
    identity = json.dumps(("marvain.dot.command.v1", str(tenant_id), operation, principal, target, request_key),
                          separators=(",", ":"))
    return uuid5(NAMESPACE_URL, identity)


def _fingerprint(*values: str) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _outgoing(source: GraphObjectRef, semantic_id: str, relationship: str) -> GraphLinkWrite:
    return GraphLinkWrite(source, GraphObjectRef(semantic_id=semantic_id), relationship)


def _read_run(view: SemanticReadView, run: SemanticObject) -> SoftwareAgentRun:
    if run.template_code != TEMPLATE_CODES["agent_run"] or run.properties.get("origin") != _RUN_ORIGIN:
        raise PermissionError("The record is outside the linked dot run scope")
    actor = _one_link(view, run, "HAS_RUN", "agent", incoming=True)
    principal = _one_link(view, run, "AUTHENTICATED_BY", "principal")
    scene = _one_link(view, run, "IN_SCENE", "scene")
    session = _one_link(view, run, "IN_SESSION", "session")
    return SoftwareAgentRun(run.semantic_id, actor.semantic_id, principal.semantic_id,
                            scene.semantic_id, session.semantic_id)


def _one_link(
    view: SemanticReadView, origin: SemanticObject, relationship: str, target_type: str, *, incoming: bool = False,
) -> SemanticObject:
    targets = view.linked_objects(origin.semantic_id, relationship_type=relationship, incoming=incoming)
    if len(targets) != 1 or targets[0].template_code != TEMPLATE_CODES[target_type]:
        raise PermissionError(f"Invalid canonical {relationship} scope")
    return targets[0]


def _authorized_scene(
    view: SemanticReadView, *, binding: DotBinding, scene: DotScene, at: datetime, layer: MemoryLayer,
    require_live_session: bool = False, allow_closed_scene: bool = False,
) -> MemoryAccessPolicy:
    try:
        actor = view.get_object(binding.actor_euid)
        principal = view.get_object(binding.principal_euid)
        scene_object = view.get_object(scene.scene_euid)
        session = view.get_object(scene.session_euid)
    except KeyError as exc:
        raise PermissionError("A configured dot identity or scene is unavailable") from exc
    scene_states = ("active", "closed") if allow_closed_scene else ("active",)
    if (actor.template_code != TEMPLATE_CODES["agent"] or actor.lifecycle_state != "active"
            or principal.template_code != TEMPLATE_CODES["principal"] or principal.lifecycle_state != "active"
            or scene_object.template_code != TEMPLATE_CODES["scene"] or scene_object.lifecycle_state not in scene_states
            or session.template_code != TEMPLATE_CODES["session"]):
        raise PermissionError("A configured dot identity or scene is unavailable")
    if _one_link(view, principal, "AUTHENTICATED_AS", "agent", incoming=True).semantic_id != actor.semantic_id:
        raise PermissionError("The principal has no canonical association with the configured software actor")
    references = view.linked_objects(principal.semantic_id, relationship_type="has_external_reference")
    if not any(_matches_issuer(ref, binding) for ref in references):
        raise PermissionError("The principal has no canonical binding to the linked OAuth subject")
    if _one_link(view, session, "IN_SCENE", "scene").semantic_id != scene_object.semantic_id:
        raise PermissionError("The conversation session has no canonical association with the configured scene")
    space = _one_link(view, scene_object, "IN_SPACE", "space")
    space_source = _tenant_source(view, space, agent_id=binding.agent_id, source_table="spaces")
    if require_live_session:
        session_source = _tenant_source(view, scene_object, agent_id=binding.agent_id, source_table="sessions")
        status = view.operational_session_status(session_id=session_source.source_id,
                                                 agent_id=space_source.agent_id, space_id=space_source.source_id)
        if status not in _LIVE_SESSION_STATES:
            raise PermissionError("The configured operational session is not available for dot writes")
    policy = MarvainSemanticLifecycle._read_policy(view, scene_object)
    if (binding.principal_euid not in policy.reader_principal_ids
            or (policy.revoked_at is not None and at >= policy.revoked_at)
            or not dict(policy.retention)[layer].permits_at(at)):
        raise PermissionError("The current scene policy does not allow the linked principal to participate")
    return policy


def _matches_issuer(reference: SemanticObject, binding: DotBinding) -> bool:
    external = reference.properties.get("external_identifier")
    return (reference.template_code == EXTERNAL_REFERENCE_TEMPLATE and reference.lifecycle_state == "active"
            and isinstance(external, dict) and external.get("system") == binding.issuer
            and external.get("target_euid") == binding.subject)


def _tenant_source(
    view: SemanticReadView, origin: SemanticObject, *, agent_id: str, source_table: str,
) -> PersistedExternalReference:
    tenant = str(UUID(agent_id))
    matches = []
    for reference in view.linked_objects(origin.semantic_id, relationship_type="has_external_reference"):
        if reference.template_code != EXTERNAL_REFERENCE_TEMPLATE:
            continue
        try:
            source = PersistedExternalReference.from_payload(reference.properties)
        except SemanticOutboxError:
            continue
        if source.source_table == source_table and source.agent_id == tenant:
            matches.append(source)
    if len(matches) != 1:
        raise PermissionError(f"The configured scene has no unique canonical {source_table} source for the linked tenant")
    return matches[0]
