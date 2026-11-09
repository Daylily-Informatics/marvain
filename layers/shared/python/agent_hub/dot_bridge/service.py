"""Authorize linked-account tool calls against explicit Marvain scene bindings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from agent_hub.agent_lifecycle import SoftwareAgentRun
from agent_hub.dot_bridge.auth import DotOAuthPrincipal
from agent_hub.memory_service import MemoryAccessPolicy


@dataclass(frozen=True)
class DotScene:
    scene_euid: str
    session_euid: str
    update_policy: MemoryAccessPolicy


@dataclass(frozen=True)
class DotBinding:
    """Server-provisioned association of an OAuth subject to a persisted software actor."""

    issuer: str
    subject: str
    agent_id: str
    actor_euid: str
    principal_euid: str
    scenes: tuple[DotScene, ...]

    def __post_init__(self) -> None:
        identifiers = (self.issuer, self.subject, self.agent_id, self.actor_euid, self.principal_euid)
        if not all(identifiers) or not self.scenes:
            raise ValueError("The dot binding requires an issuer, subject, agent, actor, principal and scenes")
        if len({scene.scene_euid for scene in self.scenes}) != len(self.scenes):
            raise ValueError("Each dot scene must have a single configured session and audience policy")
        if any(not all((scene.scene_euid, scene.session_euid)) for scene in self.scenes):
            raise ValueError("Each dot scene requires persisted scene and session identities")


@dataclass(frozen=True)
class DotMemoryHit:
    episode_euid: str
    occurred_at: datetime
    detail: str


class DotCanonicalBackend(Protocol):
    """Owning TapDB-backed operations for the linked actor.

    Load associations through persisted lineage. Resolve tenant membership and
    governing audience policies for every operation. Writes commit the graph
    and its idempotency record atomically under the operation, principal, and
    scene/run; an identical retry returns the first receipt and a conflicting
    retry raises ValueError. Return only authorized current episode detail.
    """

    def begin_run(
        self, *, binding: DotBinding, scene: DotScene, request_key: str, started_at: datetime
    ) -> SoftwareAgentRun: ...

    def load_run(self, run_euid: str) -> SoftwareAgentRun | None: ...

    def recall(
        self, *, binding: DotBinding, scene: DotScene, run: SoftwareAgentRun, query: str, access_at: datetime
    ) -> Sequence[DotMemoryHit]: ...

    def record_update(
        self,
        *,
        binding: DotBinding,
        scene: DotScene,
        run: SoftwareAgentRun,
        request_key: str,
        text: str,
        received_at: datetime,
    ) -> str:
        """Commit the attributed update and return its persisted evidence EUID."""
        ...


class DotBridge:
    def __init__(self, *, binding: DotBinding, backend: DotCanonicalBackend) -> None:
        self.binding = binding
        self.backend = backend
        self._scenes = {scene.scene_euid: scene for scene in binding.scenes}

    def _require_linked_principal(self, principal: DotOAuthPrincipal) -> None:
        if (principal.issuer, principal.subject) != (self.binding.issuer, self.binding.subject):
            raise PermissionError("This linked account has no Marvain dot binding.")

    def _require_run(self, principal: DotOAuthPrincipal, run_euid: str) -> tuple[SoftwareAgentRun, DotScene]:
        self._require_linked_principal(principal)
        run = self.backend.load_run(_required_text(run_euid, "run_euid"))
        if run is not None and (run.actor_euid, run.principal_euid) == (
            self.binding.actor_euid,
            self.binding.principal_euid,
        ):
            scene = self._scenes.get(run.scene_euid)
            if scene is not None and scene.session_euid == run.session_euid:
                return run, scene
        raise PermissionError("This linked account has no access to that Marvain run.")

    def begin_run(self, principal: DotOAuthPrincipal, *, scene_euid: str, request_key: str) -> SoftwareAgentRun:
        self._require_linked_principal(principal)
        scene = self._scenes.get(scene_euid)
        if scene is None:
            raise PermissionError("This linked account has no access to that Marvain scene.")
        return self.backend.begin_run(
            binding=self.binding,
            scene=scene,
            request_key=_required_text(request_key, "request_key"),
            started_at=datetime.now(UTC),
        )

    def recall(self, principal: DotOAuthPrincipal, *, run_euid: str, query: str) -> Sequence[DotMemoryHit]:
        run, scene = self._require_run(principal, run_euid)
        return self.backend.recall(
            binding=self.binding,
            scene=scene,
            run=run,
            query=_required_text(query, "query"),
            access_at=datetime.now(UTC),
        )

    def record_update(self, principal: DotOAuthPrincipal, *, run_euid: str, request_key: str, text: str) -> str:
        run, scene = self._require_run(principal, run_euid)
        return self.backend.record_update(
            binding=self.binding,
            scene=scene,
            run=run,
            request_key=_required_text(request_key, "request_key"),
            text=_required_text(text, "text"),
            received_at=datetime.now(UTC),
        )


def _required_text(value: str, label: str) -> str:
    if not value.strip():
        raise ValueError(f"{label} is required")
    return value
