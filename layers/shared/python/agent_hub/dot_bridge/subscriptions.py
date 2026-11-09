"""Durable transport state for explicitly activated Marvain MCP Events webhooks."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import text

from agent_hub.dot_bridge.auth import DotOAuthPrincipal
from agent_hub.dot_bridge.canonical_backend import _authorized_scene
from agent_hub.dot_bridge.delivery import CallbackError, callback_url, send_webhook, signing_key, verify_callback
from agent_hub.dot_bridge.events import HANDOFF_READY, HandoffReadyEvent, handoff_event_definition
from agent_hub.dot_bridge.service import DotBinding
from agent_hub.memory_service import MemoryLayer, MemoryPurpose
from agent_hub.secrets import get_secret_json
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore, TEMPLATE_CODES

_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")
_SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


@dataclass(frozen=True)
class DotEventSettings:
    event_scope: str
    callback_hosts: tuple[str, ...]
    subscription_ttl_ms: int
    verification_cache_seconds: int
    rotation_seconds: int
    callback_timeout_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.event_scope, str) or _SCOPE.fullmatch(self.event_scope) is None:
            raise ValueError("An explicit OAuth event scope is required")
        if not isinstance(self.callback_hosts, (list, tuple)) or not self.callback_hosts or any(
            not isinstance(host, str) or _HOSTNAME.fullmatch(host) is None for host in self.callback_hosts
        ):
            raise ValueError("Explicit lower-case callback hostnames are required")
        object.__setattr__(self, "callback_hosts", tuple(self.callback_hosts))
        for value in (self.subscription_ttl_ms, self.verification_cache_seconds, self.rotation_seconds):
            if type(value) is not int or value <= 0:
                raise ValueError("MCP Events TTL, callback verification cache and key rotation must be positive")
        timeout = self.callback_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("An explicit positive callback timeout is required")


class DotEventSubscriptions:
    def __init__(self, store: DaylilyTapdbSemanticStore, settings: DotEventSettings, *, encryption_key: str) -> None:
        self.store = store
        self.settings = settings
        self.cipher = Fernet(encryption_key.encode("ascii"))

    @classmethod
    def from_secret(cls, store: DaylilyTapdbSemanticStore, secret_arn: str) -> DotEventSubscriptions:
        data = get_secret_json(secret_arn)
        return cls(store, DotEventSettings(**data["settings"]), encryption_key=data["encryption_key"])

    @staticmethod
    def _authorize_account(binding: DotBinding, principal: DotOAuthPrincipal) -> None:
        if (principal.issuer, principal.subject) != (binding.issuer, binding.subject):
            raise PermissionError("The linked account has no Marvain event binding")

    def list_events(self, binding: DotBinding, principal: DotOAuthPrincipal) -> dict[str, Any]:
        self._authorize_account(binding, principal)
        descriptor = handoff_event_definition()
        descriptor["_meta"] = {"securitySchemes": [{"type": "oauth2", "scopes": [self.settings.event_scope]}]}
        now = datetime.now(UTC)
        with self.store.read_view() as view:
            for scene in binding.scenes:
                try:
                    _authorized_scene(view, binding=binding, scene=scene, at=now, layer=MemoryLayer.EPISODE)
                except PermissionError:
                    continue
                return {"events": [descriptor]}
        return {"events": []}

    def subscribe(
        self, *, binding: DotBinding, principal: DotOAuthPrincipal, scene_euid: str, url: str,
        secret: str, ttl_ms: int | None,
    ) -> dict[str, Any]:
        self._authorize_account(binding, principal)
        scene = next((item for item in binding.scenes if item.scene_euid == scene_euid), None)
        if scene is None:
            raise PermissionError("The linked account has no event access for that scene")
        url = callback_url(url, self.settings.callback_hosts)
        key = signing_key(secret)
        now = datetime.now(UTC)
        ttl = timedelta(milliseconds=(self.settings.subscription_ttl_ms if ttl_ms is None else
                                     min(ttl_ms, self.settings.subscription_ttl_ms)))
        subscription_id = _subscription_id(binding, scene_euid, url)
        with self.store.connection.session_scope(commit=True) as session:
            view = self.store._read_view_for_session(session)
            _authorized_scene(view, binding=binding, scene=scene, at=now, layer=MemoryLayer.EPISODE)
            row = session.execute(text("""
                SELECT * FROM public.dot_event_subscriptions WHERE subscription_id = :id FOR UPDATE
            """), {"id": subscription_id}).mappings().one_or_none()
            active = row is not None and row["stopped_at"] is None and row["expires_at"] > now
            old_key = self._decrypt(row["signing_secret"]) if active else None
            same_key = old_key == key
            if active and same_key and row["verified_at"] + timedelta(seconds=self.settings.verification_cache_seconds) > now:
                verified_at = row["verified_at"]
            else:
                verify_callback(url=url, hosts=self.settings.callback_hosts, timeout=self.settings.callback_timeout_seconds,
                                subscription_id=subscription_id, key=key)
                verified_at = datetime.now(UTC)
            previous_key = None
            previous_until = None
            if active:
                previous_key = row["previous_secret"] if same_key else row["signing_secret"]
                previous_until = row["previous_until"] if same_key else verified_at + timedelta(seconds=self.settings.rotation_seconds)
            expires_at = max(verified_at, now) + ttl
            session.execute(text("""
                INSERT INTO public.dot_event_subscriptions
                  (subscription_id, agent_id, principal_euid, actor_euid, oauth_issuer, oauth_subject, scene_euid,
                   session_euid, callback_url, signing_secret, previous_secret, previous_until, verified_at,
                   started_at, expires_at)
                VALUES (:id, CAST(:agent AS uuid), :principal, :actor, :issuer, :subject, :scene,
                        :session, :url, :secret, :previous, :previous_until, :verified_at, :started_at, :expires_at)
                ON CONFLICT (subscription_id) DO UPDATE SET actor_euid = EXCLUDED.actor_euid,
                  oauth_issuer = EXCLUDED.oauth_issuer, oauth_subject = EXCLUDED.oauth_subject,
                  session_euid = EXCLUDED.session_euid, signing_secret = EXCLUDED.signing_secret,
                  previous_secret = EXCLUDED.previous_secret, previous_until = EXCLUDED.previous_until,
                  verified_at = EXCLUDED.verified_at, started_at = EXCLUDED.started_at,
                  expires_at = EXCLUDED.expires_at, stopped_at = NULL
            """), {"id": subscription_id, "agent": binding.agent_id, "principal": binding.principal_euid,
                   "actor": binding.actor_euid, "issuer": binding.issuer, "subject": binding.subject,
                   "scene": scene_euid, "session": scene.session_euid, "url": url,
                   "secret": self.cipher.encrypt(key).decode("ascii"), "previous": previous_key,
                   "previous_until": previous_until, "verified_at": verified_at,
                   "started_at": row["started_at"] if active else verified_at, "expires_at": expires_at})
        return {"id": subscription_id, "refreshBefore": expires_at.isoformat(), "cursor": None, "truncated": False}

    def unsubscribe(self, *, binding: DotBinding, principal: DotOAuthPrincipal, scene_euid: str, url: str) -> None:
        self._authorize_account(binding, principal)
        subscription_id = _subscription_id(binding, scene_euid, url)
        with self.store.connection.session_scope(commit=True) as session:
            session.execute(text("""
                UPDATE public.dot_event_subscriptions SET stopped_at = now()
                WHERE subscription_id = :id AND stopped_at IS NULL
            """), {"id": subscription_id})

    def enqueue_handoff(
        self, session: Any, *, command_id: UUID, agent_id: str, handoff_euid: str, occurred_at: datetime,
    ) -> None:
        """Queue pointer delivery in the canonical writer's transaction, after graph creation."""
        view = self.store._read_view_for_session(session)
        handoff = view.get_object(handoff_euid)
        recipients = view.linked_objects(handoff_euid, relationship_type="ADDRESSED_TO")
        if not recipients:
            return
        scenes = view.linked_objects(handoff_euid, relationship_type="IN_SCENE")
        if len(recipients) != 1 or len(scenes) != 1:
            raise ValueError("The handoff event requires one persisted recipient and scene")
        event = HandoffReadyEvent(event_id=handoff.properties["handoff_ready_event_id"], occurred_at=occurred_at,
                                 handoff_euid=handoff_euid, scene_euid=scenes[0].semantic_id,
                                 recipient_principal_euid=recipients[0].semantic_id)
        session.execute(text("""
            INSERT INTO public.dot_event_deliveries
                (subscription_id, event_id, source_command_id, handoff_euid, occurred_at)
            SELECT subscription_id, CAST(:event AS uuid), CAST(:command AS uuid), :handoff, :occurred_at
            FROM public.dot_event_subscriptions
            WHERE agent_id = CAST(:agent AS uuid) AND principal_euid = :recipient AND scene_euid = :scene
              AND stopped_at IS NULL AND started_at <= :occurred_at AND expires_at > :occurred_at
            ON CONFLICT (subscription_id, event_id) DO NOTHING
        """), {"event": event.event_id, "command": command_id, "handoff": event.handoff_euid,
               "occurred_at": event.occurred_at, "agent": agent_id, "recipient": event.recipient_principal_euid,
               "scene": event.scene_euid})

    def deliver_for_command(self, command_id: UUID) -> bool:
        """Return whether committed delivery pointers for this queue record are terminal."""
        with self.store.connection.session_scope(commit=False) as session:
            keys = session.execute(text("""
                SELECT subscription_id, event_id FROM public.dot_event_deliveries
                WHERE source_command_id = CAST(:command AS uuid) AND state = 'pending'
            """), {"command": command_id}).all()
        retry = False
        for subscription_id, event_id in keys:
            if self._deliver(subscription_id, event_id):
                retry = True
        return not retry

    def _deliver(self, subscription_id: str, event_id: UUID) -> bool:
        params = {"id": subscription_id, "event": event_id}
        with self.store.connection.session_scope(commit=True) as session:
            row = session.execute(text("""
                SELECT subscription.*, delivery.handoff_euid, delivery.occurred_at
                FROM public.dot_event_deliveries AS delivery
                JOIN public.dot_event_subscriptions AS subscription USING (subscription_id)
                WHERE subscription_id = :id AND event_id = CAST(:event AS uuid) AND state = 'pending'
                FOR UPDATE OF delivery, subscription
            """), params).mappings().one_or_none()
            if row is None:
                return False
            now = datetime.now(UTC)
            view = self.store._read_view_for_session(session)
            if (row["stopped_at"] is not None or row["expires_at"] <= now or row["started_at"] > row["occurred_at"]
                    or not self._can_deliver(view, row, now)):
                state, status, reason = "inactive", None, "scope_inactive"
            else:
                state, status, reason = self._post(row, event_id=event_id, at=now)
            session.execute(text("""
                UPDATE public.dot_event_deliveries SET state = :state, last_http_status = :status, last_error = :reason,
                    last_attempt_at = now()
                WHERE subscription_id = :id AND event_id = CAST(:event AS uuid)
            """), {**params, "state": state, "status": status, "reason": reason})
            return state == "pending"

    def _decrypt(self, encoded: str) -> bytes:
        return self.cipher.decrypt(encoded.encode("ascii"))

    def _post(self, row: Mapping[str, Any], *, event_id: UUID, at: datetime) -> tuple[str, int | None, str | None]:
        event = HandoffReadyEvent(str(event_id), row["occurred_at"], row["handoff_euid"], row["scene_euid"],
                                 row["principal_euid"])
        keys = (self._decrypt(row["signing_secret"]),)
        if row["previous_until"] is not None and row["previous_until"] > at:
            keys += (self._decrypt(row["previous_secret"]),)
        try:
            status, _ = send_webhook(url=row["callback_url"], allowed_hosts=self.settings.callback_hosts,
                                     timeout=self.settings.callback_timeout_seconds, subscription_id=row["subscription_id"],
                                     event_id=event.event_id, payload=event.envelope(), keys=keys)
        except CallbackError as exc:
            return ("rejected" if exc.reason == "unsafe_destination" else "pending"), None, exc.reason
        except ValueError:
            return "rejected", None, "callback_not_allowed"
        if 200 <= status < 300:
            return "accepted", status, None
        return ("pending" if status in (408, 425, 429) or status >= 500 else "rejected"), status, "callback_http_error"

    @staticmethod
    def _can_deliver(view: Any, row: Mapping[str, Any], at: datetime) -> bool:
        from agent_hub.dot_bridge.service import DotScene

        try:
            scene = view.get_object(row["scene_euid"])
            handoff = view.get_object(row["handoff_euid"])
            if handoff.template_code != TEMPLATE_CODES["work_handoff"]:
                return False
            recipients = view.linked_objects(handoff.semantic_id, relationship_type="ADDRESSED_TO")
            event_scenes = view.linked_objects(handoff.semantic_id, relationship_type="IN_SCENE")
            if ([recipient.semantic_id for recipient in recipients] != [row["principal_euid"]]
                    or [item.semantic_id for item in event_scenes] != [scene.semantic_id]):
                return False
            scene_policy = MarvainSemanticLifecycle._read_policy(view, scene)
            route = DotScene(scene.semantic_id, row["session_euid"], scene_policy)
            binding = DotBinding(row["oauth_issuer"], row["oauth_subject"], str(row["agent_id"]),
                                 row["actor_euid"], row["principal_euid"], (route,))
            _authorized_scene(view, binding=binding, scene=route, at=at, layer=MemoryLayer.EPISODE)
            handoff_policy = MarvainSemanticLifecycle._read_policy(view, handoff)
        except (KeyError, PermissionError):
            return False
        return handoff_policy.permits(authenticated_principal_id=row["principal_euid"], purpose=MemoryPurpose.RECALL,
                                      layer=MemoryLayer.KNOWLEDGE, at=at)


def _subscription_id(binding: DotBinding, scene_euid: str, url: str) -> str:
    values = (str(UUID(binding.agent_id)), binding.principal_euid, url, HANDOFF_READY, {"scene_euid": scene_euid})
    identity = json.dumps(values, separators=(",", ":"), sort_keys=True).encode()
    return "sub_" + hashlib.sha256(identity).hexdigest()
