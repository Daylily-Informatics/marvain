"""Run the dedicated, long-lived Marvain dot MCP application."""
from __future__ import annotations

import json
from pathlib import Path

from click import ClickException
from typer import Option


def serve_cmd(
    binding_file: Path | None = Option(None, "--binding-file", help="Absolute path to the server-owned 4.x bindings JSON."),
    binding_secret_arn: str | None = Option(None, "--binding-secret-arn", help="Secrets Manager ARN of the 4.x bindings JSON."),
    resource_uri: str | None = Option(None, "--resource-uri", help="Exact deployed public HTTPS MCP resource URI."),
    host: str = Option(..., "--host", help="Bind address for the dedicated MCP process."),
    port: int = Option(..., "--port", min=1, max=65535, help="Bind port for the dedicated MCP process."),
) -> None:
    """Run the configured dot MCP resource in the foreground."""
    import uvicorn
    from agent_hub.dot_bridge.auth import DotOAuthConfig
    from agent_hub.dot_bridge.canonical_backend import TapdbDotCanonicalBackend
    from agent_hub.dot_bridge.mcp_server import create_dot_mcp_app
    from agent_hub.dot_bridge.service import DotBinding, DotBridge, DotScene
    from agent_hub.secrets import get_secret_json
    from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
    from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore, TEMPLATE_CODES

    if (binding_file is None) == (binding_secret_arn is None):
        raise ClickException("Select exactly one of --binding-file and --binding-secret-arn")
    if binding_file is not None and not binding_file.is_absolute():
        raise ClickException("--binding-file must be an absolute path")
    try:
        if binding_file is not None:
            bindings = json.loads(binding_file.read_text())
        else:
            if not binding_secret_arn or not binding_secret_arn.strip() or not resource_uri:
                raise ValueError("Secret-backed bindings require an explicit secret ARN and --resource-uri")
            bindings = get_secret_json(binding_secret_arn)
        raw = bindings["dot"]
        oauth = DotOAuthConfig(**raw["oauth"])
        if resource_uri is not None and oauth.resource_uri != resource_uri:
            raise ValueError("The configured OAuth resource URI must match the deployed MCP resource URI")
        selected = raw["binding"]
        store = DaylilyTapdbSemanticStore.from_environment()
        with store.read_view() as view:
            actor = view.get_object(selected["actor_euid"])
            principal = view.get_object(selected["principal_euid"])
            if actor.template_code != TEMPLATE_CODES["agent"] or principal.template_code != TEMPLATE_CODES["principal"]:
                raise ValueError("dot actor and principal must be canonical objects of the expected types")
            if not any(p.semantic_id == principal.semantic_id for p in
                       view.linked_objects(actor.semantic_id, relationship_type="AUTHENTICATED_AS")):
                raise ValueError("dot principal is not linked to its actor")
            references = view.linked_objects(principal.semantic_id, relationship_type="has_external_reference")
            if not any(ref.properties.get("external_identifier", {}).get("system") == oauth.issuer and
                       ref.properties.get("external_identifier", {}).get("target_euid") == selected["subject"]
                       for ref in references):
                raise ValueError("dot principal is not linked to the configured issuer and subject")
            scenes = []
            for item in selected["scenes"]:
                scene = view.get_object(item["scene_euid"])
                session = view.get_object(item["session_euid"])
                if scene.template_code != TEMPLATE_CODES["scene"] or session.template_code != TEMPLATE_CODES["session"]:
                    raise ValueError("dot scene or session has the wrong canonical type")
                if not any(obj.semantic_id == scene.semantic_id for obj in
                           view.linked_objects(session.semantic_id, relationship_type="IN_SCENE")):
                    raise ValueError("dot session is not linked to its configured scene")
                scenes.append(DotScene(scene_euid=scene.semantic_id, session_euid=session.semantic_id,
                                       update_policy=MarvainSemanticLifecycle._read_policy(view, scene)))
        binding = DotBinding(issuer=oauth.issuer, subject=selected["subject"], agent_id=selected["agent_id"],
                             actor_euid=actor.semantic_id, principal_euid=principal.semantic_id, scenes=tuple(scenes))
        events_mode = raw["events_mode"]
        if events_mode not in {"enabled", "disabled"}:
            raise ValueError("dot.events_mode must be explicitly enabled or disabled")
        event_secret_arn = raw.get("events_secret_arn")
        event_subscriptions = None
        if events_mode == "enabled":
            if not isinstance(event_secret_arn, str) or not event_secret_arn.strip():
                raise ValueError("dot.events_secret_arn is required when events are enabled")
            from agent_hub.dot_bridge.subscriptions import DotEventSubscriptions
            event_subscriptions = DotEventSubscriptions.from_secret(store, event_secret_arn)
        elif event_secret_arn:
            raise ValueError("dot.events_secret_arn must be omitted when events are disabled")
        app = create_dot_mcp_app(oauth, DotBridge(binding=binding, backend=TapdbDotCanonicalBackend(store)),
                                 event_subscriptions=event_subscriptions)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise ClickException(f"Dot MCP configuration is invalid: {exc}") from exc
    uvicorn.run(app, host=host, port=port)
