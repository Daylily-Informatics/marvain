"""Streamable HTTP tool transport for the owner-linked Marvain plugin."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from agent_hub.dot_bridge.auth import DotAuthenticationError, DotOAuthConfig, DotOAuthPrincipal, DotOAuthVerifier
from agent_hub.dot_bridge.service import DotBridge
from anyio import to_thread
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse


def _oauth_metadata(scope: str) -> dict[str, Any]:
    return {"securitySchemes": [{"type": "oauth2", "scopes": [scope]}]}


def _error(message: str, *, challenge: str | None = None) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        is_error=True,
        _meta={"mcp/www_authenticate": [challenge]} if challenge else None,
    )


def create_dot_mcp_app(config: DotOAuthConfig, bridge: DotBridge) -> Starlette:
    """Build the ASGI app with its SDK-owned lifespan and explicit OAuth resource path."""
    if bridge.binding.issuer != config.issuer:
        raise ValueError("The dot OAuth issuer must match the configured Marvain binding")

    server = MCPServer("marvain")
    verifier = DotOAuthVerifier(config)

    @server.custom_route(config.metadata_path, methods=["GET"])
    async def protected_resource_metadata(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "resource": config.resource_uri,
                "authorization_servers": [config.issuer],
                "scopes_supported": list(config.scopes),
            }
        )

    async def invoke(
        ctx: Context, scope: str, operation: Callable[[DotOAuthPrincipal], dict[str, Any]]
    ) -> CallToolResult:
        authorization = (ctx.headers or {}).get("authorization", "")

        def run() -> dict[str, Any]:
            return operation(verifier.authenticate(authorization, scope))

        try:
            result = await to_thread.run_sync(run)
        except DotAuthenticationError as exc:
            challenge = f'Bearer resource_metadata="{config.metadata_uri}", scope="{scope}"'
            if authorization:
                challenge += f', error="{exc.code}"'
            return _error(str(exc), challenge=challenge)
        except PermissionError:
            return _error("The linked account does not have access to the requested Marvain scope.")
        except ValueError:
            return _error("The Marvain request is invalid or conflicts with an earlier request key.")
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
            structured_content=result,
        )

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True,
                                    open_world_hint=False),
        meta=_oauth_metadata(config.run_scope),
    )
    async def begin_run(scene_euid: str, request_key: str, ctx: Context) -> CallToolResult:
        """Open a Marvain run in an explicitly selected scene. Reuse the request key for a retry."""

        def run(principal: DotOAuthPrincipal) -> dict[str, Any]:
            receipt = bridge.begin_run(principal, scene_euid=scene_euid, request_key=request_key)
            return {"run_euid": receipt.run_euid, "scene_euid": receipt.scene_euid, "origin": "marvain"}

        return await invoke(ctx, config.run_scope, run)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
        meta=_oauth_metadata(config.recall_scope),
    )
    async def recall(run_euid: str, query: str, ctx: Context) -> CallToolResult:
        """Recall current Marvain episode detail authorized for the scene of this run."""

        def run(principal: DotOAuthPrincipal) -> dict[str, Any]:
            return {"episodes": [
                {"episode_euid": hit.episode_euid, "occurred_at": hit.occurred_at.isoformat(), "detail": hit.detail}
                for hit in bridge.recall(principal, run_euid=run_euid, query=query)
            ]}

        return await invoke(ctx, config.recall_scope, run)

    @server.tool(
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True,
                                    open_world_hint=False),
        meta=_oauth_metadata(config.update_scope),
    )
    async def record_update(run_euid: str, request_key: str, text: str, ctx: Context) -> CallToolResult:
        """Record a deliberate software-actor update in Marvain. Reuse the request key for a retry."""

        def run(principal: DotOAuthPrincipal) -> dict[str, Any]:
            evidence_euid = bridge.record_update(principal, run_euid=run_euid, request_key=request_key, text=text)
            return {"evidence_euid": evidence_euid}

        return await invoke(ctx, config.update_scope, run)

    resource = urlsplit(config.resource_uri)
    return server.streamable_http_app(
        streamable_http_path=resource.path,
        host=resource.hostname,
        json_response=True,
        stateless_http=True,
    )
