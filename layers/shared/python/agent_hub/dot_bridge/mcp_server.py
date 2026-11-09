"""Streamable HTTP tool transport for the owner-linked Marvain plugin."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING, Annotated, Any, Literal
from urllib.parse import urlsplit

from agent_hub.dot_bridge.auth import DotAuthenticationError, DotOAuthConfig, DotOAuthPrincipal, DotOAuthVerifier
from agent_hub.dot_bridge.delivery import CallbackError
from agent_hub.dot_bridge.service import DotBridge
from anyio import to_thread
from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.extension import Extension, MethodBinding
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolResult, RequestParams, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from agent_hub.dot_bridge.subscriptions import DotEventSubscriptions


class _EventArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scene_euid: Annotated[str, Field(min_length=1)]


class _CallbackDestination(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    mode: Literal["webhook"]
    url: Annotated[str, Field(min_length=1)]


class _SubscribeDestination(_CallbackDestination):
    secret: SecretStr


class _Unsubscribe(RequestParams):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    name: Literal["marvain.handoff.ready"]
    arguments: _EventArguments
    delivery: _CallbackDestination


class _Subscribe(_Unsubscribe):
    delivery: _SubscribeDestination
    ttl_ms: int | None = Field(default=None, gt=0, alias="ttlMs", strict=True)
    cursor: str | None = None
    max_age_ms: int | None = Field(default=None, ge=0, alias="maxAgeMs", strict=True)


class _DotEventsExtension(Extension):
    identifier = "com.daylilyinformatics/marvain-events"

    def __init__(self, service: DotEventSubscriptions, bridge: DotBridge, verifier: DotOAuthVerifier) -> None:
        self.service = service
        self.bridge = bridge
        self.verifier = verifier

    def methods(self) -> tuple[MethodBinding, ...]:
        return (
            MethodBinding("events/list", RequestParams, self._list),
            MethodBinding("events/subscribe", _Subscribe, self._subscribe),
            MethodBinding("events/unsubscribe", _Unsubscribe, self._unsubscribe),
        )

    async def _invoke(
        self, ctx: ServerRequestContext, operation: Callable[[DotOAuthPrincipal], dict[str, Any]],
    ) -> dict[str, Any]:
        headers = ctx.request.headers if ctx.request is not None else {}

        def run() -> dict[str, Any]:
            principal = self.verifier.authenticate(headers.get("authorization", ""), self.service.settings.event_scope)
            return operation(principal)

        try:
            return await to_thread.run_sync(run)
        except CallbackError as exc:
            raise MCPError(code=-32015, message="CallbackEndpointError", data={"reason": exc.reason}) from exc
        except PermissionError as exc:
            raise MCPError(code=-32024, message="The linked account does not have event access") from exc
        except ValueError as exc:
            raise MCPError(code=-32602, message="Invalid subscription parameters") from exc

    async def _list(self, ctx: ServerRequestContext, _params: RequestParams) -> dict[str, Any]:
        return await self._invoke(ctx, partial(self.service.list_events, self.bridge.binding))

    async def _subscribe(self, ctx: ServerRequestContext, params: _Subscribe) -> dict[str, Any]:
        if params.cursor is not None:
            raise MCPError(code=-32026, message="The handoff event does not support replay")

        def subscribe(principal: DotOAuthPrincipal) -> dict[str, Any]:
            return self.service.subscribe(binding=self.bridge.binding, principal=principal,
                                          scene_euid=params.arguments.scene_euid, url=params.delivery.url,
                                          secret=params.delivery.secret.get_secret_value(), ttl_ms=params.ttl_ms)

        return await self._invoke(ctx, subscribe)

    async def _unsubscribe(self, ctx: ServerRequestContext, params: _Unsubscribe) -> dict[str, Any]:
        def unsubscribe(principal: DotOAuthPrincipal) -> dict[str, Any]:
            self.service.unsubscribe(binding=self.bridge.binding, principal=principal,
                                     scene_euid=params.arguments.scene_euid, url=params.delivery.url)
            return {}

        return await self._invoke(ctx, unsubscribe)


async def _advertise_events(ctx: ServerRequestContext, call_next: CallNext) -> HandlerResult:
    result = await call_next(ctx)
    if ctx.method not in {"initialize", "server/discover"}:
        return result
    wire = result.model_dump(mode="json", by_alias=True, exclude_none=True) if isinstance(result, BaseModel) else result
    if not isinstance(wire, dict):
        raise RuntimeError("MCP discovery did not supply a result object")
    return {**wire, "capabilities": {**wire["capabilities"], "events": {}}}


def _oauth_metadata(scope: str) -> dict[str, Any]:
    return {"securitySchemes": [{"type": "oauth2", "scopes": [scope]}]}


def _error(message: str, *, challenge: str | None = None) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)],
        is_error=True,
        _meta={"mcp/www_authenticate": [challenge]} if challenge else None,
    )


def create_dot_mcp_app(
    config: DotOAuthConfig, bridge: DotBridge, *, event_subscriptions: DotEventSubscriptions | None = None,
) -> Starlette:
    """Build the ASGI app with its SDK-owned lifespan and explicit OAuth resource path."""
    if bridge.binding.issuer != config.issuer:
        raise ValueError("The dot OAuth issuer must match the configured Marvain binding")

    verifier = DotOAuthVerifier(config)
    scopes = list(config.scopes)
    if event_subscriptions is not None:
        event_scope = event_subscriptions.settings.event_scope
        if event_scope not in scopes:
            scopes.append(event_scope)
        server = MCPServer("marvain", extensions=[_DotEventsExtension(event_subscriptions, bridge, verifier)],
                           middleware=[_advertise_events])
    else:
        server = MCPServer("marvain")

    @server.custom_route(config.metadata_path, methods=["GET"])
    async def protected_resource_metadata(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "resource": config.resource_uri,
                "authorization_servers": [config.issuer],
                "scopes_supported": scopes,
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
    async def recall(run_euid: str, source_scene_euid: str, query: str, ctx: Context) -> CallToolResult:
        """Recall authorized episode detail from one explicit source scene, which may be a prior encounter."""

        def run(principal: DotOAuthPrincipal) -> dict[str, Any]:
            return {"source_scene_euid": source_scene_euid, "episodes": [
                {"episode_euid": hit.episode_euid, "occurred_at": hit.occurred_at.isoformat(), "detail": hit.detail}
                for hit in bridge.recall(principal, run_euid=run_euid, source_scene_euid=source_scene_euid, query=query)
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
