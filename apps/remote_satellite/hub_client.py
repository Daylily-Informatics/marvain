"""Hub WebSocket + REST client for remote satellite."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Coroutine

import websockets
from websockets.client import WebSocketClientProtocol

logger = logging.getLogger(__name__)


@dataclass
class HubClientConfig:
    """Configuration for Hub client."""

    ws_url: str
    rest_url: str | None
    device_token: str
    heartbeat_interval: int = 20  # seconds
    reconnect_delay: int = 5  # seconds
    max_reconnect_delay: int = 60  # seconds


class HubClient:
    """WebSocket + REST client for communicating with Marvain Hub."""

    def __init__(
        self,
        config: HubClientConfig,
        on_command: Callable[[dict[str, Any]], Coroutine[Any, Any, dict[str, Any] | None]] | None = None,
    ) -> None:
        self.config = config
        self.on_command = on_command
        self._ws: WebSocketClientProtocol | None = None
        self._running = False
        self._authenticated = False
        self._device_id: str | None = None
        self._agent_id: str | None = None
        self._reconnect_delay = config.reconnect_delay

    async def connect(self) -> None:
        """Connect to Hub WebSocket and authenticate."""
        logger.info("Connecting to Hub WebSocket: %s", self.config.ws_url)
        self._ws = await websockets.connect(self.config.ws_url)
        logger.info("Connected. Sending hello...")

        # Send hello with device token
        await self._send({"action": "hello", "device_token": self.config.device_token})

        # Wait for hello response
        response = await self._recv()
        if response.get("type") == "hello" and response.get("ok"):
            self._authenticated = True
            self._device_id = response.get("device_id")
            self._agent_id = response.get("agent_id")
            self._reconnect_delay = self.config.reconnect_delay  # Reset on success
            logger.info("Authenticated as device %s for agent %s", self._device_id, self._agent_id)
        else:
            error = response.get("error", "unknown")
            logger.error("Authentication failed: %s", error)
            raise ConnectionError(f"Hub authentication failed: {error}")

    async def _send(self, msg: dict[str, Any]) -> None:
        """Send a message to the Hub."""
        if self._ws:
            await self._ws.send(json.dumps(msg))

    async def _recv(self) -> dict[str, Any]:
        """Receive a message from the Hub."""
        if self._ws:
            data = await self._ws.recv()
            return json.loads(data)
        return {}

    async def _handle_message(self, msg: dict[str, Any]) -> None:
        """Handle incoming message from Hub."""
        msg_type = msg.get("type", "")

        if msg_type == "cmd.ping":
            # Respond to ping
            await self._send({
                "action": "cmd.pong",
                "original_sent_at": msg.get("sent_at"),
            })
            logger.debug("Responded to cmd.ping")

        elif msg_type.startswith("cmd.") and self.on_command:
            # Delegate to command handler
            result = await self.on_command(msg)
            if result:
                await self._send(result)

        elif msg_type == "pong":
            logger.debug("Received pong")

        elif msg_type == "error":
            logger.warning("Hub error: %s", msg.get("error"))

        else:
            logger.debug("Unhandled message type: %s", msg_type)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats."""
        while self._running and self._authenticated:
            try:
                await self._send({"action": "ping"})
                logger.debug("Sent heartbeat ping")
            except Exception as e:
                logger.error("Heartbeat failed: %s", e)
                break
            await asyncio.sleep(self.config.heartbeat_interval)

    async def _message_loop(self) -> None:
        """Listen for incoming messages."""
        while self._running and self._ws:
            try:
                data = await self._ws.recv()
                msg = json.loads(data)
                await self._handle_message(msg)
            except websockets.ConnectionClosed:
                logger.warning("WebSocket connection closed")
                break
            except Exception as e:
                logger.error("Message loop error: %s", e)
                break

    async def run(self) -> None:
        """Run the client with automatic reconnection."""
        self._running = True
        while self._running:
            try:
                await self.connect()
                # Run heartbeat and message loops concurrently
                await asyncio.gather(
                    self._heartbeat_loop(),
                    self._message_loop(),
                )
            except Exception as e:
                logger.error("Connection error: %s", e)

            if self._running:
                logger.info("Reconnecting in %d seconds...", self._reconnect_delay)
                await asyncio.sleep(self._reconnect_delay)
                # Exponential backoff
                self._reconnect_delay = min(self._reconnect_delay * 2, self.config.max_reconnect_delay)

    async def stop(self) -> None:
        """Stop the client."""
        self._running = False
        if self._ws:
            await self._ws.close()
            self._ws = None

