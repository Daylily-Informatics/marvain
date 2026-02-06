"""Marvain Remote Satellite Daemon.

A lightweight daemon that runs on remote devices (Raspberry Pi, etc.) and connects
to the Marvain Hub via WebSocket. It reports heartbeats, responds to pings, and
can execute device-local tools when commanded by the Hub.

Usage:
    marvain-remote-satellite --hub-ws-url wss://example.com/ws --device-token TOKEN
"""

__version__ = "0.1.0"

