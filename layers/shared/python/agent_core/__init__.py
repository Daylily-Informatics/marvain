"""agent_core package (shared Lambda layer)

This is the minimal contract required by the Broker + Heartbeat Lambdas.
"""

from .schema import Event, MemoryItem, MemoryKind  # noqa: F401
