#!/usr/bin/env python3
"""Check AgentSession methods for interrupt/cancel."""
from livekit.agents import AgentSession

methods = [m for m in dir(AgentSession) if not m.startswith('_')]
print('AgentSession methods:')
for m in methods:
    print(f'  {m}')

