Spec 0: Fix the identity/permission spine first (prereq)
Problem

The codebase currently mixes two membership systems:

Correct: agent_memberships (used by API + websocket permission checks).

Incorrect/legacy: memberships (used by several GUI routes and admin operations like revoke/delete).

If you don’t fix this first, “devices/actions/memories” will always feel randomly broken depending on which endpoint you hit.

Requirements

Stop using memberships everywhere in code
Replace GUI SQL joins against memberships with agent_memberships and revoked_at IS NULL.

Make users schema match what GUI expects

GUI queries reference users.display_name and users.last_seen, but the migration order means those columns never get created (because users already exists by the time the “IF NOT EXISTS” create runs).

Add a migration that ALTER TABLE users ADD COLUMN display_name text, ADD COLUMN last_seen timestamptz.

Optional but strongly recommended: remove or quarantine legacy tables

Either drop the memberships table or rename it to legacy_memberships to avoid future footguns.

Acceptance criteria

GUI pages that mutate data (revoke device, delete memory, approve action) work for a real logged-in member/admin using only agent_memberships.

No endpoint references memberships anymore.

Spec 1: Devices fully functional
What “Devices” should mean

A device is a cryptographically authenticated principal that:

emits events into a space (transcripts, sensor readings, tool outputs)

receives commands (action execution requests, pings, configuration updates)

advertises capabilities and scopes

Data model

Use the existing devices table, but make these behaviors explicit:

Existing fields (keep):

device_id, agent_id

token_hash

scopes (JSON list)

capabilities (JSON list)

revoked_at, created_at, last_seen

Add (migration):

metadata jsonb default '{}' (freeform label, platform, version, etc)

last_hello_at timestamptz

last_heartbeat_at timestamptz

Auth + scope rules

Device token auth is already implemented (hash compare). Keep that.

Add scope enforcement (right now /v1/* endpoints accept any device token):

events:write required for /v1/events

memories:read for memory listing/search endpoints

actions:read for action listing

actions:write for action submission (if you expose it)

presence:write for presence/heartbeat

APIs
Device management (human via GUI/API)

POST /api/devices

Inputs: { agent_id, name, scopes, capabilities, metadata? }

Output: { device_id, device_token } (token shown once)

POST /api/devices/{device_id}/revoke

POST /api/devices/{device_id}/rotate-token

Revokes old token by replacing token_hash, returns new token once.

GET /api/devices list for current user across agents they can access

Device runtime (device authenticated)

POST /v1/devices/heartbeat

Updates devices.last_heartbeat_at and last_seen

Optionally also updates presence for a space

WebSocket “hello” handshake already exists conceptually:

Ensure it updates last_hello_at and sets connection principal metadata.

Device command channel

You need an authoritative way for Hub to command devices.

Define WS message types (server -> device):

{"type":"cmd.ping","request_id":"..."}

{"type":"cmd.run_action","action_id":"..."}

{"type":"cmd.config","payload":{...}}

Define device responses (device -> server):

{"type":"cmd.pong","request_id":"...","ts":"..."}

{"type":"cmd.action_result","action_id":"...","ok":true,"result":{...}}

Acceptance criteria

You can create a device, copy its token once, and use it to post events.

Revoking a device immediately blocks it from posting events and from WS hello.

Heartbeat updates last-seen and the GUI reflects online/offline without manual refresh (once Spec 5 is done).

Spec 2: Devices (formerly "Remotes as Devices") -- COMPLETE, legacy removed

> Status: Complete. The legacy remotes table, GUI page, API endpoints, and all related code
> have been fully removed from the codebase (2026-02-06). Satellite devices are now managed
> exclusively through the devices table with metadata.is_remote = true.

The remote satellite daemon (apps/remote_satellite/) authenticates as a device using a device token.
It connects via WebSocket, sends heartbeats, responds to cmd.ping, and executes device-local actions.

All "remote" functionality is now handled through the Devices page and the standard device API.

Spec 3: Actions fully functional
Current gaps that must be closed

GUI approve/reject endpoints update DB but do not reliably enqueue execution.

Tool runner does not persist action results in DB (only in audit logs).

send_message tool is effectively dead because broadcast_fn=None.

Action lifecycle

Define statuses:

proposed

approved

rejected

executing

executed

failed

(optional) canceled, expired

Data model changes (migration)

Add to actions table:

approved_by uuid references users(user_id)

approved_at timestamptz

result jsonb

error text

completed_at timestamptz

Approval semantics

Only users with role admin or owner can approve high-risk scopes.

Members can approve low-risk scopes if you want, but specify it explicitly.

APIs

POST /api/actions/{action_id}/approve

Checks agent_memberships for user role

Sets status to approved, records approved_by, approved_at

Enqueues {action_id} to SQS ActionQueue

POST /api/actions/{action_id}/reject

Sets status rejected

Also mirror via websocket (you already have approve/reject handlers there, keep them consistent).

Tool runner behavior

When executing:

Transition to executing.

Execute tool.

Write:

status executed or failed

executed_at, completed_at

result and error

Emit an event into the space:

type: action_result

payload: {action_id, kind, ok, result, error}

Tools that make the system actually useful

Minimum set to make “devices/actions” coherent:

send_message

MUST store as a Hub event (assistant message) even if WS broadcast fails.

Optional: also broadcast to subscribed clients.

device_command

payload: { device_id, command, args }

Implementation: send WS cmd.* to that device and await response (with timeout).

This is how Actions can operate on devices safely.

http_request keep allow-list restriction.

create_memory keep.

Acceptance criteria

From GUI: approve an action and it executes.

GUI shows action results (result/error).

A device_command action can ping a device and store the result.

Spec 4: Core agent running + full memories

This is the “make it feel like one agent across time and surfaces” spec.

Definition: “core agent”

The core agent is:

the consistent identity and policy boundary (Agent)

backed by Hub event log + memories

capable of proposing actions and using tools

accessible through multiple surfaces (LiveKit voice, future text UI, devices)

LiveKit is only a media surface.

Memory system requirements

You already have:

memories table with tier, content, embedding

planner that writes memories from transcript events

a GUI browse page (with stubbed “view details”)

Missing to be “full”:

Memory recall API usable by the runtime agent (not just the planner).

Space context retrieval (last N events) for session continuity.

Agent runtime actually using recall when speaking.

New APIs
Recall

POST /v1/recall

Auth: device token (or user token, either is fine)

Input: { agent_id, space_id?, query, k=8, tiers? }

Output: list of memory snippets (content + metadata)

Implementation: pgvector cosine distance ordering on embedding <=> query_embedding

Space context

GET /v1/spaces/{space_id}/events?limit=50

Returns normalized events suitable for prompting.

Must respect privacy mode and membership.

Memory detail (GUI completeness)

GET /api/memories/{memory_id} so “viewMemory” is not a toast stub.

Fix delete memory permission check to use agent_memberships.

How the LiveKit voice agent should use Hub memories (minimum viable)

You have two viable approaches; I’m picking the one that fits your current structure.

Recommended: hydrate context at session start
When the agent worker joins a LiveKit room for a space:

Call Hub:

fetch last N events for the space (or last N episodic memories)

fetch recall for “who am I talking to / what is this space about”

Construct a context block injected into the model instructions:

persona

relevant memories

recent space summary

explicit tool/action policy

This solves your “rejoin feels like amnesia” problem, and keeps LiveKit as transport.

Stretch goal: per-utterance recall

After each user utterance (once you have final transcript), call /v1/recall and inject incremental context to the session.

This depends on how controllable the LiveKit RealtimeModel session is, so treat it as Phase 2.

“LiveKit is just hear/speak” confirmation

Yes. That’s the intent, and the Hub code already documents the concept: LiveKit room is ephemeral, Hub space is persistent, and you can have multiple sequential LiveKit rooms for one Hub space. Your config supports this split. 

marvain-config

Acceptance criteria

Leave and rejoin a space: the agent still behaves like the same agent because it reloads context from Hub (events/memories).

Memories are not just stored; they are actually used to shape responses.

Actions proposed by planner show up reliably and can be executed.

Spec 5: Event stream actually real-time (glue that makes the GUI feel alive)

Right now you have:

WebSocket connect/disconnect/message handlers

subscription bookkeeping

but no reliable server-side broadcasting from planner/tool runner

Requirements

Introduce a shared “broadcast” module that can be called from:

/v1/events ingestion path

planner after writing memories/actions

tool runner after updating action status

It should:

query the connection registry (DynamoDB)

post messages via API Gateway management API

Events to broadcast

events.new for space subscribers

actions.updated for agent subscribers

presence.updated for space subscribers

Acceptance criteria

Actions page updates without manual refresh.

Devices online state updates without polling.

Repository requirements (so you can actually run all this)

The practical runtime requirements implied by the stack and your config are:

Amazon Web Services account with ability to provision:

Aurora PostgreSQL Serverless v2 with Data API enabled

API Gateway (REST + WebSocket)

Lambda (Python 3.11)

SQS (TranscriptQueue, ActionQueue)

S3 (artifacts + audit bucket with Object Lock)

DynamoDB (ws connection registry)

Secrets Manager (OpenAI key, LiveKit key/secret, DB creds)

Cognito Hosted UI for auth (your config has domain/pool IDs) 

marvain-config

PostgreSQL extensions:

pgcrypto

vector (pgvector)

OpenAI API key for:

embeddings (memory recall)

Responses API (planner)

Realtime (voice agent worker)

LiveKit (cloud or self-host) reachable from:

the GUI token minter (local FastAPI or Lambda)

the agent worker runtime

your browser (for the LiveKit test page)

Do this next:

Implement Spec 0 (membership + users schema fix) first. Until memberships is gone from code, devices/actions will keep failing in inconsistent ways.

Remotes model: Completed -- “remote == device” with server-side pinging removed. Remote daemon implemented in apps/remote_satellite/.

Make action approval enqueue from the GUI endpoints and add result/error columns to actions so you can see outcomes.

Add /v1/recall + /v1/spaces/{space}/events and use them in the agent worker to hydrate context on join.

Add broadcast module and wire it into event creation, planner outputs, and tool runner outputs so the GUI becomes a live control plane.