# GUI Architecture Plan (Hub + Satellites)

Status: DRAFT for Major review (no implementation until approved)

## 1) Goals
- Replace the legacy GUI (`archive/client/gui.py` + templates) entirely; do **not** reuse its broker/session/ASR concepts.
- Provide a “satellite control panel” for Hub state: devices, spaces, people/consent, privacy mode, memories, artifacts.
- Provide realtime observability: event stream and presence/notifications via Hub WebSocket.
- Provide a LiveKit test surface to join a space (room) and validate end-to-end agent interaction.
- Be easy to run locally (developer laptop) and safe-by-default (read-only views unless explicitly invoked).
- Keep dependency/toolchain overhead low; prefer Python + minimal browser JS.

## 2) Non-goals (do not do)
- Replacing the CLI (`./bin/marvain`) for deploy/build/teardown/DB init.
- Supporting the legacy Broker Lambda API, DynamoDB “agent state table”, or the legacy ASR modes.
- A full product-grade multi-tenant web app (Cognito, orgs, billing, etc.) in v1.
- Exposing long-lived secrets (e.g., LiveKit API secret) to browsers.

## 3) Recommended technology stack (one path)
**Recommended:** Local web UI served by a small Python “GUI satellite” service.
- Backend: FastAPI + Jinja2 + HTMX (minimal JS; already in env)
- Frontend: server-rendered pages + HTMX for CRUD flows; small vanilla JS for WebSocket + LiveKit
- Realtime media: LiveKit browser SDK (pinned artifact / vendored file during implementation)

Rationale:
- Avoids Node/SPA build chain; aligns with repo’s Python tooling and portability goals.
- HTMX covers most admin/dashboard UX without heavy frontend state.

## 4) High-level architecture
- **GUI Satellite (local)** serves pages and holds local config (Hub URLs + device token) in a local config file.
- Browser talks to:
  - GUI Satellite (HTML/JS)
  - Hub REST API (either directly or via GUI Satellite proxy)
  - Hub WebSocket URL (direct)
  - LiveKit (direct)

Design choice: default to **direct Hub calls from GUI Satellite** (server-side) to keep the device token out of browser storage.

## 5) Data flow (control + media)
```mermaid
flowchart LR
  U[User Browser]
  G[GUI Satellite\nFastAPI+Jinja2+HTMX]
  HR[Hub REST API\n/functions/hub_api]
  HW[Hub WebSocket API\n/functions/ws_*]
  DB[(Aurora Postgres\nData API)]
  SQS[SQS TranscriptQueue/ActionQueue]
  P[Planner Lambda]
  T[Tool Runner Lambda]
  LK[LiveKit SFU]
  W[Agent Worker\napps/agent_worker]

  U -->|HTTP| G
  G -->|REST (Bearer device token)| HR
  HR --> DB
  HR --> SQS
  P --> DB
  T --> DB

  U -->|WS (hello + subscribe)| HW
  HW -->|push notifications| U

  U -->|WebRTC| LK
  W -->|WebRTC| LK
  W -->|POST /v1/events| HR
```

## 6) Key UI pages / components
- **Dashboard**: current env, Hub endpoints, selected device, quick health checks.
- **Spaces**: list spaces, set privacy mode, show LiveKit room mapping.
- **Devices**: list/register devices, show scopes/capabilities.
- **People & Consent**: manage people and consent grants (voice/face/recording storage).
- **Memories**: list/delete memories (tiers, provenance, participants).
- **Event Stream**: tail recent events, filter by space/type/person.
- **Artifacts**: presigned upload UI + artifact listing.
- **Audit Log**: browse tamper-evident audit chain (read-only).
- **LiveKit Test**: join room, publish mic/cam, subscribe to agent tracks.

## 7) Hub API surface
### 7.1 Existing (confirmed in `functions/hub_api/app.py`)
- `GET /health`
- `POST /v1/events` (device bearer auth)
- `GET /v1/memories` (device bearer auth)
- `DELETE /v1/memories/{memory_id}` (device bearer auth)
- `POST /v1/artifacts/presign` (device bearer auth)
- Admin-only: `POST /v1/admin/bootstrap`, `POST /v1/admin/devices/register`, `POST /v1/admin/spaces/{space_id}/privacy`

### 7.2 Required additions for the GUI (proposed)
- Spaces: `GET/POST /v1/spaces`, `GET /v1/spaces/{space_id}`, `PATCH /v1/spaces/{space_id}`
- Devices: `GET /v1/devices`, `GET /v1/devices/{device_id}` (non-admin, scoped)
- People/Consent: `GET/POST /v1/people`, `GET/POST /v1/consent_grants`
- Presence: `GET /v1/presence?space_id=...`
- Events: `GET /v1/events?space_id=&type=&limit=` (for UI history)
- Audit: `GET /v1/audit?limit=` and/or `GET /v1/audit/{cursor}`
- Artifacts: `GET /v1/artifacts?prefix=` (optional)

## 8) WebSocket integration
Current state (confirmed):
- API Gateway route selection uses `$request.body.action`.
- Client should send `{ "action": "hello", "device_token": "..." }`.
- Server replies `{ "type": "hello", "ok": true, "agent_id": ..., "device_id": ..., "scopes": [...] }`.

Proposed v1 additions:
- Actions: `subscribe_presence`, `subscribe_actions`, `approve_action`, `deny_action`, `ping`.
- Server push types: `presence_update`, `action_proposed`, `action_state_changed`, `event_ingested`.

## 9) LiveKit integration
- Model: one **space** == one **LiveKit room**.
- GUI needs a safe way to obtain a short-lived LiveKit access token:
  - Preferred: Hub endpoint `POST /v1/livekit/token` (device-auth) that mints a token server-side.
  - Alternative (dev-only): user provides LiveKit API key/secret locally to GUI Satellite (never in browser).

## 10) Security & auth
- Hub REST auth: `Authorization: Bearer <device_token>` (current).
- WS auth: `hello` message with `device_token` (current).
- Admin auth: `X-Admin-Key` only for bootstrap/admin operations; keep these out of normal UI flows.
- GUI Satellite should store device token in local config (file), not in browser localStorage.
- Enforce scopes in Hub (server-side) and reflect them in UI (hide disabled actions).

## 11) Deployment model
- Default: run locally as a “satellite” alongside the CLI (fast iteration, minimal infra).
- Future option: deploy as static site + thin token-minting proxy (only after v1 proves stable).

## 12) Migration / compatibility
- No migration from legacy GUI required; legacy GUI will be deleted once the new GUI exists.

## 13) Open questions for Major
1. Should the GUI include **bootstrap** flows (admin key), or remain strictly post-bootstrap?
2. Do you want the GUI to support **multi-agent** switching, or single-agent-by-config?
3. Should WS be extended for presence/actions now, or keep WS minimal and poll REST for v1?
4. LiveKit: do we assume a managed LiveKit Cloud project, or self-hosted LiveKit in AWS?
5. Do you want the GUI to be purely local (recommended) or also optionally hosted?

