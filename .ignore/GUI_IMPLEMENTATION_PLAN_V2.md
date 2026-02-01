# GUI Implementation Plan V2 (Public GUI + Public API)

Status: **DRAFT for Major review** (no implementation until approved)

Last updated: 2026-01-25

## Assumptions
- The **GUI and Hub REST API are public** (internet reachable), because you want to build mobile apps and allow other humans to interact.
- Human users authenticate with **Cognito**; satellites/devices continue using **device bearer tokens** stored in Postgres.
- WebSocket authentication is performed by a **`hello`** message that includes an **`access_token` (preferred)** or `id_token`, and is **verified server-side in the WS Lambda**.
- Access control is multi-tenant and role-based: **owner/admin/member/guest/blocked**, with an additional **relationship label** (metadata) such as `close-friend`, `coworker`, etc.

## Trade-offs
- **Gain:** real identity + revocation + multi-tenant control without inventing auth; a public API that supports mobile apps; unified policy layer in the Hub.
- **Lose:** more AWS infra (Cognito) + more policy surface area; careful token handling is required for WS and GUI.

## 0) What changes vs `GUI_ARCHITECTURE_PLAN.md`
`GUI_ARCHITECTURE_PLAN.md` recommended a **local GUI satellite** as the default v1.

This V2 plan updates the direction to a **public GUI + public API** while preserving the core architecture:
- Hub remains the authoritative control plane (REST + WS) backed by Aurora Postgres.
- Device tokens remain valid for satellites.
- Humans use Cognito and are authorized by Hub DB memberships.

## 1) Recommended end-state (one path)
**Recommended:** Serve a **server-rendered GUI** from the existing Hub FastAPI Lambda (`functions/hub_api`) and authenticate humans via **Cognito Hosted UI**.

Rationale:
- Avoids adding a Node/SPA build chain.
- Lets the Hub act as a simple “BFF” (backend-for-frontend): HTML pages + a small amount of JS for WS + LiveKit.
- Keeps authorization logic consolidated in one service.

## 2) Identity & auth model

### 2.1 Principal types
1) **Human principal**
   - Auth: Cognito OAuth2 / OIDC
   - Tokens: browser obtains `access_token` + `id_token`
   - Hub uses **access_token** for API authorization checks (preferred; supports Cognito `GetUser`).

2) **Device principal**
   - Auth: Hub-issued **device token** (bearer secret)
   - Stored: SHA-256 hash in `devices.token_hash` (already implemented)
   - Used by satellites/agent worker.

### 2.2 REST auth strategy
REST endpoints accept:
- `Authorization: Bearer <device_token>` for device-scoped endpoints (existing behavior)
- `Authorization: Bearer <access_token>` for user-scoped endpoints (new)

Implementation note (V1 recommendation):
- Validate user **access_token** in Lambda by calling `cognito-idp:GetUser`.
  - Pros: no JWT signature library required.
  - Cons: extra network hop; cache per-token result briefly in-memory.

### 2.3 WebSocket auth strategy
Client sends:
```json
{ "action": "hello", "access_token": "…" }
```

Server (WS Lambda) verifies server-side:
- Preferred: `cognito-idp:GetUser(AccessToken=...)`
- Optional extension: accept `id_token` by verifying against Cognito JWKS (requires adding a JWT/JWK dependency).

After verification, WS Lambda stores the authenticated principal in `WsConnectionsTable`:
- `principal_type = "user"`
- `cognito_sub`, `user_id`, `agent_ids` (or a selected `agent_id`), `roles`/`scopes`

## 3) Authorization model (multi-tenant)

### 3.1 DB tables (Aurora Postgres)
Add these tables (new SQL migration, do not rewrite `sql/001_init.sql` in place):

1) `users`
- `user_id uuid PK`
- `cognito_sub text UNIQUE NOT NULL`
- `email text NULL`
- `created_at timestamptz`

2) `agent_memberships`
- `agent_id uuid FK agents(agent_id)`
- `user_id uuid FK users(user_id)`
- `role text NOT NULL` (`owner|admin|member|guest|blocked`)
- `relationship_label text NULL` (e.g. `close-friend`, `coworker`, `family`, …)
- `created_at timestamptz`, `revoked_at timestamptz NULL`
- Unique constraint `(agent_id, user_id)`

Notes:
- Relationship labels are **metadata**, not the permission source of truth.
- If needed later: add `space_memberships` for per-space overrides.

### 3.2 Policy checks
Add a small policy layer in `layers/shared/python/agent_hub/` that answers:
- “Which agents can this user access?”
- “Can this user perform action X on agent/space Y?”

Keep policy decisions explicit and boring (e.g. `can_manage_devices`, `can_view_memories`, `can_delete_memories`).

## 4) Hub REST API changes

### 4.1 Keep existing endpoints
No breaking changes:
- `POST /v1/events` remains device-auth.
- `GET/DELETE /v1/memories*` remain device-auth initially.

### 4.2 Add user-scoped endpoints (public API)
Proposed minimal set for the GUI + mobile apps:

#### Auth / identity
- `GET /v1/me` → returns user profile + memberships

#### Agents + memberships
- `GET /v1/agents` → list agents user can access
- `GET /v1/agents/{agent_id}`
- `GET /v1/agents/{agent_id}/members`
- `POST /v1/agents/{agent_id}/members` → add member by email/sub + role + relationship_label
- `PATCH /v1/agents/{agent_id}/members/{user_id}` → change role/label
- `DELETE /v1/agents/{agent_id}/members/{user_id}` → revoke

#### Devices / app tokens
- `GET /v1/devices?agent_id=...`
- `POST /v1/devices` → create device/app token (returns token once)
- `POST /v1/devices/{device_id}/revoke`

#### Spaces
- `GET /v1/spaces?agent_id=...`
- `POST /v1/spaces`
- `PATCH /v1/spaces/{space_id}` (including `privacy_mode`)

#### People + consent
- `GET/POST /v1/people`
- `GET/POST /v1/consent_grants`

#### Read-only observability
- `GET /v1/events?agent_id=&space_id=&type=&limit=`
- `GET /v1/presence?space_id=`
- `GET /v1/audit?agent_id=&limit=`

### 4.3 Admin-only endpoints (bootstrap)
Keep the existing admin-key secured endpoints, but extend bootstrap to set up the first owner:
- `POST /v1/admin/bootstrap_owner`
  - Input: `email`, `agent_id` (optional), `role=owner`
  - Side effects:
    - Ensure Cognito user exists (invite or lookup)
    - Ensure `users` row exists
    - Ensure `agent_memberships` row exists

This supports your requirement: “adding users/authorizing/assigning tokens should be possible via CLI and GUI”.

## 5) WebSocket API changes

### 5.1 `hello` message (required)
Update `functions/ws_message/handler.py` to accept:
- `access_token` (preferred)
- `id_token` (optional; later)

Reply payload should include:
- `ok`, `principal_type`, `user_id`, `cognito_sub`, and optionally `agents` list.

### 5.2 Subscription and push types (incremental)
Phase in these actions/types (do not overbuild on day 1):
- Client actions: `subscribe_presence`, `subscribe_actions`, `ping`
- Server pushes: `presence_update`, `action_proposed`, `action_state_changed`, `event_ingested`

Implementation note:
- Use the existing `WsConnectionsTable` to track subscriptions and principal context.

## 6) GUI implementation (public)

### 6.1 Where the GUI lives
Implement the GUI as routes in the existing Hub FastAPI app:
- Pages under `/` (or `/gui/*`)
- Static assets served from package directory

### 6.2 Login/logout flow
Implement Cognito Hosted UI integration:
- `/login` → redirect to Cognito authorize endpoint
- `/auth/callback` → exchange `code` for tokens (server-side), set secure HttpOnly cookie
- `/logout` → clear cookie, redirect to Cognito logout

Cookie contents should be minimal (e.g. encrypted session that stores refresh token reference or short-lived access token).

### 6.3 Core pages (initial)
1) Dashboard: environment, endpoints, memberships
2) Agents: switch agent context; show members
3) Devices/app tokens: create/revoke, scopes
4) Spaces: list/create, privacy mode toggle
5) People/consent
6) Event stream (poll REST; WS later)

### 6.4 LiveKit test surface (defer until auth baseline works)
Add Hub endpoint:
- `POST /v1/livekit/token` (user-auth) → mints short-lived LiveKit JWT server-side

GUI page uses LiveKit browser SDK to join a room mapped from `space_id`.

## 7) CLI changes (required by Major)

### 7.1 Replace the legacy `gui` command
Today `./bin/marvain gui` prints the deployed Hub GUI URL (legacy local GUI removed).

Plan:
- Implement a new GUI runner (still `marvain gui`) that either:
  - runs the new local dev server for the Hub GUI, or
  - clearly errors if GUI is only deployed as part of the stack.

Status:
- Implemented: `marvain gui` now prints the deployed GUI URL using CloudFormation stack outputs.

### 7.2 Add management commands
Add CLI commands to support public GUI/API operations:
- `marvain users invite --email ... --agent-id ... --role ... --relationship ...`
- `marvain users list --agent-id ...`
- `marvain devices create --agent-id ... --name ... --scopes ...`
- `marvain devices revoke --device-id ...`

CLI should call Hub admin endpoints (admin key) for privileged operations unless a user token is supplied.

## 8) Infrastructure (SAM / template.yaml)

### 8.1 Cognito resources
Add:
- Cognito User Pool (use the same cognito patterns/config as ` ../daylily-ursa/*` implements- read this repo for its approach), add cognito to the cli similar to `daylily-ursa`)
- User Pool Client (OAuth enabled)
- Hosted UI domain
- Outputs: `CognitoUserPoolId`, `CognitoUserPoolClientId`, `CognitoHostedUiUrl`

### 8.2 IAM permissions
Grant Hub API Lambda and WS Lambda the minimum:
- `cognito-idp:GetUser`
- `cognito-idp:ListUsers` (if supporting “add by email”)
- optionally `cognito-idp:AdminCreateUser`, `AdminUpdateUserAttributes`

### 8.3 Configuration/secrets
Store any Cognito client secret (if used) in Secrets Manager.
Pass required IDs/ARNs as environment variables.

### 8.4 Public API hardening (later but planned)
- Enable CORS for `/v1/*` for mobile clients.
- Consider AWS WAF / throttling / usage plans.
- Add structured audit entries for membership and token changes.

## 9) Database migration strategy
Create incremental SQL migrations:
- `sql/002_users_and_memberships.sql`
- (later) `sql/003_livekit_tokens.sql` if tables are needed

Update `marvain init db` to apply migrations in order (all `sql/*.sql` sorted).

## 10) Testing strategy

### 10.1 Unit tests (fast)
- Policy checks for roles and relationship labels
- REST auth helper (device token + user token flows)
- WS `hello` handler logic (event fixtures)

### 10.2 Integration tests (targeted)
- `GET /v1/me` with a mocked Cognito response
- Membership enforcement on a representative endpoint (e.g. creating a device token)

## 11) Phased execution plan (milestones)

### Phase 1 — Foundations (auth + tenancy)
- Add Cognito to `template.yaml`
- Add `users` + `agent_memberships` migration
- Add user auth helper (access_token → cognito_sub → user_id)
- Add `/v1/me` and `/v1/agents`

### Phase 2 — Management surfaces (devices/users)
- Add device/app token CRUD endpoints (user-scoped)
- Add membership management endpoints
- Add CLI commands for user/device management

### Phase 3 — WebSocket JWT hello
- Extend WS `hello` to accept `access_token` and verify via Cognito
- Store authenticated principal + subscriptions in `WsConnectionsTable`

### Phase 4 — Public GUI
- Implement `/login`, `/auth/callback`, `/logout`
- Implement core pages (agents/members, devices, spaces)

### Phase 5 — LiveKit test page (optional)
- Implement `/v1/livekit/token`
- Build GUI LiveKit join page

### Phase 6 — Remove legacy GUI (COMPLETE)
- [x] Delete or quarantine `archive/client/gui.py` + templates/static
- [x] Update docs (`README.md` / `QUICKSTART.md`) to point to the new GUI

## 12) Open questions (confirm before coding)
1) Do you want Cognito **invite-only** or **self-signup**?
- (use the same cognito patterns/config as ` ../daylily-ursa/*` implements- read this repo for its approach), add cognito to the cli similar to `daylily-ursa`)
2) For WS `hello`, is **access_token-only** acceptable for v1 (recommended), with `id_token` support deferred?
- (yes)
3) Should the first “owner” be created only via CLI bootstrap (recommended), or can the first login auto-claim ownership?
- allow cli to add the first owner do not auto claim ownership.  The first user to login should be able to add themselves as the first owner via the cli.