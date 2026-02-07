# Advanced Feature Implementation Plan

**Status**: ✅ COMPLETE
**Date**: 2026-02-03
**Author**: Forge
**Branch**: `feature/advanced-features-spec0-5`
**Completed**: 2026-02-03

---

## 1. Executive Summary

This plan implements the Advanced Feature Plan (Specs 0–5) to create a fully functional "hub + satellites" system with:

1. **Spec 0 (Prerequisite)**: Fix the identity/permission spine by eliminating the legacy `memberships` table and ensuring all code uses `agent_memberships`. Add missing `users` columns.

2. **Spec 1**: Make devices fully functional with scope enforcement, heartbeat, and command channel.

3. **Spec 2**: Devices fully unified (legacy remotes removed); remote satellite daemon implemented.

4. **Spec 3**: Complete action lifecycle with approval persistence, execution status, result storage, and tool execution.

5. **Spec 4**: Enable core agent memory recall and context hydration for session continuity.

6. **Spec 5**: Implement real-time event broadcasting to make the GUI feel alive.

**Trade-offs**:
- **Gain**: Coherent permission model, working devices/actions/memories, real-time GUI, and session continuity.
- **Lose**: Remote satellite daemon is a new app to maintain.

---

## 2. Dependency Analysis

```mermaid
flowchart TD
    S0[Spec 0: Fix Identity/Permission Spine]
    S1[Spec 1: Devices Fully Functional]
    S2[Spec 2: Devices (legacy remotes removed)]
    S3[Spec 3: Actions Fully Functional]
    S4[Spec 4: Core Agent + Memories]
    S5[Spec 5: Real-time Event Stream]

    S0 --> S1
    S0 --> S2
    S0 --> S3
    S0 --> S4
    S0 --> S5
    S1 --> S2
    S1 --> S3
    S3 --> S5
    S4 --> S5
```

**Critical Path**: Spec 0 → (Spec 1 + Spec 3) → Spec 5

**Parallel Workstreams** (after Spec 0):
- Spec 1 + Spec 2 (devices)
- Spec 3 + Spec 4 (actions/memories)
- All converge at Spec 5 (broadcasting)

---

## 3. Implementation Phases

### Phase 0: Spec 0 — Fix Identity/Permission Spine (PREREQUISITE)

**Goal**: Eliminate `memberships` table usage; ensure GUI and API use `agent_memberships` consistently.

#### 3.0.1 Database Migration

**File**: `sql/005_users_columns_and_legacy_cleanup.sql`

```sql
-- Add missing columns to users table if they don't exist
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz;

-- Rename legacy memberships table to prevent accidental use
ALTER TABLE IF EXISTS memberships RENAME TO legacy_memberships;
```

#### 3.0.2 Code Changes

| File | Change |
|------|--------|
| `functions/hub_api/app.py` | Replace all `memberships` JOIN with `agent_memberships` (8 occurrences found) |
| `sql/003_remotes.sql` | Already creates `memberships` - mark as legacy reference only | (DELETED)

**Lines to modify in `app.py`** (found via search):
- Line 428, 452, 503, 723, 783, 819, 1009, 1524, 1790, 1825, 2073

#### 3.0.3 Test Updates

| Test File | Changes |
|-----------|---------|
| `tests/test_gui_app.py` | Verify GUI routes work with `agent_memberships` |
| `tests/test_memberships.py` | Ensure no references to legacy table |

**Acceptance Criteria**:
- [ ] No code references `memberships` table (only `legacy_memberships` or `agent_memberships`)
- [ ] GUI pages (revoke device, delete memory, approve action) work correctly
- [ ] All existing tests pass

**Risk**: Medium — requires careful search/replace and testing  
**Estimate**: 2–3 hours

---

### Phase 1: Spec 1 — Devices Fully Functional

**Goal**: Scope enforcement, heartbeat, and device command channel.

#### 3.1.1 Database Migration

**File**: `sql/006_devices_enhancement.sql`

```sql
-- Add device metadata and presence tracking columns
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_hello_at timestamptz;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;
```

#### 3.1.2 New/Modified Files

| File | Change |
|------|--------|
| `functions/hub_api/api_app.py` | Add scope enforcement to `/v1/*` endpoints |
| `functions/hub_api/api_app.py` | Add `POST /v1/devices/heartbeat` |
| `functions/hub_api/api_app.py` | Add `POST /api/devices/{device_id}/rotate-token` |
| `layers/shared/python/agent_hub/auth.py` | Add `check_device_scope(device, required_scope)` |
| `functions/ws_message/handler.py` | Update `hello` to set `last_hello_at` |
| `functions/ws_message/handler.py` | Add `cmd.ping`, `cmd.pong`, `cmd.run_action`, `cmd.config` message types |

#### 3.1.3 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/devices/heartbeat` | Device token | Update last_heartbeat_at and presence |
| POST | `/api/devices/{device_id}/rotate-token` | User (admin/owner) | Rotate device token |

#### 3.1.4 Scope Enforcement Matrix

| Endpoint | Required Scope |
|----------|----------------|
| `POST /v1/events` | `events:write` |
| `GET /v1/memories` | `memories:read` |
| `GET /v1/actions` | `actions:read` |
| `POST /v1/devices/heartbeat` | `presence:write` |

#### 3.1.5 Tests

| Test File | Tests |
|-----------|-------|
| `tests/test_device_scopes.py` (new) | Scope enforcement for all v1 endpoints |
| `tests/test_hub_api_devices.py` (new) | Heartbeat, token rotation |
| `tests/test_ws_device_commands.py` (new) | cmd.ping/pong, cmd.run_action |

**Acceptance Criteria**:
- [ ] Device creation returns token once; GUI can copy it
- [ ] Revoking a device blocks POST /v1/events and WS hello
- [ ] Heartbeat updates last_seen; GUI reflects online/offline
- [ ] Scope enforcement rejects unauthorized requests

**Risk**: Low
**Estimate**: 3–4 hours

---

### Phase 2: Spec 2 -- Devices (formerly "Remotes as Devices") -- COMPLETE, legacy removed

> **Status**: Complete. The legacy `remotes` table, GUI page (`/remotes`), API endpoints
> (`/api/remotes/*`), and all related tests have been fully removed from the codebase (2026-02-06).
> Satellite devices are managed exclusively through the `devices` table.

The remote satellite daemon (`apps/remote_satellite/`) authenticates as a device and connects
via WebSocket for heartbeats, ping/pong, and action execution.

### Phase 3: Spec 3 — Actions Fully Functional

**Goal**: Complete action lifecycle with results persistence.

#### 3.3.1 Database Migration

**File**: `sql/008_actions_enhancement.sql`

```sql
-- Add approval and result tracking columns to actions
ALTER TABLE actions ADD COLUMN IF NOT EXISTS approved_by uuid REFERENCES users(user_id);
ALTER TABLE actions ADD COLUMN IF NOT EXISTS approved_at timestamptz;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS result jsonb;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS error text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS completed_at timestamptz;
```

#### 3.3.2 Status Lifecycle

```
proposed → approved → executing → executed | failed
         ↘ rejected
```

#### 3.3.3 Code Changes

| File | Change |
|------|--------|
| `functions/hub_api/app.py` | `POST /api/actions/{id}/approve` records `approved_by`, `approved_at` |
| `functions/hub_api/app.py` | `POST /api/actions/{id}/reject` sets status to `rejected` |
| `functions/ws_message/handler.py` | Update `approve_action` to record `approved_by` |
| `functions/tool_runner/handler.py` | Write `result`, `error`, `completed_at` to DB |
| `functions/tool_runner/handler.py` | Emit `action_result` event to space |
| `layers/shared/python/agent_hub/tools/send_message.py` | Store as Hub event even if WS fails |
| `layers/shared/python/agent_hub/tools/device_command.py` (new) | Send WS command to device |

#### 3.3.4 New Tool: `device_command`

**File**: `layers/shared/python/agent_hub/tools/device_command.py`

```python
def execute(payload: dict, ctx: ToolContext) -> ToolResult:
    device_id = payload.get("device_id")
    command = payload.get("command")  # "ping", "config", etc.
    args = payload.get("args", {})

    # Send WS message to device and await response (with timeout)
    # Returns result from device or timeout error
```

#### 3.3.5 Tests

| Test File | Tests |
|-----------|-------|
| `tests/test_tool_runner.py` | Update for result/error persistence |
| `tests/test_action_lifecycle.py` (new) | Full lifecycle: propose → approve → execute → result |
| `tests/test_device_command_tool.py` (new) | Device command tool |

**Acceptance Criteria**:
- [ ] GUI approve → action executes
- [ ] GUI shows action results (result/error)
- [ ] `device_command` action can ping a device
- [ ] `send_message` stores event even if broadcast fails

**Risk**: Medium
**Estimate**: 4–5 hours

---

### Phase 4: Spec 4 — Core Agent + Full Memories

**Goal**: Memory recall and context hydration for session continuity.

#### 3.4.1 New API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/recall` | Device or User | Semantic memory search |
| GET | `/v1/spaces/{space_id}/events` | Device or User | Recent events for context |
| GET | `/api/memories/{memory_id}` | User | Memory detail for GUI |

#### 3.4.2 Code Changes

| File | Change |
|------|--------|
| `functions/hub_api/api_app.py` | Add `/v1/recall` endpoint |
| `functions/hub_api/api_app.py` | Add `/v1/spaces/{space_id}/events` endpoint |
| `functions/hub_api/app.py` | Add `/api/memories/{memory_id}` detail endpoint |
| `apps/agent_worker/worker.py` | Call `/v1/recall` and `/v1/spaces/{space_id}/events` on join |
| `apps/agent_worker/worker.py` | Construct context block for model instructions |

#### 3.4.3 Recall API Specification

```json
POST /v1/recall
{
  "agent_id": "uuid",
  "space_id": "uuid (optional)",
  "query": "what does Major like to eat for breakfast?",
  "k": 8,
  "tiers": ["episodic", "semantic"]
}

Response:
{
  "memories": [
    {
      "memory_id": "uuid",
      "tier": "semantic",
      "content": "Major prefers eggs and coffee for breakfast",
      "created_at": "2026-01-15T08:30:00Z",
      "distance": 0.12
    }
  ]
}
```

#### 3.4.4 Agent Worker Context Hydration

On session start:
1. Fetch last 50 events for space: `GET /v1/spaces/{space_id}/events?limit=50`
2. Fetch relevant memories: `POST /v1/recall` with "session context" query
3. Build context block:
   - Persona (from agent config or hardcoded)
   - Relevant memories
   - Recent space summary
   - Tool/action policy

#### 3.4.5 Tests

| Test File | Tests |
|-----------|-------|
| `tests/test_recall_api.py` (new) | Recall endpoint with pgvector |
| `tests/test_space_events_api.py` (new) | Events endpoint with privacy check |
| `tests/test_agent_rejoin.py` | Update for context hydration |

**Acceptance Criteria**:
- [ ] Leave and rejoin space → agent behaves consistently
- [ ] Memories are actually used in responses (not just stored)
- [ ] Actions proposed by planner show up reliably

**Risk**: Medium — requires pgvector working correctly
**Estimate**: 4–5 hours

---

### Phase 5: Spec 5 — Real-time Event Stream

**Goal**: Make the GUI feel alive with WebSocket broadcasting.

#### 3.5.1 New Shared Module

**File**: `layers/shared/python/agent_hub/broadcast.py`

```python
def broadcast_to_subscribers(
    *,
    event_type: str,  # "events.new", "actions.updated", "presence.updated"
    agent_id: str,
    space_id: str | None,
    payload: dict,
) -> int:
    """
    Query WsConnectionsTable for matching subscriptions.
    Post messages via API Gateway Management API.
    Returns count of messages sent.
    """
```

#### 3.5.2 Integration Points

| Location | Event Type | Trigger |
|----------|------------|---------|
| `/v1/events` ingestion | `events.new` | After event inserted |
| Planner | `actions.updated` | After action created |
| Planner | `memories.new` | After memory created |
| Tool runner | `actions.updated` | After status change |
| Heartbeat | `presence.updated` | After presence updated |

#### 3.5.3 Code Changes

| File | Change |
|------|--------|
| `layers/shared/python/agent_hub/broadcast.py` (new) | Broadcast module |
| `functions/hub_api/api_app.py` | Call broadcast after `/v1/events` |
| `functions/planner/handler.py` | Call broadcast after actions/memories |
| `functions/tool_runner/handler.py` | Call broadcast after action update |
| `functions/hub_api/api_app.py` | Call broadcast after heartbeat |

#### 3.5.4 WebSocket Message Types (Server → Client)

```json
{"type": "events.new", "agent_id": "...", "space_id": "...", "event": {...}}
{"type": "actions.updated", "agent_id": "...", "action_id": "...", "status": "..."}
{"type": "presence.updated", "agent_id": "...", "space_id": "...", "device_id": "...", "status": "online"}
```

#### 3.5.5 GUI Updates

| File | Change |
|------|--------|
| `functions/hub_api/static/js/marvain.js` | Handle broadcast messages, update UI |
| `functions/hub_api/templates/actions.html` | Auto-refresh on `actions.updated` |
| `functions/hub_api/templates/devices.html` | Auto-refresh on `presence.updated` |

#### 3.5.6 Tests

| Test File | Tests |
|-----------|-------|
| `tests/test_broadcast.py` (new) | Broadcast module unit tests |
| `tests/test_ws_broadcast_integration.py` (new) | End-to-end broadcast |

**Acceptance Criteria**:
- [ ] Actions page updates without manual refresh
- [ ] Devices online state updates without polling
- [ ] Events page shows new events in real-time

**Risk**: Medium — requires DynamoDB GSI for efficient subscription lookup
**Estimate**: 4–5 hours

---

## 4. Testing Strategy

### 4.1 Test Requirements per Phase

| Phase | Unit Tests | Integration Tests | Min Coverage |
|-------|------------|-------------------|--------------|
| Phase 0 | Update existing | GUI routes work | 80% of changes |
| Phase 1 | 5+ tests | Scope enforcement | 85% |
| Phase 2 | 5+ tests | Daemon lifecycle | 80% |
| Phase 3 | 5+ tests | Action lifecycle | 85% |
| Phase 4 | 5+ tests | Recall API | 85% |
| Phase 5 | 5+ tests | Broadcast E2E | 80% |

### 4.2 Test Patterns

Following existing patterns in `tests/`:
- Use `unittest.TestCase` with `unittest.mock`
- Load `hub_api/app.py` via `_load_hub_api_app_module()` helper
- Mock `boto3.client`, database, and external services
- Use `fastapi.testclient.TestClient` for API tests

### 4.3 Test Commands

```bash
# Run all tests with coverage
pytest -q --cov=functions --cov=layers --cov-report=term-missing

# Run specific phase tests
pytest tests/test_device_scopes.py tests/test_hub_api_devices.py -v

# Check formatting before commit
ruff check . && ruff format --check .
```

---

## 5. Git Workflow

### 5.1 Branch Strategy

| Phase | Branch Name |
|-------|-------------|
| All | `feature/advanced-features-spec0-5` (main feature branch) |
| Sub-branch (optional) | `feature/advanced-features-spec0` for isolated work |

### 5.2 Commit Boundaries

Each commit should be a logical unit:

1. **Phase 0 commits**:
   - `feat(db): add migration 005 for users columns and legacy cleanup`
   - `refactor(api): replace memberships with agent_memberships`
   - `test: verify agent_memberships migration`

2. **Phase 1 commits**:
   - `feat(db): add migration 006 for device enhancement`
   - `feat(api): add scope enforcement to v1 endpoints`
   - `feat(api): add device heartbeat endpoint`
   - `feat(ws): add device command messages`

3. **Phase 2 commits**:
   - `refactor(db): remove migration 007 (remotes to devices) -- legacy cleanup`
   - `feat(app): add remote satellite daemon skeleton`
   - `refactor: remove legacy remotes page entirely`

4. **Phase 3 commits**:
   - `feat(db): add migration 008 for action enhancement`
   - `feat(api): complete action lifecycle with results`
   - `feat(tools): add device_command tool`

5. **Phase 4 commits**:
   - `feat(api): add /v1/recall endpoint`
   - `feat(api): add space events endpoint`
   - `feat(worker): add context hydration on rejoin`

6. **Phase 5 commits**:
   - `feat(shared): add broadcast module`
   - `feat(api): integrate broadcast on event ingestion`
   - `feat(gui): add real-time UI updates`

### 5.3 Commit Message Format

```
type(scope): brief description

- Detail 1
- Detail 2

Refs: ADVANCED_FEATURE_PLAN.md Spec X
```

---

## 6. Rollback Strategy

### 6.1 Database Migrations

All migrations are **additive** (ADD COLUMN, RENAME TABLE):
- No data deletion
- Can be rolled back by reversing (DROP COLUMN, RENAME back)

### 6.2 Code Rollback

```bash
# Revert to main branch
git checkout main

# Or revert specific commits
git revert <commit-hash>
```

### 6.3 Deployment Rollback

```bash
# Redeploy previous SAM version
./bin/marvain deploy --no-guided
```

### 6.4 Data Safety

- `legacy_memberships` preserved (not dropped)
- `legacy_remotes (REMOVED)` preserved (not dropped)
- Audit bucket has Object Lock (immutable)

---

## 7. Open Questions

### 7.1 Clarification Needed

1. **Remote daemon distribution**: Should the remote daemon be packaged as a pip-installable package, or distributed via other means (Docker, binary)?

2. **Scope granularity**: The spec mentions `events:write`, `memories:read`, etc. Should these be exact strings, or support wildcards like `*:read`?

3. **Broadcast rate limiting**: Should we limit broadcast frequency to prevent flooding clients during high-activity periods?

4. **Memory detail view**: The spec mentions "viewMemory is a toast stub". Should we implement a modal or a separate page for memory details?

5. **Action auto-approve logic**: Currently `auto_approve` is set by the planner. Should there be a configurable policy (per-agent or per-kind)?

### 7.2 Assumptions Made

1. **pgvector is working**: The recall API assumes pgvector extension is installed and embeddings are being stored.

2. **WebSocket Management API access**: The broadcast module requires Lambda to have `execute-api:ManageConnections` permission.

3. **DynamoDB GSI for subscriptions**: Efficient subscription lookup may require a GSI on `WsConnectionsTable`.

4. **No breaking API changes**: All changes are additive; existing endpoints continue to work.

---

## 8. Summary and Timeline

| Phase | Description | Estimate | Dependencies |
|-------|-------------|----------|--------------|
| Phase 0 | Fix identity/permission spine | 2–3 hours | None |
| Phase 1 | Devices fully functional | 3–4 hours | Phase 0 |
| Phase 2 | Devices (legacy remotes removed) | 4–5 hours | Phase 0, Phase 1 |
| Phase 3 | Actions fully functional | 4–5 hours | Phase 0 |
| Phase 4 | Core agent + memories | 4–5 hours | Phase 0 |
| Phase 5 | Real-time event stream | 4–5 hours | Phase 3, Phase 4 |

**Total estimated time**: 22–27 hours of implementation work

**Recommended execution order**:
1. Phase 0 (prerequisite)
2. Phase 1 + Phase 3 (parallel or sequential)
3. Phase 2 (after Phase 1)
4. Phase 4 (after Phase 0)
5. Phase 5 (after Phase 3 + Phase 4)

---

## 9. Approval Checklist

- [x] Major has reviewed this implementation plan
- [x] Open questions have been answered (defaults used)
- [x] Branch naming convention confirmed
- [x] Test coverage expectations confirmed
- [x] Ready to proceed with Phase 0

---

## 10. Implementation Summary

### Completion Status

All 6 phases (Specs 0-5) have been successfully implemented.

| Phase | Spec | Commit | Status |
|-------|------|--------|--------|
| 0 | Fix Identity/Permission Spine | `c5abd1f` | ✅ Complete |
| 1 | Devices Fully Functional | `24f9d3f` | ✅ Complete |
| 2 | Devices (legacy remotes removed) | `2c73b39` | ✅ Complete |
| 3 | Actions Fully Functional | `8938244` | ✅ Complete |
| 4 | Core Agent + Memories | `806bdd7` | ✅ Complete |
| 5 | Real-time Event Stream | `4604d61` | ✅ Complete |

### Test Coverage

- **229/230 tests passing** (99.6%)
- 1 failure is a **pre-existing OAuth state validation issue** (`test_auth_callback_sets_access_cookie_on_success`) unrelated to these changes

### Files Changed

**New Files Created:**
- `sql/005_users_columns_and_legacy_cleanup.sql` - Migration for users columns and legacy memberships cleanup
- `sql/006_devices_enhancement.sql` - Device scopes, heartbeat, command channel
- `sql/007_remotes_to_devices.sql (DELETED)` - Migrate remotes to devices table
- `sql/008_actions_enhancement.sql` - Action lifecycle columns (result, error, timestamps)
- `layers/shared/python/agent_hub/broadcast.py` - WebSocket broadcast module
- `layers/shared/python/agent_hub/tools/device_command.py` - Device command tool
- `apps/remote_satellite/` - Remote satellite daemon (daemon.py, hub_client.py, README.md)

**Modified Files:**
- `functions/hub_api/api_app.py` - New endpoints, scope enforcement, broadcast integration
- `functions/hub_api/app.py` - Legacy memberships → agent_memberships, new GUI routes
- `functions/planner/handler.py` - Broadcast on memory/action creation
- `functions/tool_runner/handler.py` - Broadcast on action completion, result persistence
- `functions/ws_message/handler.py` - Device command message handling
- `apps/agent_worker/worker.py` - Context hydration, space events, memory recall
- `layers/shared/python/agent_hub/auth.py` - Device scope enforcement
- `layers/shared/python/agent_hub/tools/registry.py` - Device command tool registration
- `functions/hub_api/static/js/marvain.js` - Real-time broadcast handlers

### New API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/recall` | POST | Semantic memory search with embeddings |
| `/v1/spaces/{space_id}/events` | GET | Fetch recent events for a space |
| `/v1/devices/heartbeat` | POST | Device heartbeat with presence broadcast |
| `/v1/agents/{agent_id}/tokens` | GET/POST | Agent-to-agent token management |
| `/v1/agents/{agent_id}/tokens/{token_id}` | GET | Get specific agent token |
| `/v1/agents/{agent_id}/tokens/{token_id}/revoke` | POST | Revoke agent token |

### WebSocket Broadcast Events

| Event Type | Trigger | Payload |
|------------|---------|---------|
| `events.new` | Event ingestion | `{event: {event_id, type, payload, person_id}}` |
| `actions.updated` | Action create/execute | `{action_id, kind, status, has_result?}` |
| `presence.updated` | Device heartbeat | `{device_id, status, last_heartbeat_at}` |
| `memories.new` | Memory creation | `{memory_id}` |

### Known Limitations

1. **OAuth test failure**: Pre-existing issue with `test_auth_callback_sets_access_cookie_on_success` - state validation mismatch
2. **Remote satellite**: Requires manual installation and configuration (see `apps/remote_satellite/README.md`)
3. **Broadcast rate limiting**: Not implemented (could be added if needed)

### Follow-up Work (Optional)

1. Fix the pre-existing OAuth state validation test
2. Add broadcast rate limiting if high-frequency updates cause issues
3. Create pip package for remote satellite daemon
4. Add memory detail view modal in GUI
5. Implement per-agent or per-kind action auto-approve policy configuration

---

**Do this next:**

1. Push feature branch: `git push origin feature/advanced-features-spec0-5`
2. Create PR for review
3. Review and merge when ready

