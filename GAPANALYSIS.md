# Gap Analysis: ADVANCED_FEATURE_PLAN.md vs Implementation

**Branch:** `feature/review-fixes-r1-r10`
**Date:** 2026-02-06 (updated — all gaps closed)
**Auditor:** Forge (Augment Agent)

---

## Executive Summary

| Spec | Status | Gaps |
|------|--------|------|
| Spec 0 | ✅ COMPLETE | None |
| Spec 1 | ✅ COMPLETE | GAP-1 closed (2026-02-06) |
| Spec 2 | ✅ COMPLETE | GAP-2 closed (2026-02-06) |
| Spec 3 | ✅ COMPLETE | GAP-3 closed (2026-02-06) — depended on GAP-1 |
| Spec 4 | ✅ COMPLETE | None |
| Spec 5 | ✅ COMPLETE | None |

**Overall:** All 6 specs fully complete. All gaps closed as of 2026-02-06.

---

## Spec 0: Fix Identity/Permission Spine

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Stop using `memberships` table | ✅ | All 21 SQL references in `app.py` use `agent_memberships` |
| Rename to `legacy_memberships` | ✅ | Migration 005 renames table |
| Add `users.display_name` | ✅ | Migration 005: `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text` |
| Add `users.last_seen` | ✅ | Migration 005: `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz` |

### Files Verified
- `sql/005_users_columns_and_legacy_cleanup.sql`
- `functions/hub_api/app.py` (21 references to `agent_memberships`)

---

## Spec 1: Devices Fully Functional

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Add `metadata`, `last_hello_at`, `last_heartbeat_at` columns | ✅ | Migration 006 |
| Scope enforcement on `/v1/*` endpoints | ✅ | 8 calls to `require_scope()` in `api_app.py` |
| `POST /v1/devices/heartbeat` | ✅ | Lines 882-930 in `api_app.py` |
| WS hello updates `last_hello_at` | ✅ | Lines 259-262 in `ws_message/handler.py` |
| Device command channel (`cmd.ping`, `cmd.pong`, etc.) | ✅ | Broadcast via `_send_to_device()` using GSI query |

### ~~GAP-1~~ CLOSED (2026-02-06)

Device command broadcast fully implemented in `ws_message/handler.py`:
- `_get_device_connections()` queries DynamoDB GSI `device_id_index` (with scan fallback)
- `_send_to_device()` broadcasts to all device connections via API Gateway Management API
- `cmd.ping`, `cmd.run_action`, `cmd.config` all forward to target device
- Stale connection cleanup on `GoneException`
- 3 tests per command type (broadcast, not-connected, permissions)

---

## Spec 2: Remotes as Devices

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Migrate remotes to devices table | ✅ | Migration 007 with `metadata.is_remote = true` |
| Create remote satellite daemon | ✅ | `apps/remote_satellite/daemon.py` exists |
| Daemon sends hello and heartbeat | ✅ | `hub_client.py` implements periodic heartbeat |
| Daemon responds to `cmd.ping` | ✅ | `hub_client.py` handles ping |
| Daemon executes actions | ✅ | Full action dispatch in `daemon.py` |

### ~~GAP-2~~ CLOSED (2026-02-06)

Remote action execution fully implemented in `daemon.py`:
- `_action_ping()`, `_action_status()`, `_action_echo()` built-in handlers
- `_action_shell_command()` with SAFE_SHELL_COMMANDS allowlist
- `_action_device_status()` returns comprehensive system info (disk, memory, uptime)
- `cmd.config` handler applies configuration updates

---

## Spec 3: Actions Fully Functional

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Add `approved_by`, `approved_at` columns | ✅ | Migration 008 |
| Add `result`, `error`, `completed_at` columns | ✅ | Migration 008 |
| Approval records approver info | ✅ | `ws_message/handler.py` lines 106-113 |
| Tool runner persists results | ✅ | `tool_runner/handler.py` lines 120-137 |
| Tool runner broadcasts completion | ✅ | `tool_runner/handler.py` lines 149-162 |
| `device_command` tool exists | ✅ | `layers/shared/python/agent_hub/tools/device_command.py` |
| `device_command` tool works | ✅ | GAP-1 closed — full broadcast chain functional |

### ~~GAP-3~~ CLOSED (2026-02-06)

Resolved by closure of GAP-1. The `device_command` tool now has a working broadcast path:
`device_command` → WS handler `cmd.*` → `_send_to_device()` → target device connection.

---

## Spec 4: Core Agent + Memories

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| `POST /v1/recall` endpoint | ✅ | Lines 690-761 in `api_app.py` |
| `GET /v1/spaces/{space_id}/events` endpoint | ✅ | Lines 789-838 in `api_app.py` |
| `GET /api/memories/{memory_id}` endpoint | ✅ | Lines 2142-2189 in `app.py` |
| Agent worker fetches space events | ✅ | `_fetch_space_events()` in `worker.py` |
| Agent worker fetches recall memories | ✅ | `_fetch_recall_memories()` in `worker.py` |
| Context hydration on session start | ✅ | Lines 255-270 in `worker.py` |

---

## Spec 5: Real-time Event Stream

### Status: ✅ COMPLETE

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Broadcast module exists | ✅ | `layers/shared/python/agent_hub/broadcast.py` |
| Integrated into `/v1/events` | ✅ | Lines 607-635 in `api_app.py` |
| Integrated into planner | ✅ | Lines 356-388 in `planner/handler.py` |
| Integrated into tool runner | ✅ | Lines 149-162 in `tool_runner/handler.py` |
| GUI handles `events.new` | ✅ | `_handleBroadcast()` in `marvain.js` |
| GUI handles `actions.updated` | ✅ | `_handleBroadcast()` in `marvain.js` |
| GUI handles `presence.updated` | ✅ | `_handleBroadcast()` in `marvain.js` |
| GUI handles `memories.new` | ✅ | `_handleBroadcast()` in `marvain.js` |

---

## Additional Observations (Outside Spec Scope)

### Agent Deletion

**Q: Should users be able to delete agents from the GUI?**

**Current state:** No DELETE endpoint for agents exists. The spec does not mention agent deletion.

**Recommendation:** This is intentional - agents are meant to be persistent identities. Deletion would orphan events, memories, actions, devices, etc. If needed, consider a "disable" or "archive" pattern instead.

### View Button vs Members Button

**Q: Should these do the same thing?**

**Current behavior:**
- **View button:** Navigates to `/agents/{agent_id}` (agent detail page)
- **Members button:** Navigates to `/agents/{agent_id}#members` (same page, scrolls to members section)

**Analysis:** This is correct behavior. The Members button is a shortcut to the members section on the agent detail page. They show the same page but with different scroll positions.

---

## Recommended Actions

All gaps are now closed. The following optional enhancements remain:

### Optional: Agent Archival

If agent deletion is desired:
1. Add `archived_at` column to agents table
2. Add `POST /api/agents/{agent_id}/archive` endpoint
3. Archived agents are hidden from listings but data is preserved

