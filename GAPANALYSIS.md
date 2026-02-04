# Gap Analysis: ADVANCED_FEATURE_PLAN.md vs Implementation

**Branch:** `feature/advanced-features-spec0-5`  
**Date:** 2026-02-03  
**Auditor:** Forge (Augment Agent)

---

## Executive Summary

| Spec | Status | Gaps |
|------|--------|------|
| Spec 0 | ✅ COMPLETE | None |
| Spec 1 | ⚠️ PARTIAL | Device command broadcast not implemented |
| Spec 2 | ⚠️ PARTIAL | Remote action execution is stub only |
| Spec 3 | ⚠️ PARTIAL | device_command depends on unimplemented broadcast |
| Spec 4 | ✅ COMPLETE | None |
| Spec 5 | ✅ COMPLETE | None |

**Overall:** 3 specs fully complete, 3 specs have functional gaps requiring follow-up work.

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

### Status: ⚠️ PARTIAL

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Add `metadata`, `last_hello_at`, `last_heartbeat_at` columns | ✅ | Migration 006 |
| Scope enforcement on `/v1/*` endpoints | ✅ | 8 calls to `require_scope()` in `api_app.py` |
| `POST /v1/devices/heartbeat` | ✅ | Lines 882-930 in `api_app.py` |
| WS hello updates `last_hello_at` | ✅ | Lines 259-262 in `ws_message/handler.py` |
| Device command channel (`cmd.ping`, `cmd.pong`, etc.) | ⚠️ | **Message types exist but don't broadcast to target device** |

### Gap Details

**GAP-1: Device Command Broadcast Not Implemented**

Location: `functions/ws_message/handler.py`

The following TODO comments exist:
- Line 348: `# TODO: In Phase 5, broadcast cmd.ping to the target device via WebSocket`
- Line 397: `# TODO: In Phase 5, broadcast cmd.run_action to the target device via WebSocket`
- Line 433: `# TODO: In Phase 5, broadcast cmd.config to the target device via WebSocket`

**Current behavior:** Commands are validated and acknowledged to the sender, but NOT forwarded to the target device.

**Impact:** Remote ping, device commands, and configuration updates are non-functional. The command is accepted but the target device never receives it.

---

## Spec 2: Remotes as Devices

### Status: ⚠️ PARTIAL

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Migrate remotes to devices table | ✅ | Migration 007 with `metadata.is_remote = true` |
| Create remote satellite daemon | ✅ | `apps/remote_satellite/daemon.py` exists |
| Daemon sends hello and heartbeat | ✅ | `hub_client.py` implements periodic heartbeat |
| Daemon responds to `cmd.ping` | ✅ | `hub_client.py` handles ping |
| Daemon executes actions | ⚠️ | **Stub only - returns "not_implemented"** |

### Gap Details

**GAP-2: Remote Action Execution is Stub**

Location: `apps/remote_satellite/daemon.py`, lines 49-61

```python
if msg_type == "cmd.run_action":
    kind = msg.get("kind", "")
    payload = msg.get("payload", {})
    logger.info("Received run_action command: kind=%s", kind)

    # TODO: Implement device-local action execution
    # For now, just acknowledge receipt
    return {
        "action": "action_result",
        "kind": kind,
        "status": "not_implemented",
        "message": f"Action kind '{kind}' not implemented on this device",
    }
```

Also line 66-67:
```python
elif msg_type == "cmd.config":
    # TODO: Apply configuration changes
```

**Impact:** Remote satellites can connect and report presence, but cannot execute any actual device-local actions.

---

## Spec 3: Actions Fully Functional

### Status: ⚠️ PARTIAL

### Verification

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Add `approved_by`, `approved_at` columns | ✅ | Migration 008 |
| Add `result`, `error`, `completed_at` columns | ✅ | Migration 008 |
| Approval records approver info | ✅ | `ws_message/handler.py` lines 106-113 |
| Tool runner persists results | ✅ | `tool_runner/handler.py` lines 120-137 |
| Tool runner broadcasts completion | ✅ | `tool_runner/handler.py` lines 149-162 |
| `device_command` tool exists | ✅ | `layers/shared/python/agent_hub/tools/device_command.py` |
| `device_command` tool works | ⚠️ | **Depends on GAP-1 (command broadcast)** |

### Gap Details

**GAP-3: device_command Tool Depends on Unimplemented Feature**

The `device_command` tool in `tools/device_command.py` sends commands via WebSocket to connected devices. However, since GAP-1 (device command broadcast) is not implemented in the WS message handler, this tool chain is incomplete.

**Current behavior:** The tool can find a device and attempt to send a command, but the device never receives it because the WS handler doesn't forward commands.

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

### Priority 1: Close GAP-1 (Device Command Broadcast)

Implement actual broadcast in `ws_message/handler.py`:
1. Query DynamoDB for WebSocket connections matching `target_device_id`
2. Send command message via API Gateway Management API
3. This unblocks GAP-3 (device_command tool)

### Priority 2: Close GAP-2 (Remote Action Execution)

This is lower priority as it's device-specific:
1. Define a standard set of device actions (ping, status, restart, etc.)
2. Implement handlers in `daemon.py`
3. Document how users extend with custom actions

### Optional: Agent Archival

If agent deletion is desired:
1. Add `archived_at` column to agents table
2. Add `POST /api/agents/{agent_id}/archive` endpoint
3. Archived agents are hidden from listings but data is preserved

