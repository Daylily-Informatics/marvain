# Gap Analysis — Marvain (2026-02-07)

**Branch:** `main` (post-merge of PR #31)
**Auditor:** Forge (Augment Agent)
**Method:** Full read-only review of all Python, SQL, JavaScript, HTML templates, and documentation.

---

## Executive Summary

**Overall completeness: ~97%** — Specs 0-5 are implemented end-to-end. The codebase has working pipelines for event ingestion → memory creation → action execution → real-time broadcast. All GUI pages exist with functional CRUD and WebSocket live updates.

**Gaps found: 6** (0 critical, 2 medium, 4 minor)

| # | Severity | Gap | Impact |
|---|----------|-----|--------|
| G1 | **MEDIUM** | Home dashboard Devices stat hardcoded to "—" | Dashboard shows wrong data |
| G2 | **MEDIUM** | Main nav bar missing 5 pages | Users can't discover Events, Memories, People, Audit, LiveKit |
| G3 | MINOR | Home Devices card always shows empty-state | No device preview like Agents card has |
| G4 | MINOR | People/Consent page unreachable from any nav/link | Only accessible via direct URL `/people` |
| G5 | MINOR | No device daemon onboarding UX | GUI-created devices show "Offline" with no guidance |
| G6 | MINOR | README line 262 says worker is a "skeleton" | Outdated — worker is fully functional |

---

## Verified as COMPLETE (no gaps)

All items below were verified by tracing code from ingestion → storage → query → GUI rendering → WebSocket broadcast.

| Spec | Summary | Key Evidence |
|------|---------|--------------|
| Spec 0 | Identity spine: `agent_memberships`, `users.display_name`, `users.last_seen` | `sql/005`, 21 refs in `app.py` |
| Spec 1 | Consent: `people`, `consent_grants`, privacy_mode enforcement | `app.py:1595-1730`, `planner:216-220` |
| Spec 2 | Devices: legacy remotes fully removed, satellite daemon functional | PR #31 merged |
| Spec 3 | Actions: proposal → approval → SQS → tool_runner → broadcast | `tool_runner:103-127`, `actions.html` |
| Spec 4 | Context hydration: agent fetches events+memories on session start | `worker.py:256-271` |
| Spec 5 | Broadcast: DynamoDB subscriptions → API Gateway Management API | `broadcast.py:99-166`, `marvain.js` |
| Memory chain | Events → TranscriptQueue → Planner → memories w/embeddings → broadcast | `planner:305-326`, `template.yaml:514` |
| Action chain | GUI approve → ActionQueue → ToolRunner → execute → broadcast | `tool_runner:127`, `actions.html:414-465` |
| LiveKit test | Full WebRTC page with audio/video/chat/transcript/debug panel | `livekit_test.html` (1205 lines) |
| Audit log | GUI viewer exists and renders entries from S3 | `app.py:gui_audit`, `audit.html` |

---

## Gap Details

### G1 — Home Dashboard Devices Stat Hardcoded (MEDIUM)

**What:** The Devices stat card on the home dashboard displays a literal `—` dash instead of the actual device count.

**Evidence:**
- `functions/hub_api/templates/home.html` line 18: `<div class="stat-value">—</div>` (hardcoded)
- `functions/hub_api/app.py` lines 604-617: `gui_home()` passes `agents_count`, `spaces_count`, `pending_actions` to the template but **never queries or passes** `devices_count`
- Compare to Agents: `"agents_count": len(agents_data)` (line 612) — works correctly
- Compare to Spaces: `"spaces_count": len(spaces)` (line 613) — works correctly

**Fix:** Query device count for the user's agents and pass `devices_count` to the template. Update `home.html` line 18 to `{{ devices_count }}`.

**Effort:** ~15 lines of code.

---

### G2 — Main Nav Bar Missing 5 Pages (MEDIUM)

**What:** The header navigation (`base.html` lines 36-52) only links to: Home, Agents, Spaces, Devices, Actions. Five implemented pages are absent:

| Page | Route | Has GUI? | In Nav? | In Quick Actions? |
|------|-------|----------|---------|-------------------|
| Events | `/events` | ✅ Full page | ❌ | ✅ |
| Memories | `/memories` | ✅ Full page | ❌ | ✅ |
| People/Consent | `/people` | ✅ Full page | ❌ | ❌ |
| Audit | `/audit` | ✅ Full page | ❌ | ✅ |
| LiveKit Test | `/livekit-test` | ✅ Full page | ❌ | ✅ |

**Impact:** Users must know URLs or find links buried in the home Quick Actions section. People/Consent has **zero** navigation links anywhere — it's only reachable by typing `/people` directly.

**Fix:** Add Events, Memories, and People to the main nav. Consider a "More" dropdown for Audit, LiveKit, Artifacts.

**Effort:** ~20 lines in `base.html`.

---

### G3 — Home Devices Card Always Shows Empty State (MINOR)

**What:** The home page Devices card (`home.html` lines 56-69) always renders an empty-state placeholder ("Manage your devices") regardless of how many devices exist. The Agents card (lines 71-103) dynamically lists up to 5 agents.

**Fix:** Query recent devices in `gui_home()` and render them like the agents list.

**Effort:** ~30 lines.

---

### G4 — People/Consent Page Has No Navigation Path (MINOR)

**What:** The People & Consent page (`/people`, `gui_people`) is not linked from:
- Main nav bar
- Home page Quick Actions section
- Any other page

It is only reachable by typing `/people` in the browser. The page itself is fully functional (create people, manage consent grants).

**Fix:** Add to nav bar (G2 fix) and/or add to Quick Actions on home.

**Effort:** 1-2 lines.

---

### G5 — No Device Daemon Onboarding UX (MINOR)

**What:** When a user creates a device via the GUI, the device shows "Offline" because no satellite daemon is running for it. There is no guidance in the GUI on how to:
1. Download/install the remote satellite daemon
2. Configure it with the device token
3. Start it

The satellite daemon (`apps/remote_satellite/daemon.py`) is fully functional — it just has no GUI-driven setup flow.

**Fix:** Add an onboarding panel on the device detail page with copy-pasteable setup commands (similar to the "Running an Agent Worker" collapsible in `livekit_test.html`).

**Effort:** ~40 lines of HTML.

---

### G6 — README Says Worker Is a "Skeleton" (MINOR)

**What:** `README.md` line 262: _"This repo does not ship a full satellite app yet; it ships a worker skeleton."_

This is outdated. The agent worker (`apps/agent_worker/worker.py`) is a fully functional LiveKit agent with:
- OpenAI Realtime API integration
- Transcript ingestion to Hub
- Context hydration (events + memories)
- Typed chat via data channel

**Fix:** Update the README paragraph to reflect current state.

**Effort:** 5 lines.

---

## Prioritized Implementation Plan

All 6 gaps can be fixed in a single focused session. No architectural changes needed.

### Phase 1: Dashboard Data (G1 + G3) — ~45 lines

1. In `gui_home()` (`app.py`): query device count and recent devices for the user's agents
2. Pass `devices_count` and `recent_devices` to the template
3. In `home.html`: replace hardcoded `—` with `{{ devices_count }}`
4. In `home.html`: replace devices empty-state with dynamic device list (matching agents card pattern)

### Phase 2: Navigation (G2 + G4) — ~25 lines

1. In `base.html`: add Events, Memories, People to header nav
2. Consider a "More" dropdown or second row for Audit, LiveKit Test, Artifacts
3. In `home.html`: add People/Consent to Quick Actions section

### Phase 3: Device Onboarding UX (G5) — ~40 lines

1. In `device_detail.html`: add collapsible "Getting Started" panel with:
   - Install instructions for the satellite daemon
   - Pre-filled command with the device token
   - Link to `apps/remote_satellite/README.md`

### Phase 4: Documentation (G6) — ~5 lines

1. Update `README.md` line 262 to accurately describe the agent worker

### Total Estimated Effort

| Phase | Lines Changed | Files |
|-------|--------------|-------|
| Phase 1 | ~45 | `app.py`, `home.html` |
| Phase 2 | ~25 | `base.html`, `home.html` |
| Phase 3 | ~40 | `device_detail.html` |
| Phase 4 | ~5 | `README.md` |
| **Total** | **~115** | **4 files** |

---

## What Was NOT Found (Claims Verified)

These items were explicitly checked and found to be **correctly implemented**, contradicting any assumption that they might be missing:

- ✅ Memory persistence (planner creates episodic + semantic memories with vector embeddings)
- ✅ Action approval/rejection workflow (GUI buttons + API endpoints + SQS processing)
- ✅ broadcast_fn wired in tool_runner (line 127: `broadcast_fn=_make_broadcast_fn(agent_id, space_id)`)
- ✅ Context hydration in agent worker (fetches 50 events + 8 recalled memories)
- ✅ Privacy mode blocks event processing in planner AND event ingestion in api_app
- ✅ Consent grants CRUD (create, revoke-all-then-recreate pattern)
- ✅ WebSocket real-time updates on all GUI pages (events, actions, memories, presence)
- ✅ Device command channel (cmd.ping, cmd.run_action, cmd.config) via DynamoDB GSI
- ✅ LiveKit test page with full audio/video/chat/transcript/debug panel
- ✅ Audit trail viewer reading from S3 Object Lock bucket

---

## Methodology

1. Read every `.py`, `.sql`, `.html`, `.js` file in the repository
2. Traced 3 end-to-end pipelines: transcript→memory, action→execution, event→broadcast
3. Compared `GAPANALYSIS.md` claims against actual code (all claims verified)
4. Compared `ADVANCED_FEATURE_PLAN.md` specs against implementation
5. Checked every GUI template for functional completeness
6. Checked nav bar and home page for discoverability of all features
7. Checked `template.yaml` for SQS queue wiring correctness
8. Verified all 18 CLI commands exist and are documented

---

**Awaiting review.** No code changes will be made until this analysis is approved.

