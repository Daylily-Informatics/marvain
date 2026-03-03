# GUI Overhaul & Agent Hub Plan

> **Date**: 2026-03-03
> **Status**: Proposed — awaiting approval

## Goal

Overhaul the Marvain GUI into a minimal, visually striking, information-dense agent operations hub — while also refactoring device/location onboarding, the action system extensibility, and the memory schema for richer metadata.

## Current State Assessment

**GUI** (`functions/hub_api/app.py` + templates + `marvain.css`):
- 11+ separate page templates, each server-rendered via Jinja2
- All pages are full-page navigations (no SPA behavior)
- Dark theme with decent CSS variables, but heavy/scattered inline styles
- Home page is a basic stat-cards + quick-links dashboard
- ~2,000 lines of CSS, ~4,200 lines of `app.py`

**Devices & Location Onboarding** (`devices.html`, `device_detail.html`):
- Device creation is a modal with manual scope checkboxes
- Satellite launch requires manually copying a token and clicking "Launch Satellite"
- No concept of "location" — devices are just named and scoped
- Remote satellite (`apps/remote_satellite/daemon.py`) connects via WebSocket but there's no streamlined GUI flow to provision a remote location end-to-end

**Actions** (`actions.html`, tool registry, `tool_runner`):
- 5 tools hardcoded in `_register_default_tools()`: send_message, create_memory, http_request, device_command, shell_command
- Adding a new tool requires: (1) write a Python module, (2) import it in registry.py, (3) add to the GUI's `action-kind` dropdown
- No plugin/discovery mechanism

**Memories** (DB schema `memories` table + `create_memory.py` + `memories.html`):
- Flat schema: `tier`, `content`, `participants` (JSON array of strings), `provenance` (JSON), `retention` (JSON), `embedding`
- No structured metadata: who the memory is *about*, scene context, modality, emotional valence, confidence score, relationships to other memories
- Participants are bare string IDs — no link to the `people` table
- No tagging, no categorization, no memory consolidation

---

## Architecture Decisions

1. **Keep Jinja2 SSR** — no SPA rewrite. Instead, introduce HTMX for partial-page updates where it makes pages feel snappier. This is the lowest-risk way to make the GUI feel modern without a full framework migration.
2. **Component-ize the CSS** — extract inline styles into reusable CSS classes. Reduce template duplication with Jinja2 macros.
3. **Location = Device + Place metadata** — extend the `devices` table with `location` (JSON: label, coordinates, timezone, room/area). The GUI gets a "Locations" view that groups devices by location and shows a streamlined provisioning wizard.
4. **Plugin-based tool registry** — tools auto-discovered from the `tools/` directory via `__init__.py` exports. The GUI action-kind dropdown populated dynamically from the registry, not hardcoded.
5. **Rich memory schema** — add DB columns for `subject_person_id`, `tags`, `scene_context`, `modality`, `confidence`, and `related_memories`. Migrate existing data.

---

## Phases Overview

| Phase | What | Risk |
|-------|------|------|
| **1. CSS/Template Refactor** | Eliminate inline styles, create Jinja2 macros, add HTMX | Low |
| **2. Dashboard Redesign** | Dense ops console home page | Medium |
| **3. Location Wizard** | Streamlined device+location provisioning | Medium |
| **4. Plugin Tool Registry** | Auto-discovered tools, tool catalog page | Low |
| **5. Rich Memories** | Structured metadata (subject, tags, scene, modality, confidence) | Medium |

Each phase is independently mergeable. Phase 1 lays the CSS/macro foundation the others build on.

---

## Acceptance Criteria

- GUI is visually minimal, dark-themed, information-dense — all key data visible on home screen without scrolling
- Device provisioning takes ≤5 clicks from "I want to add a location" to "satellite running"
- Adding a new action tool = adding a single Python file (no template/registry edits)
- Memories store rich metadata: subject, tags, scene context, modality, confidence, relationships
- All existing tests pass after changes
- No regressions in authentication, WebSocket, or API behavior

## Non-goals

- SPA/React rewrite (keep Jinja2 SSR + HTMX)
- Mobile-first responsive design (desktop-optimized is fine)
- Memory consolidation/summarization logic (future work)
- LiveKit/voice pipeline changes
- Deployment pipeline changes

## Assumptions

- HTMX 2.x via CDN is acceptable (confirm?)
- PostgreSQL supports `text[]` and `uuid[]` column types (yes, it does)
- The `people` table already has the data needed for `subject_person_id` foreign keys
- Local dev environment has all credentials configured

## Verification Plan

- `cd functions/hub_api && python -m pytest ../../tests/test_gui_app.py -v` — GUI tests pass
- `python -m pytest tests/ -v --ignore=tests/e2e` — all unit tests pass
- `ruff check . && ruff format --check .` — lint clean
- Visual spot-check: launch GUI, navigate all pages, verify no regressions

## Rollback Plan

- Each phase is a separate PR on a feature branch
- SQL migrations are additive (ADD COLUMN IF NOT EXISTS) — safe to leave in place
- If HTMX causes issues, remove the script tag and revert to full-page loads
- Tool registry changes are backward-compatible (old `register()` function still works alongside new auto-discovery)

