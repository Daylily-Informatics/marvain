# Phase 2: Hub Dashboard Redesign — Dense Ops Console

> **Parent plan**: [GUI_OVERHAUL_PLAN.md](../GUI_OVERHAUL_PLAN.md)
> **Risk**: Medium — new queries, template redesign
> **Depends on**: Phase 1 (macros and CSS foundation)

## Overview

Redesign the home page into a single-screen operations console: agent status panel, live event feed (HTMX polling or WS-driven), device health matrix, pending actions queue, and memory count sparkline — all visible at once.

## Scope

- `functions/hub_api/templates/home.html` — complete redesign
- `functions/hub_api/app.py` `gui_home()` — enrich context data (recent events, device health)
- `functions/hub_api/static/css/marvain.css` — add dashboard-specific layout classes
- New partial templates for dashboard widgets (via macros or includes)

## Definition of Done

- Home page shows: agent status, live event ticker, device health grid, pending action count + top-3, memory stats — all above the fold on a 1080p display
- No page navigation required to get a full operational picture
- HTMX or WS used for at least one live-updating widget

## Verification

```bash
# Visual inspection at 1920×1080 — all panels visible without scroll

# HTMX polling endpoint returns fresh data
curl -s http://localhost:8443/api/dashboard/events | jq .

# Load test: home page renders in <500ms with 100 memories, 10 devices, 50 events
```

