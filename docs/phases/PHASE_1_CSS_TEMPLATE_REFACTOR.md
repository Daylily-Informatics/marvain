# Phase 1: GUI Foundation — CSS & Template Refactor

> **Parent plan**: [GUI_OVERHAUL_PLAN.md](../GUI_OVERHAUL_PLAN.md)
> **Risk**: Low — cosmetic only, no backend logic or DB changes

## Overview

Modernize the CSS design system and eliminate inline styles from templates. Create Jinja2 macros for repeated UI patterns (cards, badges, filter bars, modals, empty states). Introduce HTMX for key interactions.

## Scope

- `functions/hub_api/static/css/marvain.css` — refactor into modular sections, add new utility classes
- `functions/hub_api/templates/base.html` — add HTMX script tag, refactor nav into a more compact/dense layout
- `functions/hub_api/templates/*.html` — replace inline `style=` attributes with CSS classes
- Create `functions/hub_api/templates/macros/` — Jinja2 macros for card, badge, filter-bar, modal, empty-state, stat-card
- **NOT in scope**: backend logic changes, DB schema changes

## Definition of Done

- Zero inline `style=` attributes in template files (or <5 remaining for truly one-off cases)
- All templates use shared macros for cards, modals, filter bars
- HTMX loaded in base template
- Visual regression: pages render identically (spot-check with browser)

## Verification

```bash
# Inline styles should be nearly eliminated
grep -r 'style=' functions/hub_api/templates/ | wc -l  # → <5

# Macro files exist
ls functions/hub_api/templates/macros/

# HTMX is loaded
grep 'htmx' functions/hub_api/templates/base.html

# Launch GUI locally, visually compare before/after screenshots
```

