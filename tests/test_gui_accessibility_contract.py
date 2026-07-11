from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "functions" / "hub_api" / "templates"
STATIC = ROOT / "functions" / "hub_api" / "static"
WORKFLOW_MANIFEST = ROOT / "tests" / "e2e" / "gui_workflow_manifest.json"

PRIMARY_GUI_PAGES = {
    "dashboard",
    "agents",
    "people",
    "locations",
    "spaces",
    "devices",
    "sessions",
    "live-session",
    "memories",
    "recognition",
    "actions",
    "actions-guide",
    "tools",
    "personas",
    "tapdb-graph",
    "tapdb-query",
    "audit",
    "observability",
    "capability-matrix",
    "artifacts",
    "settings-profile",
}


def test_base_template_exposes_keyboard_and_live_region_landmarks() -> None:
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    assert 'class="skip-link" href="#main-content"' in base
    assert 'id="main-content"' in base
    assert 'id="marvain-announcer"' in base
    assert 'aria-live="polite"' in base
    assert 'id="mobile-nav-toggle"' in base
    assert 'aria-controls="primary-navigation"' in base
    assert 'aria-expanded="false"' in base
    assert 'id="primary-navigation"' in base


def test_shared_javascript_owns_accessible_navigation_modals_and_notifications() -> None:
    javascript = (STATIC / "js" / "marvain.js").read_text(encoding="utf-8")
    agents = (TEMPLATES / "agents.html").read_text(encoding="utf-8")

    for contract in (
        "_setMobileNavigation",
        "_trapModalFocus",
        "modalReturnFocus",
        "aria-modal",
        "aria-labelledby",
        "Dismiss notification",
        "aria-busy",
    ):
        assert contract in javascript
    assert "Marvain.hideModal = function" not in agents
    assert "Marvain.showModal('create-agent-modal')" in agents


def test_styles_include_visible_focus_mobile_navigation_and_reduced_motion() -> None:
    css = (STATIC / "css" / "marvain.css").read_text(encoding="utf-8")

    assert ":focus-visible" in css
    assert ".skip-link:focus" in css
    assert ".header-nav.is-open" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert ".toast-close" in css


def test_branded_error_templates_are_present_and_recoverable() -> None:
    not_found = (TEMPLATES / "404.html").read_text(encoding="utf-8")
    server_error = (TEMPLATES / "500.html").read_text(encoding="utf-8")

    assert "Page Not Found - Marvain" in not_found
    assert "Dashboard" in not_found
    assert "Service Error - Marvain" in server_error
    assert "Retry" in server_error
    assert "Observability" in server_error


def test_gui_does_not_offer_permanent_delete_controls() -> None:
    rendered_sources = "\n".join(path.read_text(encoding="utf-8") for path in sorted(TEMPLATES.rglob("*.html"))).lower()
    forbidden = (
        "permanently delete",
        "permanently deleted",
        "this action cannot be undone",
        ">delete agent<",
        ">delete space<",
        ">delete device<",
        "function deletememory(",
        "function deletedevice(",
        "function confirmdeletespace(",
    )
    for phrase in forbidden:
        assert phrase not in rendered_sources


def test_gui_workflow_manifest_requires_page_specific_persisted_proof() -> None:
    manifest = json.loads(WORKFLOW_MANIFEST.read_text(encoding="utf-8"))
    workflows = manifest["workflows"]

    assert manifest["schema"] == "marvain.gui-workflows.v1"
    assert manifest["screenshot_phases"] == ["before", "before_submit", "after_submit"]
    assert {workflow["page"] for workflow in workflows} == PRIMARY_GUI_PAGES
    assert len({workflow["id"] for workflow in workflows}) == len(workflows)

    commands = set()
    for workflow in workflows:
        assert workflow["path"].startswith("/")
        assert workflow["heading"]
        assert len(workflow["browser_steps"]) >= 2
        assert workflow["command"] not in commands
        commands.add(workflow["command"])

        postcondition = workflow["persisted_postcondition"]
        assert postcondition["owner"]
        assert postcondition["request"].startswith("GET ")
        assert len(postcondition["assert"]) >= 2
        assert "route renders" not in " ".join(postcondition["assert"]).lower()

    raw = WORKFLOW_MANIFEST.read_text(encoding="utf-8")
    assert "MVN-" not in raw
    assert "M-" not in raw
