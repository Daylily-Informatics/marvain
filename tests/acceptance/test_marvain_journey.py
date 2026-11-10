"""Attended acceptance journey using real sign-in, microphone and audible response.

Explicit opt-in only. No fake microphone, canned response, stored browser cookies,
resource provisioning, teardown, or inferred environment. Run with pytest -s only
when authorized. The operator completes Google MFA and browser media prompts.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"{name} is required")
    return value


def test_chrome_voice_reply() -> None:
    if os.environ.get("MARVAIN_ATTENDED_ACCEPTANCE") != "1":
        pytest.skip("Real microphone acceptance requires explicit attended opt-in")
    from playwright.sync_api import sync_playwright, expect

    base = _required("MARVAIN_ACCEPTANCE_BASE_URL").rstrip("/")
    space_id = _required("MARVAIN_ACCEPTANCE_SPACE_ID")
    agent_id = _required("MARVAIN_ACCEPTANCE_AGENT_ID")
    setup = Path(_required("MARVAIN_ACCEPTANCE_SETUP_RECEIPT"))
    output = Path(_required("MARVAIN_ACCEPTANCE_OUTPUT"))
    assert base.startswith("https://"), "Use the deployed HTTPS Hub"
    assert setup.is_absolute() and output.is_absolute(), "Receipt paths must be absolute"
    preparation = json.loads(setup.read_text())
    # Consume the recorded owning results. Do not repeat deployment or inventory probes.
    assert preparation["agent_id"] == agent_id
    assert preparation["space_id"] == space_id
    assert preparation["browser_activation"]["status"] == "written"
    assert preparation["responder_activation"]["status"] == "success"
    assert preparation["recording_policy"] == "private_owner_and_agent_retain_until_revoked"
    assert preparation["hub_release"] and preparation["responder_release"]
    assert preparation["deployment_receipt"]
    steps = []
    with sync_playwright() as playwright:
        # A fresh isolated Chrome context makes the real login part of the journey.
        browser = playwright.chromium.launch(channel="chrome", headless=False)
        context = browser.new_context()
        page = context.new_page()
        joined = False
        try:
            page.goto(base + "/live-session", wait_until="domcontentloaded")
            assert input("Complete Marvain Google sign-in/MFA in Chrome. Type SIGNED IN: ").strip() == "SIGNED IN"
            # The production route is explicit; no API login or browser-cookie bypass.
            page.goto(base + "/live-session", wait_until="domcontentloaded")
            expect(page.locator("#space_id")).to_be_visible()
            page.locator("#space_id").select_option(space_id)
            option = page.locator(f'#space_id option[value="{space_id}"]')
            assert option.get_attribute("data-agent-id") == agent_id
            steps.append("authenticated_existing_agent_and_space")
            page.locator("#btn-join").click()
            joined = True
            assert input("Allow the microphone in Chrome. Say Hello Marvain, then type SPOKEN: ").strip() == "SPOKEN"
            expect(page.locator("#btn-leave")).to_be_enabled()
            expect(page.locator("#remote-media audio").first).to_be_attached(timeout=60_000)
            # Track attachment is not proof of an audible answer; the human result controls acceptance.
            assert input("Did you hear Marvain reply? Type HEARD MARVAIN REPLY only if yes: ").strip() == "HEARD MARVAIN REPLY"
            steps.append("human_heard_spoken_reply")
            assert page.locator("#btn-camera").inner_text().strip().endswith("Enable Camera")
            page.locator("#btn-leave").click()
            joined = False
            expect(page.locator("#btn-join")).to_be_enabled()
            steps.append("left_session")
            receipt = {"schema":"marvain.acceptance.receipt.v1","feature":"chrome_voice_reply",
                "result":"accepted","accepted_at":datetime.now(timezone.utc).isoformat(),
                "base_url":base,"agent_id":agent_id,"space_id":space_id,
                "hub_release":preparation["hub_release"],"responder_release":preparation["responder_release"],
                "steps":steps,"human_acceptance":"HEARD MARVAIN REPLY",
                "not_proven":["face","voice_identity","dogs","recording_persistence","recall","two_locations"]}
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(receipt,indent=2)+"\n")
        finally:
            if joined and page.locator("#btn-leave").is_enabled():
                page.locator("#btn-leave").click()
            context.close()
            browser.close()
