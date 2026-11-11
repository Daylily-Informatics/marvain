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
    _run_attended_journey(feature="chrome_voice_reply")


def test_cross_session_recall() -> None:
    _run_attended_journey(feature="cross_session_recall")


def test_spoken_camera_observation() -> None:
    _run_attended_journey(feature="spoken_camera_observation")


def test_quiet_typed_face_recognition() -> None:
    _run_attended_journey(feature="quiet_typed_face_recognition")


def _run_attended_journey(*, feature: str) -> None:
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
            quiet_face = feature == "quiet_typed_face_recognition"
            page.locator("#join-mic").set_checked(not quiet_face)
            page.locator("#btn-join").click()
            joined = True
            if not quiet_face:
                assert input("Allow the microphone in Chrome. Say Hello Marvain, then type SPOKEN: ").strip() == "SPOKEN"
            expect(page.locator("#btn-leave")).to_be_enabled()
            expect(page.locator("#remote-media audio").first).to_be_attached(timeout=60_000)
            if quiet_face:
                expect(page.locator("#btn-mic")).to_contain_text("Mic Off")
                page.locator("#chat-input").fill("Hello Marvain. Please reply aloud; I am keeping my microphone off.")
                page.locator("#btn-send-chat").click()
                steps.append("typed_chat_with_microphone_off")
            # Track attachment is not proof of an audible answer; the human result controls acceptance.
            assert input("Did you hear Marvain reply? Type HEARD MARVAIN REPLY only if yes: ").strip() == "HEARD MARVAIN REPLY"
            steps.append("human_heard_spoken_reply")
            assert page.locator("#btn-camera").inner_text().strip().endswith("Enable Camera")
            human_acceptance = "HEARD MARVAIN REPLY"
            session_ids = []
            if quiet_face:
                session_ids.append(page.locator("#session-info code").first.inner_text())
                expected_person = input("Enter the name on your already approved face reference: ").strip()
                assert expected_person, "An approved reference person is required"
                assert input("Enable Camera in Chrome with your face alone in view. Type CAMERA READY: ").strip() == "CAMERA READY"
                page.locator("#chat-input").fill("Recognize my face from the camera using the approved face reference.")
                page.locator("#btn-send-chat").click()
                expect(page.locator("#lifecycle-log")).to_contain_text(
                    f"Fresh face comparison: {expected_person}", timeout=60_000
                )
                human_acceptance = input("Only if you heard the reference-match reply with your microphone still off, type HEARD FACE MATCH: ").strip()
                assert human_acceptance == "HEARD FACE MATCH"
                expect(page.locator("#btn-mic")).to_contain_text("Mic Off")
                steps.append("fresh_face_reference_match_with_audible_reply_and_microphone_off")
            if feature == "spoken_camera_observation":
                session_ids.append(page.locator("#session-info code").first.inner_text())
                assert input("Enable Camera in Chrome, ask aloud what is visible, change the view and ask again. Type BOTH VIEWS CORRECT only if both answers match: ").strip() == "BOTH VIEWS CORRECT"
                steps.append("human_confirmed_two_fresh_spoken_camera_descriptions")
                assert input("Disable Camera and ask what is visible now. Type CAMERA OFF ACKNOWLEDGED only if Marvain reports no current camera access: ").strip() == "CAMERA OFF ACKNOWLEDGED"
                steps.append("human_confirmed_camera_off_not_old_view")
                human_acceptance = "BOTH VIEWS CORRECT; CAMERA OFF ACKNOWLEDGED"
            if feature == "cross_session_recall":
                session_ids.append(page.locator("#session-info code").first.inner_text())
                assert input("Tell Marvain a new distinctive fact or marker. After its reply, type FACT SPOKEN: ").strip() == "FACT SPOKEN"
                steps.append("human_spoke_distinctive_fact")
            page.locator("#btn-leave").click()
            joined = False
            expect(page.locator("#btn-join")).to_be_enabled()
            steps.append("left_session")
            if feature == "cross_session_recall":
                page.locator("#btn-join").click()
                joined = True
                assert input("Wait for the new greeting, then ask for the fact without saying the answer. Type ASKED: ").strip() == "ASKED"
                session_ids.append(page.locator("#session-info code").first.inner_text())
                assert session_ids[1] != session_ids[0], "Recall must occur in a distinct session"
                human_acceptance = input("Only if Marvain correctly recalled it, type RECALLED ACROSS SESSIONS: ").strip()
                assert human_acceptance == "RECALLED ACROSS SESSIONS"
                steps.append("human_confirmed_recall_in_distinct_session")
                page.locator("#btn-leave").click()
                joined = False
                expect(page.locator("#btn-join")).to_be_enabled()
            receipt = {"schema":"marvain.acceptance.receipt.v1","feature":feature,
                "result":"accepted","accepted_at":datetime.now(timezone.utc).isoformat(),
                "base_url":base,"agent_id":agent_id,"space_id":space_id,
                "hub_release":preparation["hub_release"],"responder_release":preparation["responder_release"],
                "steps":steps,"human_acceptance":human_acceptance,"session_ids":session_ids,
                "not_proven":["voice_identity","dogs","recording_persistence","two_locations",
                              "liveness","sensitive_action_authorization","face_mismatch_handling"]
                             + (["face"] if not quiet_face else [])
                             + (["recall"] if feature != "cross_session_recall" else [])
                             + (["camera"] if feature not in {"spoken_camera_observation", "quiet_typed_face_recognition"} else [])}
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(receipt,indent=2)+"\n")
        finally:
            if joined and page.locator("#btn-leave").is_enabled():
                page.locator("#btn-leave").click()
            context.close()
            browser.close()
