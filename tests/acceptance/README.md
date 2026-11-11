# Progressive Marvain acceptance

This records the real path to an audible reply, recall across distinct sessions, fresh spoken camera descriptions with camera-off behavior, and quiet typed face recognition with an audible reply. The source tests have been **written, not run**. Human acceptance is recorded in the journey manifest; it is not a passing automated test run.

The journey includes deployment, Google/Cognito sign-in, existing agent/space, private owner/agent recording policy, canonical browser activation, AWS responder activation, Join, microphone permission, speech, audible reply, and Leave. Infrastructure setup is a fixture prepared through the owning Marvain CLI. The test consumes its recorded success instead of redeploying or probing it again.

Run only after the separately required test-execution authorization. It uses a new headed Chrome context and the actual microphone. The human completes sign-in/MFA and attests to hearing the response; fake audio and track presence cannot satisfy that acceptance. It incurs normal conversation charges and the selected recording policy applies. No credentials, cookies, audio, or screenshot contents are written into the receipt.

Provide these explicit environment values:

- `MARVAIN_ATTENDED_ACCEPTANCE=1`
- `MARVAIN_ACCEPTANCE_BASE_URL`: selected HTTPS Hub including its stage
- `MARVAIN_ACCEPTANCE_AGENT_ID` and `MARVAIN_ACCEPTANCE_SPACE_ID`: actual persisted UUIDs
- `MARVAIN_ACCEPTANCE_SETUP_RECEIPT`: absolute path to JSON with actual `agent_id`, `space_id`, `hub_release`, `responder_release`, `deployment_receipt`, `browser_activation.status=written`, `responder_activation.status=success`, and `recording_policy=private_owner_and_agent_retain_until_revoked`
- `MARVAIN_ACCEPTANCE_OUTPUT`: absolute output receipt path

Authorized invocation from the activated checkout:

```sh
python -m pytest -s /Users/jmajor/projects/marvain/tests/acceptance/test_marvain_journey.py
```

Extend the manifest and add one attended test per newly accepted capability. Keep unaccepted features pending. For biometrics, include enrollment consent, review, a new matching sample, a different person's mismatch, simultaneous voice/face conflict, revocation, stale/reused challenge rejection, and the exact selected export/action. Do not make physical actions, enrollment, exports, or message sends part of the voice test implicitly.

The quiet face journey keeps the microphone off, consumes an existing approved reference, and asks the human to enable the camera. It accepts the fresh comparison lifecycle result plus human confirmation of the audible reply. It does not claim liveness, mismatch performance, or authorization for sensitive actions. The 4.0.18 Hub / 4.0.17 responder attended result is recorded; the automated entrypoint remains unrun.
