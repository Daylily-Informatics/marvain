# Marvain Integrations V1 Plan

## Summary

Plan Mode is still active, so no repo-tracked implementation has been performed. I revised the plan to include the new global CLI/auth requirement before integration work.

The new Phase 1 is a foundation phase: adopt the `./cli-core-yo` pattern for the Marvain CLI, remove the current argparse/Typer fallback path, and replace Marvain Cognito usage with `daylily-auth-cognito` wherever Cognito is used. This shifts the original `integration_messages` phase to Phase 2. That is the main repo/order mismatch: your first requested order began with schema, but the later CLI/auth requirement is global and is most coherent as the first phase.

All test commands will be run from the repo root after `. ./marvain_activate`, with `AWS_PROFILE=daylily AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1`.

## Public Interfaces And Decisions

- CLI: replace the current `marvain_cli` entry path with the `cli-core-yo` v2 style used by `./bloom`: one immutable `CliSpec`, `create_app(spec)`, `run(spec, args)`, command registry policies, and no argparse fallback.
- Dependencies: add `cli-core-yo==2.0.0` and `daylily-auth-cognito==2.0.1` where Marvain packages/runtime need them; remove direct reliance on the old `daylily-cognito` package where replaced.
- Cognito: all Marvain Cognito login/token/admin flows touched in Phase 1 must use `daylily-auth-cognito`; if the library lacks a needed Cognito capability, the phase stops and reports that as a blocker rather than adding direct boto3 fallback.
- Integrations V1: use stack-level provider secrets, not `integration_accounts`.
  - `SLACK_SECRET_ARN`: `{"signing_secret":"...","bot_token":"..."}`
  - `TWILIO_SECRET_ARN`: `{"account_sid":"...","auth_token":"...","from_number":"+1..."}` or `messaging_service_sid`
  - `GITHUB_SECRET_ARN`: `{"webhook_secret":"..."}`
  - `INTEGRATION_QUEUE_URL`
- Webhook routes:
  - `POST /v1/integrations/slack/webhook/{agent_id}/{space_id}`
  - `POST /v1/integrations/twilio/webhook/{agent_id}/{space_id}`
  - `POST /v1/integrations/github/webhook/{agent_id}/{space_id}`
- Tools:
  - `slack_post_message`: payload `{channel_id, text, thread_ts?}`, scope `slack:message:write`
  - `twilio_send_sms`: payload `{to, body}`, scope `twilio:sms:send`
- Out of scope remains unchanged: Gmail, Linear, Ramp, retention sweeper, OAuth UI, generic `http_request` provider actions, queues beyond `IntegrationQueue`, and broad refactors.

## Phase Plan

1. **CLI/Auth Foundation**
   - Refactor [marvain_cli](/Users/jmajor/projects/daylily/marvain/marvain_cli) to follow the `./cli-core-yo` pattern from `./bloom`, preserving existing Marvain commands and behavior while removing fallback CLI paths.
   - Update CLI tests to use cli-core conformance/smoke patterns instead of Typer/argparse fallback assumptions.
   - Replace Cognito code in [agent_hub/cognito.py](/Users/jmajor/projects/daylily/marvain/layers/shared/python/agent_hub/cognito.py), [agent_hub/auth.py](/Users/jmajor/projects/daylily/marvain/layers/shared/python/agent_hub/auth.py), and CLI ops where touched with `daylily-auth-cognito`.
   - Stop after this phase and report exact files, tests, blockers, and the Phase 2 recommendation.

2. **`integration_messages` Schema And Storage**
   - Add the next SQL migration after `sql/016_action_idempotency.sql` for `integration_messages`, without `integration_account_id`.
   - Add a narrow storage/model helper under `agent_hub.integrations` for inserting provider messages and linking to an optional Marvain event ID.
   - Add unit tests for shape, insert binding, provider/source IDs, payload storage, and idempotency behavior.

3. **IntegrationQueue Wiring**
   - Add `IntegrationQueue` to the existing SAM stack.
   - Add `INTEGRATION_QUEUE_URL` to shared config and Hub API/Planner wiring as needed.
   - Add only minimal enqueue plumbing; no provider-specific behavior yet.

4. **Slack Webhook Ingestion**
   - Add Slack webhook route with signature verification, URL challenge handling, minimal event normalization, `integration_messages` insert, Marvain `integration.event.received` event insert, and enqueue to `IntegrationQueue`.
   - Hard-fail missing secrets/config; no fallback behavior.

5. **Planner Support For `integration.event.received`**
   - Teach planner to consume integration-received events from `IntegrationQueue`.
   - Convert normalized integration payload text into the existing planner path with bounded metadata, preserving current planner schema validation and action creation flow.
   - Keep changes narrow to the event extraction/dedupe path.

6. **`slack_post_message` Tool**
   - Add tool contract/model, registry module, required permission scope, secret loading, and Slack API call.
   - Add focused tool runner tests with HTTP mocked; do not use generic `http_request`.

7. **Twilio Ingress And `twilio_send_sms`**
   - Add Twilio webhook route with signature validation, normalized inbound SMS storage/event/enqueue behavior.
   - Add `twilio_send_sms` contract/tool/scope/secret loading with mocked tests.
   - Keep SMS sending separate from Slack provider code except for shared storage helpers.

8. **GitHub Webhook Ingestion**
   - Add GitHub webhook route with HMAC signature validation, selected event normalization, `integration_messages` insert, Marvain event insert, and enqueue.
   - No GitHub outbound tools in V1.

## Multi-Agent Work Allocation

- Agent 1: CLI/auth foundation implementation and tests.
- Agent 2: `integration_messages` migration/storage and storage tests.
- Agent 3: SAM/config/IntegrationQueue wiring.
- Agent 4: Slack ingress route and tests.
- Agent 5: planner event support and tests.
- Agent 6: Slack tool contract/runner implementation and tests.
- Agent 7: Twilio ingress/tool implementation and tests.
- Agent 8: GitHub ingress implementation and final V1 integration test sweep.

Agents must only work on their assigned phase after explicit approval for that phase. No parallel phase execution unless you explicitly approve parallel work.

## Test Plan

- Phase 1: CLI smoke/conformance tests, CLI config tests, auth/Cognito unit tests, and any affected ops tests.
- Phase 2: migration/static SQL checks and storage unit tests.
- Phase 3: SAM template/config unit tests and route smoke tests for unchanged API behavior.
- Phase 4: Slack webhook tests for valid signature, invalid signature, URL challenge, storage, event creation, queue enqueue.
- Phase 5: planner tests for `integration.event.received` extraction and existing planner regressions.
- Phase 6: Slack tool contract and mocked API call tests.
- Phase 7: Twilio webhook signature/storage/enqueue tests and mocked send-SMS tool tests.
- Phase 8: GitHub signature/storage/enqueue tests and final targeted suite.

## Assumptions

- The current checked-out branch remains the only source of truth.
- The new CLI/auth requirement is global and should happen before integration-specific phases.
- `daylily-auth-cognito` is mandatory for Cognito paths; no direct boto3 fallback should be added.
- Stack-level provider secrets are the approved V1 substitute for `integration_accounts`.
- Phase reporting will include: phase completed, exact files created/modified, migrations added, tests run, test results, blockers/design concerns, and recommended next phase.
