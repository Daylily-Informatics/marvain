# Remaining Integration Gaps

Sampled at: `2026-04-13 05:34 PDT`

This note explains the three material remaining gaps called out in
`docs/still_to_add.md`, using the current checked-out branch as the source of
truth.

## 1. Linear inbound webhook ingestion

Current branch state:

- Outbound Linear exists through `layers/shared/python/agent_hub/tools/linear_comment_create.py`.
- The Hub API exposes webhook ingress for Slack, Twilio, and GitHub only:
  - `POST /v1/integrations/slack/webhook/{integration_account_id}`
  - `POST /v1/integrations/twilio/webhook/{integration_account_id}`
  - `POST /v1/integrations/github/webhook/{integration_account_id}`
- There is no `layers/shared/python/agent_hub/integrations/linear.py`.
- There is no `POST /v1/integrations/linear/webhook/{integration_account_id}`.

Why this is still a gap:

- Marvain can write into Linear, but it cannot ingest Linear-originated issue,
  comment, or status activity.
- No Linear records can be normalized into `integration_messages`.
- The planner cannot react to inbound Linear events through
  `integration.event.received`.

What completion requires:

- Add a Linear provider ingress module.
- Add the account-keyed Linear webhook route in `functions/hub_api/api_app.py`.
- Verify webhook authenticity.
- Normalize inbound payloads into `integration_messages`.
- Create the synthetic `integration.event.received` event and enqueue
  `IntegrationQueue`.
- Add route and provider regression coverage.

## 2. Gmail outbound draft/send tools

Current branch state:

- Gmail inbound exists through `functions/gmail_poll/handler.py` and
  `layers/shared/python/agent_hub/integrations/gmail.py`.
- Tool contracts already define `gmail_create_draft` and `gmail_send_message`
  in `layers/shared/python/agent_hub/contracts/tools.py`.
- There are no corresponding runtime tool modules in
  `layers/shared/python/agent_hub/tools/`.

Why this is still a gap:

- Marvain can ingest Gmail messages and plan against them.
- Marvain cannot execute typed Gmail outbound actions through the tool runner.
- This leaves a contract/runtime mismatch: the action kinds are modeled, but
  they are not implemented.

What completion requires:

- Add `layers/shared/python/agent_hub/tools/gmail_create_draft.py`.
- Add `layers/shared/python/agent_hub/tools/gmail_send_message.py`.
- Reuse the existing account-secret and outbound-message patterns used by Slack,
  Twilio, GitHub, and Linear.
- Persist outbound Gmail rows in `integration_messages`.
- Finalize sent/drafted/error state consistently.
- Add focused tool tests and runner integration tests.

## 3. Expanded integration audit typing

Current branch state:

- Integration audit emission currently covers:
  - `integration_account_created`
  - `integration_message_redacted`
- The broader deep-analysis spec called for a wider message lifecycle audit set.

Why this is still a gap:

- The runtime works, but the audit trail is thin.
- You cannot reconstruct the full integration-message lifecycle from audit logs.
- Receive, dedupe, triage, draft, and send transitions are not consistently
  represented as first-class audit events.

What completion requires:

- Add audit entry emission for:
  - `integration_message_received`
  - `integration_message_deduped`
  - `integration_message_triaged`
  - `integration_message_drafted`
  - `integration_message_sent`
- Wire those events into the existing inbound, status-update, and outbound tool
  paths.
- Add regression tests that prove the events are emitted at the intended
  lifecycle points.

## Priority order

Recommended completion order:

1. Linear inbound webhook ingestion
2. Gmail outbound draft/send tools
3. Expanded integration audit typing

That order matches user-visible value:

- Linear is currently outbound-only.
- Gmail is currently inbound-only.
- Audit typing is important, but it does not block the basic provider loops.
