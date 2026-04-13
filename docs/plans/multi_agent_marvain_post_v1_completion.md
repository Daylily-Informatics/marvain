# Multi-Agent Plan For Marvain Post-V1 Completion

## Summary

This plan covers the **14 grouped incomplete deliverables** behind the current `46%` broad-spec accounting, plus the **outbound provider durability fix**. It does **not** cover the separately deferred items that are still out of scope: Ramp, OAuth UI, generic provider `http_request`, extra queues beyond `IntegrationQueue`, or broad refactors outside the touched path.

Two decisions are locked:

- `cli-core-yo` remains the CLI surface; direct Typer usage is acceptable **inside** that `cli-core-yo` structure. No change to `cli-core-yo` itself is needed.
- Outbound provider durability uses **prewrite then finalize**:
  - create a durable outbound `integration_messages` row **before** any provider send
  - then update that same row to `sent` or `error` after the provider call
  - no outbox queue in this plan

The 14 grouped deliverables in this plan are:

1. `integration_accounts` schema/store  
2. `integration_accounts` CRUD API  
3. `integration_sync_state` schema/store  
4. Gmail poll ingress  
5. Linear webhook ingress  
6. Slack/GitHub/Twilio migration from stack-level secret ownership to `integration_account_id` ownership  
7. Durable outbound provider lifecycle (`pending -> sent|error`)  
8. Planner recent-thread integration context  
9. Action scope union + connector permission scopes  
10. Normalized message read APIs  
11. `set_message_status`  
12. Gmail outbound tools  
13. GitHub + Linear outbound tools  
14. Retention, audit typing, and regulated-scope cleanup

## Agent Ownership

### Agent 1 — Runtime/Data Foundation
**Owns:** `sql/`, `layers/shared/python/agent_hub/integrations/`, `template.yaml`

Implements:

- `integration_accounts` migration, model, and store helpers
- `integration_sync_state` migration, model, and store helpers
- final `integration_messages` broad-spec shape:
  - add `integration_account_id`
  - add `action_id`
  - add `contains_phi`
  - add `retention_until`
  - add `processed_at`
  - add `redacted_at`
- outbound message store helpers:
  - `begin_outbound_integration_message(...)`
  - `finalize_outbound_integration_message_success(...)`
  - `finalize_outbound_integration_message_error(...)`
- IAM/runtime support for integration-account secret lookup
- SAM resources for `GmailPollFunction` and `RetentionSweeperFunction`

Locked implementation choices:

- provider credentials move to `integration_accounts.credentials_secret_arn`
- all integration credentials secrets must live under a stack-owned prefix, and runtime IAM is granted only for that prefix
- no runtime fallback to `SLACK_SECRET_ARN`, `TWILIO_SECRET_ARN`, or `GITHUB_SECRET_ARN`

### Agent 2 — Hub API Owner
**Owns:** `functions/hub_api/api_app.py`

Implements:

- `integration_accounts` CRUD endpoints
- normalized message list/detail endpoints
- all final account-keyed webhook routes
- runtime account loading / account-status enforcement

Locked implementation choices:

- webhook routes become:
  - `POST /v1/integrations/slack/webhook/{integration_account_id}`
  - `POST /v1/integrations/github/webhook/{integration_account_id}`
  - `POST /v1/integrations/linear/webhook/{integration_account_id}`
  - `POST /v1/integrations/twilio/webhook/{integration_account_id}`
- `paused` and `revoked` accounts reject outbound tools and ignore ingress
- message read APIs are:
  - `GET /v1/agents/{agent_id}/messages`
  - `GET /v1/agents/{agent_id}/messages/{integration_message_id}`
- list API filters: `provider`, `status`, `external_thread_id`, `limit`
- list ordering: newest first by `created_at DESC`
- list default `limit = 50`, max `200`

### Agent 3 — Gmail Owner
**Owns:** `functions/gmail_poll/`, `layers/shared/python/agent_hub/integrations/gmail.py`

Implements:

- Gmail provider secret handling via integration account secret
- scheduled Gmail poller
- Gmail normalization into `integration_messages`
- synthetic `integration.event.received`
- cursor handling through `integration_sync_state`

Locked implementation choices:

- Gmail is poll-only in this plan
- poll loop only loads `active` Gmail accounts
- cursor update happens only after:
  1. message rows committed
  2. synthetic events committed
  3. `IntegrationQueue` enqueue succeeds

### Agent 4 — Provider Ingress Owner
**Owns:** provider modules except Gmail: `layers/shared/python/agent_hub/integrations/{slack,github,twilio,linear}.py`

Implements:

- Linear webhook verification + normalization
- account-aware Slack/GitHub/Twilio provider secret resolution
- route helper interfaces consumed by Agent 2

Locked implementation choices:

- Linear route is account-keyed and webhook-secret verified
- Slack/GitHub/Twilio provider modules no longer depend on stack-level provider env secret ARNs
- dedupe continues to be provider-derived and stable per account-owned ingress event

### Agent 5 — Planner/Action Owner
**Owns:** `functions/planner/handler.py`, `layers/shared/python/agent_hub/action_service.py`, `layers/shared/python/agent_hub/permission_service.py`, `layers/shared/python/agent_hub/contracts/tools.py`

Implements:

- recent-thread integration context in planner
- action scope union behavior
- connector payload models and permission scopes

Locked implementation choices:

- planner integration thread context loads up to **10** prior normalized messages
- thread context filter is:
  - same `agent_id`
  - same `provider`
  - same `external_thread_id`
  - exclude current message
  - newest first
- if `external_thread_id` is missing, planner gets no prior thread context
- persisted action scopes are:
  - `normalize_scopes(requested_scopes ∪ registry.required_scopes)`
- add connector scopes:
  - `message:triage`
  - `gmail:message:write`
  - `github:issue:write`
  - `linear:comment:write`

### Agent 6 — Messaging Tool Owner
**Owns:** `layers/shared/python/agent_hub/tools/` for `set_message_status`, Slack/Twilio tools, Gmail tools

Implements:

- durable outbound lifecycle for Slack and Twilio
- `set_message_status`
- `gmail_create_draft`
- `gmail_send_message`

Locked implementation choices:

- outbound tools always:
  1. load existing row by `agent_id + dedupe_key=action:{action_id}`
  2. if none, insert `direction='outbound'`, `status='pending'`, request payload persisted
  3. call provider
  4. finalize same row to `sent` or `error`
- duplicate handling:
  - existing `sent`: return stored success, do not resend
  - existing `error`: return stored failure, do not resend
  - existing `pending`: return failure, do not resend
- `set_message_status` allowed statuses:
  - `triaged`
  - `drafted`
  - `ignored`
  - `error`
- `set_message_status` sets `processed_at` the first time one of those statuses is applied
- status reason is stored in message payload metadata, not a new top-level column
- `gmail_create_draft` writes outbound row with final status `drafted`
- `gmail_send_message` finalizes outbound row to `sent`

### Agent 7 — Provider Action Owner
**Owns:** `layers/shared/python/agent_hub/tools/` for GitHub and Linear outbound tools

Implements:

- `github_issue_comment`
- `linear_comment_create`

Locked implementation choices:

- both tools are account-keyed
- both use the same durable outbound prewrite/finalize lifecycle as Agent 6
- both persist provider object IDs into `integration_messages.external_message_id`
- both write `action_id` onto the outbound row

### Agent 8 — Compliance/Verification Owner
**Owns:** `functions/retention_sweeper/`, `layers/shared/python/agent_hub/audit.py`, regression verification

Implements:

- retention sweeper
- integration-specific audit entry types
- regulated-scope cleanup
- final cross-subsystem regression pass

Locked implementation choices:

- `RetentionSweeperFunction` runs daily
- sweeper redacts:
  - `body_text`
  - `body_html`
  - large provider payload content
- sweeper preserves:
  - identifiers
  - timestamps
  - status
  - provider routing metadata
  - audit references
- integration audit entry types added:
  - `integration_account_created`
  - `integration_message_received`
  - `integration_message_deduped`
  - `integration_message_triaged`
  - `integration_message_drafted`
  - `integration_message_sent`
  - `integration_message_redacted`
- regulated default tool-runner scope profile removes:
  - `http:request`
  - `shell:execute`

## Phase Order And Dependencies

### Phase 1 — Foundation Gate
**Agents:** 1 and 5 only

Deliver:

- all schema expansion
- account/sync-state stores
- durable outbound store helpers
- connector payload models
- connector permission scopes
- action scope union behavior
- scheduled-function/template scaffolding

This gate must land first because all remaining work depends on the final data model and payload/scope contracts.

### Phase 2 — Parallel Feature Build
**Agents:** 2, 3, 4, 6, 7, 8 in parallel after Phase 1

Deliver in parallel:

- Agent 2: account CRUD + message read APIs
- Agent 3: Gmail poll ingress
- Agent 4: Linear ingress + account-aware Slack/GitHub/Twilio provider modules
- Agent 6: outbound durability for Slack/Twilio, `set_message_status`, Gmail tools
- Agent 7: GitHub/Linear outbound tools
- Agent 8: retention sweeper + audit typing + regulated-scope cleanup

Constraint:

- only Agent 2 edits `api_app.py`
- provider agents expose helper functions/interfaces; Agent 2 integrates them into routes

### Phase 3 — Integration Gate
**Agents:** 2, 5, 8

Deliver:

- final account-keyed webhook route integration in `api_app.py`
- planner thread-context wiring
- full regression pass and failure triage
- update `docs/still_to_add.md` completion accounting after implementation, if desired, as a final documentation sweep

## Public Interfaces And Behavioral Contract

- `integration_accounts` create payload:
  - `provider`
  - `display_name`
  - `credentials_secret_arn`
  - `default_space_id?`
  - `external_account_id?`
  - `scopes?`
  - `config?`
- account patch payload:
  - optional updates to the same mutable fields plus `status`
- account statuses:
  - `active`
  - `paused`
  - `revoked`
- provider secret shapes:
  - Slack: `bot_token`, `signing_secret`
  - Gmail: `client_id`, `client_secret`, `refresh_token`, `user_email`
  - GitHub: `token`, `webhook_secret`
  - Linear: `api_key`, `webhook_secret`
  - Twilio: `account_sid`, `auth_token`, and one of `from_number` or `messaging_service_sid`
- `integration_messages` outbound status contract:
  - `pending`
  - `sent`
  - `error`
  - Gmail draft path may end at `drafted`
- inbound triage status contract:
  - `received`
  - `triaged`
  - `drafted`
  - `ignored`
  - `error`

## Test Plan

- **Schema/store**
  - migrations for `integration_accounts`, `integration_sync_state`, and expanded `integration_messages`
  - insert/update/finalize helpers for outbound lifecycle
- **Accounts/API**
  - CRUD auth, validation, status transitions, secret-prefix enforcement
  - message list/detail filters, ordering, and ownership checks
- **Ingress**
  - Gmail poll dedupe and cursor atomicity
  - Linear webhook signature verification and duplicate delivery
  - Slack/GitHub/Twilio still ingest correctly after account-key conversion
- **Planner/action**
  - integration thread context included only when `external_thread_id` exists
  - persisted action scopes equal requested scopes union tool-required scopes
- **Outbound durability**
  - no send occurs before durable `pending` row exists
  - success updates same row to `sent`
  - provider failure updates same row to `error`
  - duplicate `action:{action_id}` never resends
- **Tools**
  - `set_message_status`
  - Gmail draft/send
  - GitHub issue comment
  - Linear comment create
- **Compliance**
  - retention sweeper redacts only expired rows
  - audit entries emitted for new integration lifecycle events
  - regulated default scope profile excludes generic provider-execution paths
- **Full verification**
  - targeted subsystem suites first
  - then full repo `pytest`

## Assumptions And Defaults

- No compatibility shims, no fallback secret paths, no data-migration behavior.
- Stack-level provider secrets were acceptable for the V1 sprint only; this plan replaces them with account-owned secret references.
- Ramp, OAuth UI, generic provider `http_request`, extra queues beyond `IntegrationQueue`, and broad refactors remain deferred after this plan.
- `cli-core-yo` is unchanged; only repo-local CLI structure matters here.
