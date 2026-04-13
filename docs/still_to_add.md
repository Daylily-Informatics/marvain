# Still To Add

This document tracks the work intentionally left outside the completed V1 sprint slice.

The current branch now covers the sprinted V1 path:

- `integration_messages`
- `IntegrationQueue`
- Slack webhook ingestion
- GitHub webhook ingestion
- Twilio SMS ingestion
- planner support for `integration.event.received`
- `slack_post_message`
- `twilio_send_sms`
- outbound `integration_messages` rows for Slack and Twilio actions

Everything below remains deferred.

## Gmail

Status: not started.

Why it is still out:

- no Gmail poller
- no Gmail provider module
- no Gmail webhook substitute or cursoring
- no `gmail_create_draft`
- no `gmail_send_message`

What still needs to be added:

- provider secret contract and stack wiring
- mailbox sync state storage
- poll worker
- normalization into `integration_messages`
- planner-safe outbound tools

## Linear

Status: not started.

Why it is still out:

- no Linear webhook route
- no Linear provider module
- no Linear outbound comment tool

What still needs to be added:

- webhook verification and normalization
- planner mapping for Linear issue/comment events
- `linear_comment_create`
- any provider-specific secret/config wiring

## Ramp

Status: not started.

Why it is still out:

- no Ramp schema
- no Ramp ingress path
- no Ramp provider module
- no Ramp planner/action mapping

What still needs to be added:

- source-of-truth event model for Ramp objects
- provider auth and secret shape
- normalization into `integration_messages`
- any outbound action surface, if still desired

## retention sweeper

Status: not started.

Why it is still out:

- no sweeper Lambda
- no redaction schedule
- current `integration_messages` V1 table does not include the broader PHI/retention fields from the deep spec

What still needs to be added:

- retention/redaction columns if the broader spec stays in force
- scheduled sweeper function
- audit entries for redaction batches

## OAuth UI

Status: not started for integrations.

Why it is still out:

- V1 uses stack-level provider secrets
- there is no user-facing integration connect/disconnect UI
- there is no provider account authorization flow for Slack/GitHub/Gmail/Linear/Twilio

What still needs to be added:

- integration account model and CRUD
- provider-specific OAuth initiation/callback flows
- UI surfaces for connect, rotate, revoke, and status

## generic http_request provider actions

Status: intentionally not implemented.

Why it is still out:

- the sprint explicitly required typed provider tools instead of generic outbound provider actions
- current V1 only uses `slack_post_message` and `twilio_send_sms`

What still needs to be added:

- a clear policy decision that generic provider actions are allowed
- per-provider allowlists and approval rules
- stronger audit and abuse controls than the current V1 needs

## extra queues beyond IntegrationQueue

Status: not started.

Why it is still out:

- the sprint explicitly limited queue expansion
- current ingress work uses `IntegrationQueue` only

What still needs to be added:

- a concrete need that justifies another queue
- ownership boundaries for each new queue consumer
- test coverage for retry and dedupe semantics

## broad refactors outside the touched path

Status: intentionally deferred.

Why it is still out:

- the sprint required minimal edits on the existing patterns
- this branch stays narrow around planner, tool runner, webhook ingress, storage, stack wiring, and CLI cleanup

What still needs to be added:

- only after a new scoped plan exists
- no greenfield project value comes from speculative cleanup for untouched areas

## Completion Accounting

Method:

- For the sprint plan, count completed phases against the 8 named phases in `docs/plans/marvain_sprint_to_functional_plan.md`.
- For the user-declared V1 scope, count completed scope items against the 7 mandatory items listed in the sprint request.
- For the broader `docs/plans/marvain_deep_analysis_upgrade_spec.md`, use grouped implementation deliverables from Phase 4 plus the explicit idempotency requirements. This avoids fake precision from counting every sub-bullet as a separate feature.

### Sprint plan

- `8 / 8` phases complete
- Percent complete: `100%`

### Mandatory V1 scope

- `7 / 7` mandatory scope items complete
- Percent complete: `100%`

The 7 counted items are:

1. Slack webhook ingestion
2. GitHub webhook ingestion
3. Twilio SMS ingestion
4. `integration_messages` table
5. planner support for `integration.event.received`
6. `slack_post_message`
7. `twilio_send_sms`

### Broader deep-analysis integration upgrade spec

Grouped deliverable count:

- Core runtime: `4 / 6` complete
- Provider ingress: `3 / 5` complete
- Planner and action shaping: `2 / 4` complete
- Provider tools and message writes: `3 / 7` complete
- Compliance and admin surfaces: `0 / 4` complete

Total grouped deliverables complete: `12 / 26`

Percent complete: `46%`

What is counted as complete in that `12`:

- `IntegrationQueue` wiring
- shared integration queue config
- `integration_messages` schema
- integration storage/model layer
- Slack inbound webhook
- GitHub inbound webhook
- Twilio inbound webhook
- planner branch for `integration.event.received`
- deterministic planner action idempotency for integration events
- `slack_post_message`
- `twilio_send_sms`
- outbound `integration_messages` rows for Slack and Twilio actions

What is still missing from that broader spec:

- integration accounts CRUD
- integration sync state
- Gmail
- Linear
- message read endpoints
- `set_message_status`
- Gmail outbound tools
- GitHub outbound tool
- Linear outbound tool
- compliance retention/redaction work
- expanded integration audit typing
- broader scope/refactor items from the original deep spec

## Notes On The Two Cleanup Items From This Turn

### Typer-backed metadata

`cli-core-yo` still builds on Typer upstream. The remaining local indirection layer was removed instead of adding another shim. The branch now uses Typer imports directly in `marvain_cli/commands.py` and no longer carries a local `cli_primitives.py` wrapper.

### Outbound provider action records

Slack and Twilio outbound tools now write outbound `integration_messages` rows using `dedupe_key = f"action:{action_id}"`.

One limitation still remains by design:

- the provider side effect happens before the local outbound row is written, so a post-send DB failure is still possible
- fixing that would require a broader send-state design than this sprint allowed
