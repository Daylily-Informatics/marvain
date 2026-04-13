# Still To Add

This document is derived from the current checked-out branch. It is a publication
target for remaining gaps and refreshed completion accounting, not a source of
truth on its own.

Source documents used for the accounting below:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/IMPLEMENTATION_STATUS.generated.md`
- `ADVANCED_FEATURE_PLAN.md`
- `docs/plans/marvain_deep_analysis_upgrade_spec.md`
- `docs/plans/marvain_sprint_to_functional_plan.md`
- `docs/plans/multi_agent_marvain_post_v1_completion.md`

Percentages use equal-weight grouped deliverables. Only `complete / total` counts
toward the percentage. `partial` items are called out in notes and do not receive
credit. There is intentionally no single blended repo-wide percentage.

## Gmail

Status: partial.

Already in branch:

- account-backed Gmail credentials in `integration_accounts.credentials_secret_arn`
- `functions/gmail_poll/handler.py`
- `integration_sync_state` cursor management
- normalized inbound Gmail storage in `integration_messages`
- synthetic `integration.event.received` planner ingress

Still missing:

- `gmail_create_draft`
- `gmail_send_message`
- outbound Gmail execution and regression coverage

## Linear

Status: partial.

Already in branch:

- `linear_comment_create` outbound tool
- Linear action contract payload and required scope wiring
- outbound `integration_messages` persistence for Linear comment sends

Still missing:

- `layers/shared/python/agent_hub/integrations/linear.py`
- account-keyed Linear webhook ingress
- inbound normalization and `integration.event.received` wiring for Linear

## Ramp

Status: not started.

Still missing:

- provider model and credentials contract
- normalized inbound storage model
- planner/action mapping
- any outbound action surface, if still desired

## retention sweeper

Status: partial.

Already in branch:

- `contains_phi`, `retention_until`, and `redacted_at` on `integration_messages`
- `functions/retention_sweeper/handler.py`
- `integration_message_redacted` audit emission

Still missing:

- the broader integration audit event set from the deep-analysis spec:
  `integration_message_received`, `integration_message_deduped`,
  `integration_message_triaged`, `integration_message_drafted`,
  `integration_message_sent`

## OAuth UI

Status: partial.

Already in branch:

- `integration_accounts` schema and store
- Hub API CRUD for integration accounts
- account-owned secret references instead of stack-level provider secrets

Still missing:

- user-facing connect/disconnect UI
- provider-specific OAuth initiation and callback flows
- token rotation/revoke UX for human operators

## generic http_request provider actions

Status: intentionally not implemented.

Still missing:

- a scoped approval and policy model that explicitly allows generic provider egress
- provider allowlists and abuse controls strong enough for planner exposure

## extra queues beyond IntegrationQueue

Status: not started.

Still missing:

- a concrete need that justifies another queue
- ownership boundaries for each added consumer
- retry and dedupe coverage for any new queue path

## broad refactors outside the touched path

Status: intentionally deferred.

Still missing:

- a new scoped plan that justifies repo-wide cleanup
- explicit value beyond speculative polish

## Completion Accounting

Method:

- Score each source family separately.
- Use grouped deliverables rather than per-bullet counting.
- Count only `complete / total`.
- Call out `partial` items in notes without giving completion credit.

### Repo base requirements

Sources: `README.md`, `docs/ARCHITECTURE.md`,
`docs/IMPLEMENTATION_STATUS.generated.md`

This family measures the baseline starter/runtime promises made by the repo
docs, not the later expansion specs.

| Group | Status | Notes |
| --- | --- | --- |
| AWS SAM runtime spine | complete | Hub API, planner, tool runner, ws handlers, async workers, and supporting stack resources exist on this branch. |
| Plane separation | complete | Media, control, cognition, state, execution, and observability planes all have concrete code surfaces. |
| Durable truth and audit backbone | complete | Aurora, SQS, DynamoDB ws registry, artifacts, and audit storage are all wired in the repo. |
| Realtime and control surfaces | complete | REST routes, WebSocket handlers, LiveKit token minting, and satellite/device flows are present. |
| Planner and tool execution contracts | complete | Planner, tool runner, contracts, scopes, and action execution paths are implemented. |
| Route coverage and generated checks | complete | Route smoke tests are enforced and the generated implementation status file is all PASS. |
| Local runtime workflow | complete | Conda activation, CLI workflow, local GUI, and local agent worker paths are documented and present. |
| Deployment and recovery guidance | complete | Build, deploy, bootstrap, and reset guidance are present in the repo docs. |

Repo base requirements complete: `8 / 8`

Percent complete: `100%`

### Architectural aspirations

Sources: `ADVANCED_FEATURE_PLAN.md`,
`docs/plans/marvain_deep_analysis_upgrade_spec.md`

#### `ADVANCED_FEATURE_PLAN.md`

| Group | Status | Notes |
| --- | --- | --- |
| Spec 0: identity and permission spine | complete | Repo uses `agent_memberships`; legacy `memberships` was quarantined and users-column cleanup landed. |
| Spec 1: devices fully functional | complete | Device create/revoke/rotate, heartbeat, scope-aware auth, and ws command flows are present. |
| Spec 2: remotes as devices | complete | The plan itself marks this complete and the repo uses the device-only model. |
| Spec 3: actions fully functional | complete | Approval enqueue, lifecycle persistence, runner result/error writes, and device command execution are present. |
| Spec 4: core agent plus full memories | complete | `/v1/recall`, `/v1/spaces/{space_id}/events`, memory detail APIs, and worker context hydration are present. |
| Spec 5: realtime event stream | complete | Broadcast wiring and live GUI/device updates are implemented. |

Advanced feature plan complete: `6 / 6`

Percent complete: `100%`

#### `docs/plans/marvain_deep_analysis_upgrade_spec.md`

| Group | Complete | Total | Notes |
| --- | ---: | ---: | --- |
| Core runtime | 6 | 6 | `IntegrationQueue`, integration schemas, stores, account CRUD, planner event branch, and action-scope expansion are in place. |
| Provider ingress | 4 | 5 | Slack, GitHub, Twilio, and Gmail poll ingress are complete; Linear ingress is still missing. |
| Planner and action shaping | 4 | 4 | `integration.event.received`, recent-thread context, connector payload shaping, and action scope union are in place. |
| Provider tools and message writes | 5 | 7 | `set_message_status`, Slack, Twilio, GitHub, and Linear outbound paths are complete; Gmail draft/send remain missing. |
| Compliance and admin surfaces | 3 | 4 | retention and redaction landed; broader integration audit typing remains partial and does not count. |

Deep-analysis upgrade spec complete: `22 / 26`

Percent complete: `85%`

Architectural aspirations family complete: `28 / 32`

Percent complete: `88%`

Still materially missing in this family:

- Linear inbound webhook ingestion
- Gmail outbound draft/send tools
- expanded integration audit entry typing

### Current plan goals

Sources: `docs/plans/marvain_sprint_to_functional_plan.md`,
`docs/plans/multi_agent_marvain_post_v1_completion.md`

#### `docs/plans/marvain_sprint_to_functional_plan.md`

Sprint plan complete: `8 / 8`

Percent complete: `100%`

#### `docs/plans/multi_agent_marvain_post_v1_completion.md`

| Deliverable | Status | Notes |
| --- | --- | --- |
| 1. `integration_accounts` schema/store | complete | Landed. |
| 2. `integration_accounts` CRUD API | complete | Landed. |
| 3. `integration_sync_state` schema/store | complete | Landed. |
| 4. Gmail poll ingress | complete | Landed. |
| 5. Linear webhook ingress | not started | Still missing. |
| 6. Slack/GitHub/Twilio account migration | complete | Landed. |
| 7. Durable outbound lifecycle | complete | Outbound rows are inserted before provider side effects for the implemented outbound tools. |
| 8. Planner recent-thread integration context | complete | Landed. |
| 9. Action scope union and connector permission scopes | complete | Landed. |
| 10. Normalized message read APIs | complete | Landed. |
| 11. `set_message_status` | complete | Landed. |
| 12. Gmail outbound tools | not started | Still missing. |
| 13. GitHub and Linear outbound tools | complete | Landed. |
| 14. Retention, audit typing, regulated-scope cleanup | partial | Retention and scope cleanup landed; expanded audit typing is still open. |

Post-V1 plan complete: `11 / 14`

Percent complete: `79%`

Current plan goals family complete: `19 / 22`

Percent complete: `86%`
