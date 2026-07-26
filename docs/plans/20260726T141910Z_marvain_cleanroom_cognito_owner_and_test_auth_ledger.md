# Marvain Clean-Room Cognito Owner and Test-Authentication Ledger

Timestamp: `2026-07-26T14:19:10Z`

## Control Ledger

Controlling prior ledger: `docs/plans/20260726T105158Z_marvain_cleanroom_authenticated_finalization_pause_ledger.md`

Ledger path: `docs/plans/20260726T141910Z_marvain_cleanroom_cognito_owner_and_test_auth_ledger.md`

## Gate 0: Inventory Freeze

- Target: clean-room stack `marvain-cleanroom-20260712T111914Z`, profile `lsmc`, region `us-west-1`.
- Branch: `codex/marvain-operational-100-closure`; preserve the user-owned dirty paths `AGENTS.md`, `.playwright-cli/`, and `Marvain_Restart_Thread.md`.
- Prior handoff: the authenticated-finalization ledger remains unchanged. Its Cognito-token prerequisite is still open; no SAM, Secrets Manager, Hub token-rotation, or ECS action has run in this phase.
- Read-only owner-account evidence: `marvain --config <selected-clean-room-config> --env cleanroom cognito get-user <user-supplied-owner-email>` returned `not found`.
- Read-only/interactive reset evidence: Cognito Hosted UI rejected the prior reset request with `Could not reset password for the account`; therefore no reset email/code exists for the absent account.
- Current local GUI: the selected-config GUI is running at `http://localhost:8084`, with the configured Cognito callback URL. The listener is an existing local process, not a deployment change.
- Explicit approval: the user authorized creation of the supplied clean-room owner account and one isolated synthetic test account for a live login test. The supplied owner email is intentionally not persisted in this repository ledger.
- Plan amendment approval: the user authorized a secure password-stdin implementation and an owner-membership claim. The implementation must not print, persist, or accept a password or Cognito access token through command-line arguments; it may obtain a transient access token only in process from the selected pool and app client.
- Safety boundary: do not use the CLI's hard-coded `TempPw123!` path. The synthetic test credential must be generated at runtime, kept out of output/config/ledger, and its Cognito account must be cleaned up by the existing E2E fixture. The owner password must be selected and entered by the owner, never sent through chat or command-line arguments.
- Acceptance: (1) a user account exists for the supplied owner email, (2) a generated synthetic account completes the configured Hosted UI callback, (3) the test account is removed, and (4) the owner-login/token step is accurately reported without claiming an unavailable access token.

| ID | Area/Repo | Requirement/Surface | Status | Category | Approval Gate | Owner | Evidence | Root Cause | Terminal Note |
|---|---|---|---|---|---|---|---|---|---|
| AUTH-001 | Cognito owner account | Verify the supplied owner account does not already exist. | SUCCESS | legitimate_safety_handling | Gate 0 | Codex | `marvain cognito get-user` returned `not found`; Hosted UI reset request was rejected for the absent account. |  | Account creation is required before a reset or normal owner login can succeed. |
| AUTH-002 | Cognito owner account | Create the supplied owner email in the selected clean-room pool with email marked verified and no invitation/password disclosure. | SUCCESS | feature_implementation | Gate 3: Active Product Routes And Auth | Codex | Approved live `marvain cognito create-user` completed against pool `us-west-1_BecII637d`; receipt showed `Enabled=true`, `email_verified=true`, and `FORCE_CHANGE_PASSWORD`. No password, token, verification code, or account identifier is retained here. |  | Owner account exists; the owner must complete password establishment before normal interactive login. |
| AUTH-003 | Cognito owner account | Request a fresh reset after creation and leave owner password selection to the owner. | FAIL | active_product_contract | Gate 3: Active Product Routes And Auth | Codex | After AUTH-002, the previously approved Hosted UI reset request was retried and returned the same `Could not reset password for the account` error. The only concrete repair attempted was creation of the formerly absent account, followed by a fresh reset request. | Cognito returned only a generic failure; live evidence shows that an account created with a suppressed invitation and no owner-selected password remains `FORCE_CHANGE_PASSWORD` and cannot use this Hosted UI reset path. | A secure owner-password provisioning mechanism is required before owner login; do not use the static temporary-password path or pass an owner password through chat/argv. |
| AUTH-004 | Hosted UI E2E | Run the existing generated-user Hosted UI E2E against the selected local GUI and clean-room Cognito pool. | SUCCESS | contract_test | Gate 3: Active Product Routes And Auth | Codex | With the selected profile/region, local GUI base URL, pool ID, and `example.test` test domain, `python -m pytest tests/e2e/test_hosted_ui_login_playwright.py -q --tb=short` -> `1 passed in 4.90s`. |  | A generated runtime-only account completed the Cognito Hosted UI login and returned to the local GUI callback. |
| AUTH-005 | Test-account lifecycle | Verify the generated test Cognito user is deleted and record only non-secret evidence. | SUCCESS | legitimate_safety_handling | Gate 5: Final Acceptance | Codex | Approved fixture teardown completed; read-only Marvain CLI JSON listing found `0` users matching the synthetic `marvain-e2e-*@example.test` pattern. |  | The synthetic Cognito account was deleted. The GUI callback may retain its normal Marvain user projection; no unsupported/direct deletion was attempted. |
| AUTH-006 | Deployment handoff | State whether an owner `MARVAIN_ACCESS_TOKEN` is available for the already-approved deployment/finalization sequence. | BLOCKED | active_product_contract | Gate 5: Final Acceptance | Codex | Owner Cognito account exists and the secure in-process authentication path is validated, but no owner-selected permanent password or login-derived token is available. | Owner-only password entry is still required. | The implementation does not export, print, or persist `MARVAIN_ACCESS_TOKEN`; deployment finalization remains paused. |
| AUTH-007 | Secure CLI auth | Implement an explicit `--password-stdin` Cognito-password path for account password establishment, owner claim, and deployment finalization without outputting or persisting the password or transient access token. | SUCCESS | feature_implementation | Gate 3: Active Product Routes And Auth | Codex | `cognito set-password`, `members claim-owner`, and `agent finalize-deployment` now expose the explicit secure mode; deterministic tests cover stdin, hidden TTY prompting, exclusivity, owner claim, and finalization routing. The public claim/finalization commands no longer expose `--access-token`; the static temporary-password branch was removed. | The initial implementation used an unsupported admin auth flow; source-declared client policy required the normal user-password flow. | The secure path holds the Cognito access token only in process and uses `USER_PASSWORD_AUTH` against the selected client. |
| AUTH-008 | Secure CLI auth | Validate the new credential path locally and with one isolated generated Cognito user, then remove that user. | SUCCESS | contract_test | Gate 3: Active Product Routes And Auth | Codex | Final deterministic suite -> `1173 passed, 38 skipped`; live selected-pool `tests/e2e/test_cognito_password_stdin.py` -> `1 passed in 1.68s`; read-only Marvain CLI cleanup check -> `synthetic_cognito_users_remaining=0`. | The first live probe rejected `ADMIN_USER_PASSWORD_AUTH` as disabled; source inspection identified `ALLOW_USER_PASSWORD_AUTH`, then the implementation and test were corrected before acceptance. | No generated password, access token, or synthetic email was retained. |
| AUTH-009 | Owner membership | Establish the owner-selected permanent password through the secure interactive path, then claim first-owner membership for the configured agent. | IN_PROGRESS | active_product_contract | Gate 3: Active Product Routes And Auth | Codex | The owner entered credentials locally in the approved interactive session, but no claim receipt was retained. The two earlier follow-up checks used a child process with captured stdio, which prevented the required TTY password prompt; those checks are invalid diagnostic attempts, not proof of failure or success. | The owner must enter a chosen permanent password locally; Codex must not receive it through chat or command arguments. | Do not replace an existing owner or run deployment finalization in this row. |
| AUTH-010 | Owner membership verification | Provide a direct TTY-only owner count verifier that returns no membership details and hard-fails on malformed response data. | SUCCESS | feature_implementation | Gate 3: Active Product Routes And Auth | Codex | `members list --owner-count-only` returns only `active_owner_memberships`; focused tests -> `17 passed`; full suite -> `1177 passed, 38 skipped`. | Capturing a child process suppresses `getpass`; the verifier must `exec` the Marvain CLI directly in the owner terminal. | The live count remains pending a direct owner-terminal run; no password, token, email, agent ID, or membership details are retained. |

## Scope Limits

- This ledger does not authorize a SAM deployment, worker token rotation, Secrets Manager write, ECS restart, or physical-device claim.
- This ledger does not retain any password, Cognito access token, verification code, or real owner email address.
- The failed predecessor stack remains out of scope and untouched.

## Execution Resumed

- AUTH-007 and AUTH-008 completed under the user-approved secure-password and owner-claim amendment; AUTH-009 is awaiting the owner-only interactive password entry.
- AUTH-006 remains accurately blocked until AUTH-009 completes; no `MARVAIN_ACCESS_TOKEN` will be exported, printed, or written to local configuration.
- AUTH-010 adds a redacted direct-TTY verification path after the two captured-stdio diagnostics proved unable to prompt securely. It is source-validated but does not itself assert the live owner result.
- The prior image receipt remains `sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9`; this source-only authentication change does not republish an image or alter the selected deployment configuration.

## Current Terminal Report

All rows terminal: `no`

Objective complete: `no`

Status counts:

- SUCCESS: `7`
- DUPLICATE: `0`
- NO_LONGER_NEEDED: `0`
- FAIL: `1`
- BLOCKED: `1`
- IN_PROGRESS: `1`
- OPEN: `0`

Validation and live evidence:

- `marvain --dry-run cognito create-user <owner-email>` -> selected pool, verified-email attribute, suppressed invitation, and no temporary password parameter.
- Approved `marvain cognito create-user <owner-email>` -> Cognito owner account created with `Enabled=true`, verified email, and `FORCE_CHANGE_PASSWORD`; only redacted receipt fields were retained in terminal output.
- Approved Hosted UI reset request after creation -> Cognito returned `Could not reset password for the account`; no verification code was handled.
- User-approved generated-user Hosted UI E2E -> `tests/e2e/test_hosted_ui_login_playwright.py` passed against `http://localhost:8084` and the selected clean-room pool.
- Read-only `marvain cognito list-users` JSON check -> no synthetic `marvain-e2e-*@example.test` Cognito users remain.
- Secure credential final validation -> original generated-user password-stdin auth -> `1 passed`; read-only Marvain CLI cleanup check -> `synthetic_cognito_users_remaining=0`. The follow-on redacted owner-count implementation passed `17` focused tests and `1177 passed, 38 skipped` repository-wide tests.
- Repository checks -> Ruff, formatting, docs contracts, implementation-status, regenerated capability matrix, and canonical design-status check passed. The canonical design status remains 89%; the required `--min-score 90` rejection and independent operational 85% rejection were both recorded as expected.

Residual risks:

- The owner password/claim and owner membership count are not independently verified until the direct interactive TTY-only command returns a count.
- The approved image deployment, device-token rotation, ECS restart, and vertical-slice proof remain untouched.
