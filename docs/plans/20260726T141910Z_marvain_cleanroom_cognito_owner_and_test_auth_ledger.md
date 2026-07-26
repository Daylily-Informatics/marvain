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
- Safety boundary: do not use the CLI's hard-coded `TempPw123!` path. The synthetic test credential must be generated at runtime, kept out of output/config/ledger, and its Cognito account must be cleaned up by the existing E2E fixture. The owner password must be selected and entered by the owner, never sent through chat or command-line arguments.
- Acceptance: (1) a user account exists for the supplied owner email, (2) a generated synthetic account completes the configured Hosted UI callback, (3) the test account is removed, and (4) the owner-login/token step is accurately reported without claiming an unavailable access token.

| ID | Area/Repo | Requirement/Surface | Status | Category | Approval Gate | Owner | Evidence | Root Cause | Terminal Note |
|---|---|---|---|---|---|---|---|---|---|
| AUTH-001 | Cognito owner account | Verify the supplied owner account does not already exist. | SUCCESS | legitimate_safety_handling | Gate 0 | Codex | `marvain cognito get-user` returned `not found`; Hosted UI reset request was rejected for the absent account. |  | Account creation is required before a reset or normal owner login can succeed. |
| AUTH-002 | Cognito owner account | Create the supplied owner email in the selected clean-room pool with email marked verified and no invitation/password disclosure. | SUCCESS | feature_implementation | Gate 3: Active Product Routes And Auth | Codex | Approved live `marvain cognito create-user` completed against pool `us-west-1_BecII637d`; receipt showed `Enabled=true`, `email_verified=true`, and `FORCE_CHANGE_PASSWORD`. No password, token, verification code, or account identifier is retained here. |  | Owner account exists; the owner must complete password establishment before normal interactive login. |
| AUTH-003 | Cognito owner account | Request a fresh reset after creation and leave owner password selection to the owner. | FAIL | active_product_contract | Gate 3: Active Product Routes And Auth | Codex | After AUTH-002, the previously approved Hosted UI reset request was retried and returned the same `Could not reset password for the account` error. The only concrete repair attempted was creation of the formerly absent account, followed by a fresh reset request. | Cognito returned only a generic failure; live evidence shows that an account created with a suppressed invitation and no owner-selected password remains `FORCE_CHANGE_PASSWORD` and cannot use this Hosted UI reset path. | A secure owner-password provisioning mechanism is required before owner login; do not use the static temporary-password path or pass an owner password through chat/argv. |
| AUTH-004 | Hosted UI E2E | Run the existing generated-user Hosted UI E2E against the selected local GUI and clean-room Cognito pool. | SUCCESS | contract_test | Gate 3: Active Product Routes And Auth | Codex | With the selected profile/region, local GUI base URL, pool ID, and `example.test` test domain, `python -m pytest tests/e2e/test_hosted_ui_login_playwright.py -q --tb=short` -> `1 passed in 4.90s`. |  | A generated runtime-only account completed the Cognito Hosted UI login and returned to the local GUI callback. |
| AUTH-005 | Test-account lifecycle | Verify the generated test Cognito user is deleted and record only non-secret evidence. | SUCCESS | legitimate_safety_handling | Gate 5: Final Acceptance | Codex | Approved fixture teardown completed; read-only Marvain CLI JSON listing found `0` users matching the synthetic `marvain-e2e-*@example.test` pattern. |  | The synthetic Cognito account was deleted. The GUI callback may retain its normal Marvain user projection; no unsupported/direct deletion was attempted. |
| AUTH-006 | Deployment handoff | State whether an owner `MARVAIN_ACCESS_TOKEN` is available for the already-approved deployment/finalization sequence. | BLOCKED | active_product_contract | Gate 5: Final Acceptance | Codex | Owner Cognito account now exists, but no owner-selected permanent password or login-derived access token is available. | AUTH-003 failed under the allowed reset path. | Supply a secure owner-password provisioning/login path before attempting the already-approved deployment/finalization sequence. |

## Scope Limits

- This ledger does not authorize a SAM deployment, worker token rotation, Secrets Manager write, ECS restart, or physical-device claim.
- This ledger does not retain any password, Cognito access token, verification code, or real owner email address.
- The failed predecessor stack remains out of scope and untouched.

## Current Terminal Report

All rows terminal: `yes`

Objective complete: `no`

Status counts:

- SUCCESS: `4`
- DUPLICATE: `0`
- NO_LONGER_NEEDED: `0`
- FAIL: `1`
- BLOCKED: `1`

Validation and live evidence:

- `marvain --dry-run cognito create-user <owner-email>` -> selected pool, verified-email attribute, suppressed invitation, and no temporary password parameter.
- Approved `marvain cognito create-user <owner-email>` -> Cognito owner account created with `Enabled=true`, verified email, and `FORCE_CHANGE_PASSWORD`; only redacted receipt fields were retained in terminal output.
- Approved Hosted UI reset request after creation -> Cognito returned `Could not reset password for the account`; no verification code was handled.
- User-approved generated-user Hosted UI E2E -> `tests/e2e/test_hosted_ui_login_playwright.py` passed against `http://localhost:8084` and the selected clean-room pool.
- Read-only `marvain cognito list-users` JSON check -> no synthetic `marvain-e2e-*@example.test` Cognito users remain.

Residual risks:

- The owner account is not login-ready until a secure owner-password path is supplied.
- The approved image deployment, device-token rotation, ECS restart, and vertical-slice proof remain untouched.
