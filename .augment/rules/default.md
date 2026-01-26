# Marvain — repo-local Augment rules (default)

These rules are **repo-specific** and layer on top of the global rules in `~/.augment/rules/00_base_rules.md`.

## Environment
- Primary environment manager is **Conda**.
  - Env name: `marvain`
  - Spec file: `config/marvain_conda.yaml`
  - Python: **3.11**
- Prefer activating with:
  - `. ./marvain_activate`
- Treat `MARVAIN_ALLOW_VENV=1` as an escape hatch only (use only if explicitly requested).

## Safety (AWS / destructive operations)
- Do **not** run destructive or stateful AWS operations without explicit Major approval.
  - Examples: `sam deploy`, CloudFormation updates/deletes, S3 deletes, DB init against real stacks.
- Prefer `--dry-run` modes whenever available (e.g., `./bin/marvain ... --dry-run`).

## Testing & verification (default)
- Fast local signal:
  - `python -m pytest -q`
- When changing CLI behavior, prefer adding/updating tests under `tests/`.

## Codebase conventions
- Runtime/targets:
  - AWS SAM/CloudFormation stack in `template.yaml`
  - Lambda code in `functions/`
  - Shared library in `layers/shared/`
  - CLI in `marvain_cli/` and wrapper in `bin/marvain`
- Prefer **stdlib / existing deps**; adding dependencies requires justification.

## Architecture: GUI vs API
- **Hub API (deployed)**: REST API Lambda behind API Gateway for programmatic access (devices, CLI, satellites). Uses `api_app.py` via `lambda_handler.py`.
- **GUI (local only)**: FastAPI app with Jinja2 templates + HTMX, runs on `localhost:8084`. Uses `app.py` which imports `api_app` and adds GUI routes.
- GUI authenticates via Cognito Hosted UI and connects directly to deployed AWS resources (Aurora Data API, Cognito, S3, SQS).
- **Never deploy GUI to Lambda** — keep GUI code out of `api_app.py`.

## Logging & determinism
- Prefer explicit configuration (flags/config) over implicit shell state.
- When wrapping external tools (AWS/SAM), log the exact command being run (unless quiet mode).

## Documentation updates
- If behavior changes, update the nearest doc:
  - `README.md`, `QUICKSTART.md`, and/or `docs/ARCHITECTURE.md`.