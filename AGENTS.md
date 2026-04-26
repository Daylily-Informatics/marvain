# AGENTS.md - marvain

## Instruction Precedence

- Follow the Daylily/LSMC global Polaris standards unless this file is more specific.
- Repo-specific instructions in this file override generic workspace guidance for Marvain work.
- Optimize for correctness, clarity, and reproducibility. Prefer one recommended path, state assumptions when they matter, and ask only when blocked.
- Before acting, read relevant instruction files in `~/.agents/*`, `~/.codex/*`, `./.agents`, `./.codex`, `./AGENTS.md`, and `./CLAUDE.md` when present.

## Required Terminal Setup

From the repo root, in every new terminal, run this before any repo command:

```bash
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
source ./activate
```

- Never work around terminal or activation problems by skipping `source ./activate`.
- If activation fails or the expected `marvain` CLI is unavailable afterward, stop and diagnose the activation or packaging problem. Do not patch around it with aliases, raw `python -m ...`, or PATH hacks.
- The declared console script is `marvain = "marvain_cli.__main__:main"` and must be available from the activated Conda env.

## Marvain Command Ownership

- Use the Marvain CLI as the primary interface: prefer `marvain ...` over raw AWS, SAM, direct Python module execution, or direct config edits.
- Use Marvain's explicit `--config <path>` when targeting a non-default config. The normal user config is under `~/.config/marvain/`.
- Do not bypass the intended CLI path just because a command is missing or broken. Diagnose and repair the CLI/package/config path, or ask before using a workaround.
- For user-facing CLI output, use the existing `cli_core_yo.output` primitives. Do not add raw `print()` or `console.print()` for normal command output.
- The root CLI owns JSON mode. Do not add per-command `--json` flags.

## Safety And AWS

- Use `AWS_PROFILE=daylily` and `us-east-1` unless the user explicitly supplies a different profile or region.
- Do not use the AWS `default` profile implicitly or explicitly for Marvain work.
- Do not execute destructive AWS or local reset actions unless the user gives a second explicit approval after being told the exact destructive effect.
- Treat initial requests such as "teardown", "destroy", "delete", "reset", or similar as permission to inspect, prepare, or dry-run only.
- Do not answer interactive confirmation prompts for destructive actions unless that second explicit approval has already been given in the current thread.
- Marvain config can contain secrets or device tokens after bootstrap. Do not print secrets, commit local config, or place real credentials/PHI/PII/customer data in tests or examples.
- If AWS work involves EC2 or another remote host, avoid heredoc-driven remote script generation. Create an inspectable script file, log output, and use a named tmux session for long-running server or workflow processes.

## Change Policy

- Do not add fallback behavior, compatibility shims, migration paths, dual-read/dual-write behavior, or legacy field support unless the user explicitly asks for it in the current thread.
- Prefer direct fixes and hard failures over silent fallback paths.
- Do not assume there is existing production data to migrate unless the user says so.
- Keep changes minimal and local. Avoid drive-by refactors.
- Never invent APIs, filenames, config keys, or results. If something cannot be verified, say what was checked and what remains unknown.

## Activation And Dependency Boundaries

- `activate` is for activating the Conda env and making the repo CLI available. Do not move runtime bootstrap, config creation, AWS deployment, or unrelated tool installation into activation.
- Python package dependencies belong in `pyproject.toml`.
- Conda/system bootstrap belongs in `environment.yaml`.
- If a runtime or test import is missing, fix the repo dependency contract or the explicit setup path, not shell aliases or ad hoc install snippets.
- This repo uses `setuptools_scm`; do not hardcode package versions or edit generated version files.
- Version tags should be bare numeric semver such as `1.2.3`, never `v1.2.3`.

## Git And Release Discipline

- Work on feature branches. Do not push directly to `main`; merge to `main` through PRs unless the user explicitly directs otherwise.
- When asked about branch state or whether the checkout is caught up, fetch first and answer directly from `git status`, `HEAD`, and `origin/main`.
- When publishing or tagging, commit all in-scope work intentionally, push the branch, open a PR to `main`, and use annotated numeric semver tags when a tag is requested.

## Validation

Run the smallest relevant checks for the change. For broad Marvain changes, use the repo CI commands:

```bash
ruff check functions/ layers/ apps/ marvain_cli/ tests/
ruff format --check functions/ layers/ apps/ marvain_cli/ tests/
python scripts/verify_docs_contracts.py
python scripts/generate_implementation_status.py --check
python -m pytest tests/ -q --tb=short
```

- E2E tests are marked `e2e`; run them only when the deployed-stack contract is in scope.
- Before finalizing docs-only or generated-status changes, run `git diff --check`.
