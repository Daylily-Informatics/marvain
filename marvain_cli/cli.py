from __future__ import annotations

import os
import sys
from pathlib import Path

from cli_core_yo.app import create_app as _create_app
from cli_core_yo.app import run
from cli_core_yo.spec import (
    BackendDetectSpec,
    BackendValidationSpec,
    CliSpec,
    ContextOptionSpec,
    EnvSpec,
    ExecutionBackendSpec,
    InvocationContextSpec,
    PluginSpec,
    PolicySpec,
    PrereqSpec,
    RuntimeSpec,
    XdgSpec,
)

from marvain_cli._registry_v2 import MARVAIN_AWS_TAG, MARVAIN_RUNTIME_TAG, MARVAIN_SAM_TAG
from marvain_cli.config import ConfigError, find_config_path, load_config_dict, resolve_env

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _marvain_info_hook() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [
        ("Project Root", str(PROJECT_ROOT)),
        ("Conda Env", os.environ.get("CONDA_DEFAULT_ENV", "(not set)")),
        ("AWS Profile", os.environ.get("AWS_PROFILE", "(not set)")),
        ("AWS Region", os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "(not set)"),
    ]
    try:
        config_path = find_config_path(None)
        if config_path is None:
            rows.append(("Marvain Config", "(not found)"))
            return rows
        cfg = load_config_dict(config_path)
        env = resolve_env(
            cfg,
            env=None,
            profile_override=None,
            region_override=None,
            stack_override=None,
        )
        rows.extend(
            [
                ("Marvain Config", str(config_path)),
                ("Marvain Env", env.env),
                ("Stack", env.stack_name),
            ]
        )
    except ConfigError as exc:
        rows.append(("Marvain Config", f"invalid ({exc})"))
    return rows


spec = CliSpec(
    prog_name="marvain",
    app_display_name="Marvain",
    dist_name="marvain",
    root_help="Marvain repository CLI.",
    xdg=XdgSpec(app_dir_name="marvain"),
    policy=PolicySpec(),
    env=EnvSpec(
        active_env_var="MARVAIN_ACTIVE",
        project_root_env_var="MARVAIN_REPO_ROOT",
        activate_script_name="./activate",
        deactivate_script_name="conda deactivate",
        status_fields=["CONDA_DEFAULT_ENV", "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"],
        allow_reset=False,
        preferred_backend="marvain-conda",
    ),
    runtime=RuntimeSpec(
        supported_backends=[
            ExecutionBackendSpec(
                name="marvain-conda",
                kind="conda",
                entry_guidance="source ./activate",
                detect=BackendDetectSpec(env_vars=("CONDA_PREFIX",)),
                validation=BackendValidationSpec(env_vars=("CONDA_PREFIX",)),
            )
        ],
        default_backend="marvain-conda",
        guard_mode="enforced",
        allow_skip_check=False,
        prereqs=[
            PrereqSpec(
                key="marvain-active-env",
                kind="env_var",
                value="MARVAIN_ACTIVE",
                help="Activate Marvain with source ./activate.",
                severity="error",
                applies_to_backends={"marvain-conda"},
                tags={MARVAIN_RUNTIME_TAG},
                success_message="Marvain activation marker is present.",
                failure_message="Marvain is not active. Run `source ./activate` from the repo root.",
            ),
            PrereqSpec(
                key="marvain-conda-env-name",
                kind="command_probe",
                value=(
                    sys.executable,
                    "-c",
                    "import os, sys; sys.exit(0 if os.environ.get('CONDA_DEFAULT_ENV', '').strip() == 'marvain' else 1)",
                ),
                help="Use the marvain conda environment from source ./activate.",
                severity="error",
                applies_to_backends={"marvain-conda"},
                tags={MARVAIN_RUNTIME_TAG},
                success_message="Marvain conda environment name is valid.",
                failure_message="Active conda environment is not marvain. Run `source ./activate` from the repo root.",
            ),
            PrereqSpec(
                key="marvain-package-import",
                kind="python_import",
                value="marvain_cli",
                help="Install this checkout into the active environment.",
                severity="error",
                applies_to_backends={"marvain-conda"},
                tags={MARVAIN_RUNTIME_TAG},
                success_message="Marvain package import is available.",
                failure_message="Marvain package import failed. Run `python -m pip install --editable '.[dev]'`.",
            ),
            PrereqSpec(
                key="aws-cli",
                kind="binary",
                value="aws",
                help="Install AWS CLI and activate Marvain.",
                severity="error",
                applies_to_backends={"marvain-conda"},
                tags={MARVAIN_AWS_TAG},
                success_message="AWS CLI is available.",
                failure_message="AWS CLI is required for this command.",
            ),
            PrereqSpec(
                key="sam-cli",
                kind="binary",
                value="sam",
                help="Install AWS SAM CLI and activate Marvain.",
                severity="error",
                applies_to_backends={"marvain-conda"},
                tags={MARVAIN_SAM_TAG},
                success_message="AWS SAM CLI is available.",
                failure_message="AWS SAM CLI is required for this command.",
            ),
        ],
    ),
    context=InvocationContextSpec(
        options=[
            ContextOptionSpec(
                name="config_path",
                option_flags=("--config",),
                value_type="str",
                help="Path to config YAML",
            ),
            ContextOptionSpec(name="env", option_flags=("--env",), value_type="str", help="Environment name"),
            ContextOptionSpec(
                name="profile", option_flags=("--profile",), value_type="str", help="AWS profile override"
            ),
            ContextOptionSpec(name="region", option_flags=("--region",), value_type="str", help="AWS region override"),
            ContextOptionSpec(name="stack", option_flags=("--stack",), value_type="str", help="Stack name override"),
        ]
    ),
    plugins=PluginSpec(explicit=["marvain_cli.commands.register"]),
    info_hooks=[_marvain_info_hook],
)


def build_app():
    return _create_app(spec)


app = build_app()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--version"]:
        args = ["version"]
    return run(spec, args)


if __name__ == "__main__":
    raise SystemExit(main())
