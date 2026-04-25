from __future__ import annotations

import os
import sys
from pathlib import Path

from cli_core_yo.app import create_app as _create_app
from cli_core_yo.app import run
from cli_core_yo.spec import (
    CliSpec,
    ContextOptionSpec,
    InvocationContextSpec,
    PluginSpec,
    PolicySpec,
    XdgSpec,
)

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
