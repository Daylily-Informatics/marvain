from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class ResolvedEnv:
    env: str
    aws_profile: str
    aws_region: str
    stack_name: str
    raw: dict[str, Any]


def find_config_path(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.exists():
            raise ConfigError(f"Config not found: {p}")
        return p

    repo_local = Path("marvain.yaml").resolve()
    if repo_local.exists():
        return repo_local

    # User-global config locations (prefer XDG base dir spec).
    xdg_home = Path(os.getenv("XDG_CONFIG_HOME") or (Path.home() / ".config")).expanduser()
    candidates = [xdg_home / "marvain" / "marvain-config.yaml"]
    for p in candidates:
        if p.exists():
            return p.resolve()

    return None


def load_config_dict(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    obj = yaml.safe_load(text)
    if obj is None:
        return {}
    if not isinstance(obj, dict):
        raise ConfigError("Config root must be a mapping")
    return obj


def save_config_dict(path: Path, cfg: dict[str, Any]) -> None:
    """Write config back to disk using the declared PyYAML dependency."""
    path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")


def resolve_env(
    cfg: dict[str, Any],
    *,
    env: str | None,
    profile_override: str | None,
    region_override: str | None,
    stack_override: str | None,
) -> ResolvedEnv:
    env_name = str(env or os.getenv("MARVAIN_ENV") or cfg.get("default_env") or "").strip()
    if not env_name:
        raise ConfigError("Environment is required. Pass --env, set MARVAIN_ENV, or set config.default_env.")
    envs = cfg.get("envs") or {}
    if not isinstance(envs, dict):
        raise ConfigError("config.envs must be a mapping")
    env_cfg = envs.get(env_name)
    if not isinstance(env_cfg, dict):
        raise ConfigError(f"env '{env_name}' not found (or not a mapping)")

    aws_profile = profile_override or env_cfg.get("aws_profile") or os.getenv("AWS_PROFILE") or ""
    if not aws_profile or aws_profile == "default":
        raise ConfigError("AWS profile is required and may not be 'default'. Pass --profile or set AWS_PROFILE.")

    aws_region = (
        region_override or env_cfg.get("aws_region") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""
    )
    if not aws_region:
        raise ConfigError(
            "AWS region is required. Set envs.<env>.aws_region, or pass --region, or set AWS_REGION/AWS_DEFAULT_REGION."
        )

    stack_name = stack_override or env_cfg.get("stack_name") or ""
    if not stack_name:
        raise ConfigError("stack_name is required. Set envs.<env>.stack_name or pass --stack.")

    return ResolvedEnv(
        env=env_name,
        aws_profile=str(aws_profile),
        aws_region=str(aws_region),
        stack_name=str(stack_name),
        raw=env_cfg,
    )


def sanitize_name_for_stack(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9-]", "", s)
    s = re.sub(r"-+", "-", s)
    return s.strip("-") or "user"


def render_config_yaml(*, env: str, aws_region: str, stack_name: str) -> str:
    # Keep formatting simple so the stdlib parser can read it even without PyYAML.
    return (
        "version: 1\n"
        f"default_env: {env}\n\n"
        "envs:\n"
        f"  {env}:\n"
        f'    aws_region: "{aws_region}"\n'
        f'    stack_name: "{stack_name}"\n'
        "    sam:\n"
        '      template: "template.yaml"\n'
        "      capabilities:\n"
        '        - "CAPABILITY_IAM"\n'
        "      parameter_overrides:\n"
        f'        StageName: "{env}"\n'
        '        DbName: "agenthub"\n'
        '        AuroraMinACU: "0.5"\n'
        '        AuroraMaxACU: "2"\n'
        '        PlannerModel: "gpt-4.1-mini"\n'
        "    resources: {}\n"
        "    bootstrap:\n"
        "      agent_id: null\n"
        "      space_id: null\n"
        "      device_id: null\n"
        "      device_name: null\n"
        "      device_token: null\n"
    )
