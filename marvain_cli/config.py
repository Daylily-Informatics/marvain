from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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
    candidates = [
        # Primary canonical location
        xdg_home / "marvain" / "marvain-config.yaml",
        # Legacy locations (kept for backwards compatibility during migration)
        xdg_home / "marvain" / "marvain.yaml",
        xdg_home / "marvain" / "config.yaml",
        Path.home() / ".marvain" / "config.yaml",
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()

    return None


def load_config_dict(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")

    # Prefer PyYAML when installed.
    try:
        import yaml  # type: ignore

        obj = yaml.safe_load(text)
        if obj is None:
            return {}
        if not isinstance(obj, dict):
            raise ConfigError("Config root must be a mapping")
        return obj
    except ModuleNotFoundError:
        return _parse_simple_yaml(text)


def save_config_dict(path: Path, cfg: dict[str, Any]) -> None:
    """Write config back to disk.

    Prefer PyYAML when available. Otherwise use a small deterministic YAML emitter
    compatible with `_parse_simple_yaml`.
    """

    try:
        import yaml  # type: ignore

        text = yaml.safe_dump(cfg, sort_keys=False)
    except ModuleNotFoundError:
        text = dump_simple_yaml(cfg)

    path.write_text(text, encoding="utf-8")


def resolve_env(
    cfg: dict[str, Any],
    *,
    env: str | None,
    profile_override: str | None,
    region_override: str | None,
    stack_override: str | None,
) -> ResolvedEnv:
    env_name = env or os.getenv("MARVAIN_ENV") or str(cfg.get("default_env") or "dev")
    envs = cfg.get("envs") or {}
    if not isinstance(envs, dict):
        raise ConfigError("config.envs must be a mapping")
    env_cfg = envs.get(env_name)
    if not isinstance(env_cfg, dict):
        raise ConfigError(f"env '{env_name}' not found (or not a mapping)")

    aws_profile = profile_override or env_cfg.get("aws_profile") or os.getenv("AWS_PROFILE") or ""
    if not aws_profile or aws_profile == "default":
        raise ConfigError(
            "AWS profile is required and may not be 'default'. "
            "Set envs.<env>.aws_profile, or pass --profile, or set AWS_PROFILE."
        )

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


def render_config_yaml(*, env: str, aws_profile: str, aws_region: str, stack_name: str) -> str:
    # Keep formatting simple so the stdlib parser can read it even without PyYAML.
    return (
        "version: 1\n"
        f"default_env: {env}\n\n"
        "envs:\n"
        f"  {env}:\n"
        f'    aws_profile: "{aws_profile}"\n'
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


def dump_simple_yaml(obj: Any) -> str:
    """Emit a tiny YAML subset used by this repo.

    Supports dict/list/scalars (str/int/float/bool/None). Output is deterministic.
    """

    def quote(s: str) -> str:
        needs = False
        if s == "" or s != s.strip():
            needs = True
        if any(ch in s for ch in [":", "#", "{", "}", "[", "]", "\n", "\t"]):
            needs = True
        if s.lower() in ("null", "true", "false", "~"):
            needs = True
        if re.fullmatch(r"[-+]?[0-9]+(\.[0-9]+)?", s or ""):
            needs = True
        if not needs:
            return s
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{esc}"'

    def scalar(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            return str(v)
        if isinstance(v, str):
            return quote(v)
        raise ConfigError(f"Unsupported scalar type in config: {type(v)!r}")

    out: list[str] = []

    def emit(v: Any, indent: int) -> None:
        pad = " " * indent
        if isinstance(v, dict):
            if not v:
                out.append(f"{pad}{{}}")
                return
            for k, vv in v.items():
                if not isinstance(k, str):
                    raise ConfigError("Only string keys are supported in config")
                if isinstance(vv, (dict, list)):
                    out.append(f"{pad}{k}:")
                    emit(vv, indent + 2)
                else:
                    out.append(f"{pad}{k}: {scalar(vv)}")
            return
        if isinstance(v, list):
            if not v:
                out.append(f"{pad}[]")
                return
            for item in v:
                if isinstance(item, (dict, list)):
                    out.append(f"{pad}-")
                    emit(item, indent + 2)
                else:
                    out.append(f"{pad}- {scalar(item)}")
            return
        out.append(f"{pad}{scalar(v)}")

    emit(obj, 0)
    return "\n".join(out).rstrip() + "\n"


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Very small YAML subset parser.

    Supports:
      - mappings via indentation
      - lists via '- '
      - scalars: strings, quoted strings, null, true/false, ints, floats

    This is intentionally limited but sufficient for marvain.yaml generated by the CLI.
    """

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        s = raw.rstrip("\n")
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        # strip inline comments (naive, but ok for our generated YAML)
        if "#" in s:
            before, _hash, after = s.partition("#")
            if before.strip():
                s = before.rstrip()
        indent = len(s) - len(s.lstrip(" "))
        lines.append((indent, s.lstrip(" ")))

    def parse_scalar(v: str) -> Any:
        v = v.strip()
        if v in ("null", "~"):
            return None
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        if re.fullmatch(r"[-+]?[0-9]+", v):
            try:
                return int(v)
            except Exception:
                return v
        if re.fullmatch(r"[-+]?[0-9]+\.[0-9]+", v):
            try:
                return float(v)
            except Exception:
                return v
        # inline empty map/list shortcuts
        if v == "{}":
            return {}
        if v == "[]":
            return []
        return v

    def parse_block(i: int, indent: int) -> tuple[Any, int]:
        if i >= len(lines):
            return {}, i
        cur_indent, cur = lines[i]
        if cur_indent < indent:
            return {}, i
        if cur_indent != indent:
            raise ConfigError(f"Invalid indentation at line: {cur}")

        if cur.startswith("- "):
            arr: list[Any] = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                item = lines[i][1][2:].strip()
                if not item:
                    # nested block list item (rare; not used by our config)
                    child, i = parse_block(i + 1, indent + 2)
                    arr.append(child)
                else:
                    arr.append(parse_scalar(item))
                    i += 1
            return arr, i

        obj: dict[str, Any] = {}
        while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
            line = lines[i][1]
            if ":" not in line:
                raise ConfigError(f"Expected key: value, got: {line}")
            k, _colon, rest = line.partition(":")
            key = k.strip()
            rest = rest.lstrip(" ")
            if rest == "":
                # nested block
                if i + 1 < len(lines) and lines[i + 1][0] >= indent + 2:
                    child, j = parse_block(i + 1, indent + 2)
                    obj[key] = child
                    i = j
                else:
                    obj[key] = {}
                    i += 1
            else:
                obj[key] = parse_scalar(rest)
                i += 1
        return obj, i

    parsed, _ = parse_block(0, 0)
    if not isinstance(parsed, dict):
        raise ConfigError("Config root must be a mapping")
    return parsed
