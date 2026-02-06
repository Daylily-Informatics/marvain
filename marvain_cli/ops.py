from __future__ import annotations

import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from typing import Any, Iterable

from marvain_cli.config import ConfigError, ResolvedEnv, find_config_path, load_config_dict, resolve_env, save_config_dict


MARVAIN_CONDA_ENV_NAME = "marvain"
MARVAIN_CONDA_ENV_FILE = "config/marvain_conda.yaml"
MARVAIN_ALLOW_VENV_ENVVAR = "MARVAIN_ALLOW_VENV"


@dataclass(frozen=True)
class Ctx:
    config_path: Path
    cfg: dict[str, Any]
    env: ResolvedEnv


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def _fmt_cmd(cmd: list[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def _fmt_cmd_redacted(cmd: list[str]) -> str:
    """
    Format a command for logging, redacting known sensitive arguments.

    Currently redacts values passed to flags like ``--secret-arn``.
    """
    # Work on a shallow copy so we don't mutate the original command.
    redacted_cmd = list(cmd)
    # Flags whose following argument should be treated as sensitive.
    sensitive_flags = {"--secret-arn"}
    i = 0
    while i < len(redacted_cmd) - 1:
        if redacted_cmd[i] in sensitive_flags:
            # Replace the following argument with a redacted marker.
            redacted_cmd[i + 1] = "***REDACTED***"
            i += 2
        else:
            i += 1
    return _fmt_cmd(redacted_cmd)


def load_ctx(
    *,
    config_override: str | None,
    env: str | None,
    profile: str | None,
    region: str | None,
    stack: str | None,
) -> Ctx:
    p = find_config_path(config_override)
    if p is None:
        raise ConfigError("No config found. Create one with: marvain config init")
    cfg = load_config_dict(p)
    resolved = resolve_env(cfg, env=env, profile_override=profile, region_override=region, stack_override=stack)
    return Ctx(config_path=p, cfg=cfg, env=resolved)


def cmd_env(resolved: ResolvedEnv) -> dict[str, str]:
    # We prefer explicit configuration. Many AWS/SAM tools honor these env vars.
    return {
        "AWS_PROFILE": resolved.aws_profile,
        "AWS_REGION": resolved.aws_region,
        "AWS_DEFAULT_REGION": resolved.aws_region,
    }


def aws_cli_args(resolved: ResolvedEnv) -> list[str]:
    """Explicit AWS CLI args.

    We still pass env vars via `cmd_env()` for tools that only honor env, but the
    AWS CLI supports explicit `--profile/--region` which we prefer.
    """

    return ["--profile", resolved.aws_profile, "--region", resolved.aws_region]


def sam_cli_args(resolved: ResolvedEnv) -> list[str]:
    # SAM CLI supports `--profile/--region` for deploy/logs.
    return ["--profile", resolved.aws_profile, "--region", resolved.aws_region]


def run_cmd(
    cmd: list[str],
    *,
    env: dict[str, str] | None,
    dry_run: bool,
    check: bool = True,
    cwd: str | None = None,
) -> int:
    _eprint(f"$ {_fmt_cmd_redacted(cmd)}")
    if dry_run:
        return 0
    merged = os.environ.copy()
    if env:
        merged.update(env)
    p = subprocess.run(cmd, env=merged, cwd=cwd)
    if check and p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd)
    return p.returncode


def run_json(
    cmd: list[str],
    *,
    env: dict[str, str] | None,
    dry_run: bool,
    cwd: str | None = None,
) -> Any:
    _eprint(f"$ {_fmt_cmd_redacted(cmd)}")
    if dry_run:
        return {}
    merged = os.environ.copy()
    if env:
        merged.update(env)
    out = subprocess.check_output(cmd, env=merged, cwd=cwd)
    return json.loads(out.decode("utf-8"))


def require_tools(names: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for n in names:
        if shutil.which(n) is None:
            missing.append(n)
    return missing


def _truthy_env(name: str) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _conda_env_is_active(env_name: str) -> bool:
    if (os.environ.get("CONDA_DEFAULT_ENV") or "") == env_name:
        return True
    prefix = os.environ.get("CONDA_PREFIX") or ""
    if prefix:
        return os.path.basename(prefix.rstrip("/")) == env_name
    return False


def _conda_env_exists(env_name: str) -> bool:
    if shutil.which("conda") is None:
        return False
    try:
        out = subprocess.check_output(["conda", "env", "list", "--json"])
        data = json.loads(out.decode("utf-8"))
        envs = data.get("envs") or []
        for p in envs:
            if isinstance(p, str) and os.path.basename(p.rstrip("/")) == env_name:
                return True
        return False
    except Exception:
        return False


def _python_is_311() -> bool:
    return sys.version_info[:2] == (3, 11)


def _conda_preflight(*, enforce: bool) -> int:
    """Ensure the primary Conda env exists and is active.

    We keep an escape hatch via MARVAIN_ALLOW_VENV=1.

    Returns:
      0 on success
      2 on preflight failure (matches other CLI error semantics)
    """

    if not enforce:
        return 0
    if _truthy_env(MARVAIN_ALLOW_VENV_ENVVAR):
        return 0

    if shutil.which("conda") is None:
        _eprint(
            "Conda is required for marvain. Install Miniconda/Mambaforge, then create env with: "
            f"conda env create -f {MARVAIN_CONDA_ENV_FILE} (or set {MARVAIN_ALLOW_VENV_ENVVAR}=1 to bypass)"
        )
        return 2

    if not _conda_env_exists(MARVAIN_CONDA_ENV_NAME):
        _eprint(
            f"Conda env '{MARVAIN_CONDA_ENV_NAME}' not found. Create it with: conda env create -f {MARVAIN_CONDA_ENV_FILE}"
        )
        return 2

    if not _conda_env_is_active(MARVAIN_CONDA_ENV_NAME):
        _eprint(
            f"Conda env '{MARVAIN_CONDA_ENV_NAME}' exists but is not active. Activate with: conda activate {MARVAIN_CONDA_ENV_NAME} (or source ./marvain_activate)"
        )
        return 2

    if not _python_is_311():
        _eprint(
            f"Python {sys.version_info.major}.{sys.version_info.minor} detected; marvain requires Python 3.11 (activate conda env '{MARVAIN_CONDA_ENV_NAME}')."
        )
        return 2

    # SAM's Python builder specifically looks for `python3.11` on PATH.
    if shutil.which("python3.11") is None:
        _eprint(
            "python3.11 not found on PATH (required by `sam build` for runtime python3.11). "
            f"Activate conda env '{MARVAIN_CONDA_ENV_NAME}' (or source ./marvain_activate)."
        )
        return 2

    return 0


def aws_stack_outputs(ctx: Ctx, *, dry_run: bool) -> dict[str, str]:
    cmd = [
        "aws",
        "cloudformation",
        "describe-stacks",
        *aws_cli_args(ctx.env),
        "--stack-name",
        ctx.env.stack_name,
        "--output",
        "json",
    ]
    data = run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)
    outs: dict[str, str] = {}
    stacks = (data or {}).get("Stacks") or []
    if not stacks:
        return outs
    for o in stacks[0].get("Outputs") or []:
        k = o.get("OutputKey")
        v = o.get("OutputValue")
        if isinstance(k, str) and isinstance(v, str):
            outs[k] = v
    return outs


def _env_resources_from_config(ctx: Ctx) -> dict[str, Any]:
    envs = ctx.cfg.get("envs")
    if not isinstance(envs, dict):
        return {}
    env_cfg = envs.get(ctx.env.env)
    if not isinstance(env_cfg, dict):
        return {}
    res = env_cfg.get("resources")
    return res if isinstance(res, dict) else {}


def resolve_stack_output(ctx: Ctx, *, key: str, dry_run: bool) -> str:
    """Resolve a CloudFormation output by key.

    Prefers config.envs[env].resources (populated by `marvain monitor outputs --write-config`).
    Falls back to live `describe-stacks` only when not dry-run.
    """

    res = _env_resources_from_config(ctx)
    v = res.get(key)
    if isinstance(v, str) and v:
        return v
    if dry_run:
        raise ConfigError(
            f"Missing stack output '{key}' in config. Run: marvain monitor outputs --write-config"
        )
    outs = aws_stack_outputs(ctx, dry_run=False)
    v2 = outs.get(key)
    if isinstance(v2, str) and v2:
        return v2
    raise ConfigError(f"Missing stack output '{key}' (not in config and not in live stack outputs)")


def _redact_secret(s: str, *, keep: int = 6) -> str:
    s = str(s or "")
    if len(s) <= keep:
        return "***"
    return s[:keep] + "..."


def resolve_access_token(access_token: str | None) -> str:
    tok = (access_token or os.getenv("MARVAIN_ACCESS_TOKEN") or "").strip()
    if not tok:
        raise ConfigError("Missing access token (pass --access-token or set MARVAIN_ACCESS_TOKEN)")
    return tok


def resolve_hub_rest_api_base(ctx: Ctx, *, hub_rest_api_base: str | None, dry_run: bool) -> str:
    base = (hub_rest_api_base or os.getenv("MARVAIN_HUB_REST_API_BASE") or "").strip()
    if base:
        return base.rstrip("/")
    return resolve_stack_output(ctx, key="HubRestApiBase", dry_run=dry_run).rstrip("/")


def _hub_url(base: str, path: str) -> str:
    p = "/" + str(path or "").lstrip("/")
    return base.rstrip("/") + p


def hub_api_json(
    ctx: Ctx,
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    access_token: str,
    hub_rest_api_base: str | None,
    dry_run: bool,
    timeout_s: int = 30,
) -> dict[str, Any]:
    """Call Hub REST API with Bearer access token.

    Uses stdlib urllib; intended for CLI automation and is dry-run testable.
    """

    base = resolve_hub_rest_api_base(ctx, hub_rest_api_base=hub_rest_api_base, dry_run=dry_run)
    url = _hub_url(base, path)
    method_u = str(method).upper()

    # Avoid printing secrets; but log enough to reproduce.
    _eprint(f"$ HTTP {method_u} {url} (Authorization: Bearer {_redact_secret(access_token)})")
    if payload is not None:
        _eprint(f"$   json={json.dumps(payload, sort_keys=True)}")

    if dry_run:
        return {}

    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method_u)
    req.add_header("Authorization", f"Bearer {access_token}")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        msg = raw.decode("utf-8", errors="replace")
        raise RuntimeError(f"Hub API HTTP {getattr(e, 'code', '?')}: {msg}")

    txt = raw.decode("utf-8") if raw else "{}"
    return json.loads(txt)


def hub_claim_first_owner(
    ctx: Ctx,
    *,
    agent_id: str,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    return hub_api_json(
        ctx,
        method="POST",
        path=f"/v1/agents/{agent_id}/claim_owner",
        payload=None,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def hub_list_memberships(
    ctx: Ctx,
    *,
    agent_id: str,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    return hub_api_json(
        ctx,
        method="GET",
        path=f"/v1/agents/{agent_id}/memberships",
        payload=None,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def hub_grant_membership(
    ctx: Ctx,
    *,
    agent_id: str,
    email: str,
    role: str,
    relationship_label: str | None,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    payload: dict[str, Any] = {"email": email, "role": role}
    if relationship_label is not None:
        payload["relationship_label"] = relationship_label
    return hub_api_json(
        ctx,
        method="POST",
        path=f"/v1/agents/{agent_id}/memberships",
        payload=payload,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def hub_update_membership(
    ctx: Ctx,
    *,
    agent_id: str,
    user_id: str,
    role: str,
    relationship_label: str | None,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    payload: dict[str, Any] = {"role": role}
    if relationship_label is not None:
        payload["relationship_label"] = relationship_label
    return hub_api_json(
        ctx,
        method="PATCH",
        path=f"/v1/agents/{agent_id}/memberships/{user_id}",
        payload=payload,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def hub_revoke_membership(
    ctx: Ctx,
    *,
    agent_id: str,
    user_id: str,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    return hub_api_json(
        ctx,
        method="DELETE",
        path=f"/v1/agents/{agent_id}/memberships/{user_id}",
        payload=None,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def hub_register_device(
    ctx: Ctx,
    *,
    agent_id: str,
    name: str | None,
    scopes: list[str] | None,
    access_token: str | None,
    hub_rest_api_base: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    tok = resolve_access_token(access_token)
    payload: dict[str, Any] = {"agent_id": agent_id}
    if name is not None:
        payload["name"] = name
    if scopes is not None:
        payload["scopes"] = scopes
    return hub_api_json(
        ctx,
        method="POST",
        path="/v1/devices/register",
        payload=payload,
        access_token=tok,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=dry_run,
    )


def sam_build_simple(*, dry_run: bool, template: str = "template.yaml") -> int:
    """Run `sam build` without requiring a config file."""

    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    # Note: --clean was removed in newer SAM CLI versions; use --cached=false if needed.
    return run_cmd(["sam", "build", "-t", template], env=None, dry_run=dry_run)


def sam_build(ctx: Ctx, *, dry_run: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    sam_cfg = (ctx.env.raw.get("sam") or {}) if isinstance(ctx.env.raw.get("sam"), dict) else {}
    template = str(sam_cfg.get("template") or "template.yaml")
    return run_cmd(["sam", "build", "-t", template], env=cmd_env(ctx.env), dry_run=dry_run)


def sam_deploy(ctx: Ctx, *, dry_run: bool, guided: bool, no_confirm: bool = False) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    sam_cfg = (ctx.env.raw.get("sam") or {}) if isinstance(ctx.env.raw.get("sam"), dict) else {}
    source_template = str(sam_cfg.get("template") or "template.yaml")
    caps = sam_cfg.get("capabilities") or ["CAPABILITY_IAM"]
    if not isinstance(caps, list):
        caps = ["CAPABILITY_IAM"]
    param_overrides = sam_cfg.get("parameter_overrides") or {}
    if not isinstance(param_overrides, dict):
        param_overrides = {}

    # Check for LIVEKIT_URL environment variable and add to parameter overrides
    livekit_url = os.environ.get("LIVEKIT_URL", "").strip()
    if livekit_url:
        param_overrides["LiveKitUrl"] = livekit_url
        _eprint(f"Using LIVEKIT_URL from environment: {livekit_url}")
    elif "LiveKitUrl" not in param_overrides:
        _eprint("ERROR: LIVEKIT_URL environment variable is not set and LiveKitUrl is not in parameter_overrides.")
        _eprint("Please set LIVEKIT_URL or add LiveKitUrl to your marvain config.")
        _eprint("Hint: export LIVEKIT_URL=<your-livekit-url> or add LiveKitUrl to sam.parameter_overrides in marvain-config.yaml")
        return 1

    # Always build before deploy so Lambda functions include vendored dependencies.
    # This prevents the common failure mode where deployed Lambdas are missing
    # runtime deps (e.g., mangum) if `sam deploy` is run against the source template.
    build_rc = run_cmd(["sam", "build", "-t", source_template], env=cmd_env(ctx.env), dry_run=dry_run)
    if build_rc != 0:
        return build_rc

    # Deploy the built template.
    template = ".aws-sam/build/template.yaml"

    cmd = [
        "sam",
        "deploy",
        *sam_cli_args(ctx.env),
        "--template-file",
        template,
        "--stack-name",
        ctx.env.stack_name,
        "--resolve-s3",
        "--no-fail-on-empty-changeset",
    ]
    if guided:
        cmd.append("--guided")
    else:
        # Non-guided deploys must be fully non-interactive by default.
        # Keep `--no-confirm` as a legacy flag, but `--no-guided` should never
        # require stdin input.
        cmd.append("--no-confirm-changeset")

    if caps:
        cmd.append("--capabilities")
        cmd.extend([str(c) for c in caps])

    if param_overrides:
        cmd.append("--parameter-overrides")
        for k, v in param_overrides.items():
            cmd.append(f"{k}={v}")

    return run_cmd(cmd, env=cmd_env(ctx.env), dry_run=dry_run)


def _stream_process(
    *,
    prefix: str | None,
    cmd: list[str],
    env: dict[str, str],
    log_fh: TextIO | None,
    log_lock: threading.Lock | None,
) -> int:
    """Run a command and stream combined stdout/stderr to stdout (and optionally a file)."""

    p = subprocess.Popen(cmd, env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert p.stdout is not None
    try:
        for line in p.stdout:
            out_line = f"[{prefix}] {line}" if prefix else line
            sys.stdout.write(out_line)
            sys.stdout.flush()
            if log_fh is not None:
                if log_lock is not None:
                    with log_lock:
                        log_fh.write(out_line)
                        log_fh.flush()
                else:
                    log_fh.write(out_line)
                    log_fh.flush()
    except KeyboardInterrupt:
        # Ctrl-C will generally be handled in the main thread; this keeps streaming helpers quiet.
        pass
    finally:
        try:
            p.terminate()
        except Exception:
            pass
    return p.wait()


def _tail_one(
    function_name: str,
    cmd: list[str],
    env: dict[str, str],
    *,
    log_fh: TextIO | None,
    log_lock: threading.Lock | None,
) -> None:
    _stream_process(prefix=function_name, cmd=cmd, env=env, log_fh=log_fh, log_lock=log_lock)


def _since_to_sam_start_time(since: str) -> str:
    """Convert our compact --since (e.g. 10m, 1h) into `sam logs -s` format.

    SAM CLI accepts natural language like: '10min ago', '2hour ago'.
    If `since` doesn't match the compact form, we pass it through as-is.
    """

    s = since.strip()
    if not s:
        return s
    # Compact form: <int><unit>
    if len(s) >= 2 and s[:-1].isdigit() and s[-1] in ("s", "m", "h", "d"):
        n = int(s[:-1])
        unit = s[-1]
        if unit == "s":
            return f"{n}sec ago"
        if unit == "m":
            return f"{n}min ago"
        if unit == "h":
            return f"{n}hour ago"
        if unit == "d":
            return f"{n}day ago"
    return s


def sam_logs(
    ctx: Ctx,
    *,
    dry_run: bool,
    functions: list[str] | None,
    tail: bool,
    since: str | None,
    output_file: str | None = None,
    suppress_sam_warnings: bool = False,
) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    base = ["sam", "logs", *sam_cli_args(ctx.env), "--stack-name", ctx.env.stack_name]
    if since:
        # SAM CLI uses -s/--start-time (not --since).
        base.extend(["-s", _since_to_sam_start_time(since)])
    if tail:
        base.append("--tail")

    if dry_run:
        if functions:
            for f in functions:
                _eprint(f"$ {_fmt_cmd([*base, '--name', f])}")
        else:
            _eprint(f"$ {_fmt_cmd(base)}")
        return 0

    env = cmd_env(ctx.env)
    if suppress_sam_warnings:
        # SAM CLI is a Python program; this suppresses a known, non-actionable warning
        # emitted by SAM's dependencies on some Python versions.
        env["PYTHONWARNINGS"] = (
            "ignore:Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.*:UserWarning"
        )

    log_fh: TextIO | None = None
    log_lock: threading.Lock | None = None
    if output_file:
        p = Path(output_file)
        if p.parent and str(p.parent) != ".":
            p.parent.mkdir(parents=True, exist_ok=True)
        log_fh = p.open("a", encoding="utf-8")
        log_lock = threading.Lock()

    try:
        # Preferred UX: one `sam logs` call for all stack resources (no per-function `--name`).
        if not functions:
            return _stream_process(prefix=None, cmd=base, env=env, log_fh=log_fh, log_lock=log_lock)

        # If functions were specified, tail each explicitly (repeatable --function).
        threads: list[threading.Thread] = []
        for f in functions:
            cmd = [*base, "--name", f]
            t = threading.Thread(
                target=_tail_one,
                args=(f, cmd, env),
                kwargs={"log_fh": log_fh, "log_lock": log_lock},
                daemon=True,
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return 0
    finally:
        if log_fh is not None:
            try:
                log_fh.close()
            except Exception:
                pass


def monitor_outputs(ctx: Ctx, *, dry_run: bool, write_config: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    outs = aws_stack_outputs(ctx, dry_run=dry_run)
    print(json.dumps({"stack": ctx.env.stack_name, "outputs": outs}, indent=2, sort_keys=True))

    if write_config and not dry_run:
        envs = ctx.cfg.setdefault("envs", {})
        if isinstance(envs, dict):
            env_cfg = envs.setdefault(ctx.env.env, {})
            if isinstance(env_cfg, dict):
                res = env_cfg.setdefault("resources", {})
                if isinstance(res, dict):
                    for k, v in outs.items():
                        res[k] = v
                save_config_dict(ctx.config_path, ctx.cfg)
                _eprint(f"Updated resources in config: {ctx.config_path}")
    return 0


def monitor_status(ctx: Ctx, *, dry_run: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    cmd = [
        "aws",
        "cloudformation",
        "describe-stacks",
        *aws_cli_args(ctx.env),
        "--stack-name",
        ctx.env.stack_name,
        "--output",
        "json",
    ]
    data = run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)
    if dry_run:
        return 0
    stacks = (data or {}).get("Stacks") or []
    if not stacks:
        _eprint("No stack found")
        return 1
    s0 = stacks[0]
    print(json.dumps({"stack": ctx.env.stack_name, "status": s0.get("StackStatus")}, indent=2, sort_keys=True))
    return 0


def _pretty_print_status(result: dict[str, Any]) -> None:
    """Pretty print status result."""
    stack = result.get("stack", "unknown")
    exists = result.get("exists", False)
    status_val = result.get("status", "UNKNOWN")
    outputs = result.get("outputs", {})

    # Status color indicators
    if not exists:
        status_indicator = "⚪"  # Not deployed
        status_color = ""
    elif "COMPLETE" in status_val and "ROLLBACK" not in status_val:
        status_indicator = "🟢"  # Healthy
        status_color = ""
    elif "IN_PROGRESS" in status_val:
        status_indicator = "🟡"  # In progress
        status_color = ""
    else:
        status_indicator = "🔴"  # Error/rollback
        status_color = ""

    print(f"\n{status_indicator} Stack: {stack}")
    print(f"   Status: {status_val if exists else 'NOT DEPLOYED'}")

    if exists and outputs:
        print(f"\n   Resources ({len(outputs)}):")
        # Group outputs by type for better readability
        for key in sorted(outputs.keys()):
            value = outputs[key]
            # Truncate long values
            display_val = value if len(value) <= 60 else value[:57] + "..."
            print(f"     {key}: {display_val}")
    print()


def status(ctx: Ctx, *, dry_run: bool, output_json: bool = False) -> int:
    """Show deployment status: stack existence, status, and key resources."""
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    cmd = [
        "aws",
        "cloudformation",
        "describe-stacks",
        *aws_cli_args(ctx.env),
        "--stack-name",
        ctx.env.stack_name,
        "--output",
        "json",
    ]
    data = run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)
    if dry_run:
        return 0

    stacks = (data or {}).get("Stacks") or []
    if not stacks:
        result = {"stack": ctx.env.stack_name, "exists": False}
        if output_json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            _pretty_print_status(result)
        return 0

    s0 = stacks[0]
    stack_status = s0.get("StackStatus", "UNKNOWN")

    # Extract key outputs
    outputs = {}
    for o in s0.get("Outputs") or []:
        k = o.get("OutputKey")
        v = o.get("OutputValue")
        if isinstance(k, str) and isinstance(v, str):
            outputs[k] = v

    result = {
        "stack": ctx.env.stack_name,
        "exists": True,
        "status": stack_status,
        "outputs": outputs,
    }
    if output_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _pretty_print_status(result)
    return 0


def _pretty_print_info(result: dict[str, Any]) -> None:
    """Pretty print info result."""
    env = result.get("environment", "unknown")
    stack = result.get("stack_name", "unknown")
    profile = result.get("aws_profile", "default")
    region = result.get("aws_region", "unknown")
    resources = result.get("resources") or {}

    print(f"\n📦 Environment: {env}")
    print(f"   Stack:       {stack}")
    print(f"   Profile:     {profile}")
    print(f"   Region:      {region}")

    if resources:
        print(f"\n   Resources ({len(resources)}):")
        for key in sorted(resources.keys()):
            value = resources[key]
            # Truncate long values
            display_val = value if len(value) <= 60 else value[:57] + "..."
            print(f"     {key}: {display_val}")
    else:
        print("\n   Resources: (stack not deployed or no outputs)")
    print()


def info(ctx: Ctx, *, dry_run: bool, output_json: bool = False) -> int:
    """Show deployment info: stack name, region, profile, and resource details."""
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    # Get stack outputs if stack exists
    outputs = {}
    cmd = [
        "aws",
        "cloudformation",
        "describe-stacks",
        *aws_cli_args(ctx.env),
        "--stack-name",
        ctx.env.stack_name,
        "--output",
        "json",
    ]
    data = run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)
    if not dry_run and data:
        stacks = (data or {}).get("Stacks") or []
        if stacks:
            for o in stacks[0].get("Outputs") or []:
                k = o.get("OutputKey")
                v = o.get("OutputValue")
                if isinstance(k, str) and isinstance(v, str):
                    outputs[k] = v

    result = {
        "environment": ctx.env.env,
        "stack_name": ctx.env.stack_name,
        "aws_profile": ctx.env.aws_profile,
        "aws_region": ctx.env.aws_region,
        "resources": outputs if outputs else None,
    }
    if output_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        _pretty_print_info(result)
    return 0


def teardown(ctx: Ctx, *, dry_run: bool, yes: bool, wait: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    if dry_run and not yes:
        # In dry-run, don't force confirmation; just show what would happen.
        yes = True
    if not yes:
        _eprint(f"About to delete CloudFormation stack: {ctx.env.stack_name}")
        _eprint("Re-run with --yes to confirm.")
        return 2
    run_cmd(
        ["aws", "cloudformation", "delete-stack", *aws_cli_args(ctx.env), "--stack-name", ctx.env.stack_name],
        env=cmd_env(ctx.env),
        dry_run=dry_run,
    )
    if wait:
        run_cmd(
            [
                "aws",
                "cloudformation",
                "wait",
                "stack-delete-complete",
                *aws_cli_args(ctx.env),
                "--stack-name",
                ctx.env.stack_name,
            ],
            env=cmd_env(ctx.env),
            dry_run=dry_run,
        )
    return 0


def doctor(ctx: Ctx, *, dry_run: bool) -> int:
    rc = _conda_preflight(enforce=True)
    if rc != 0:
        return rc

    missing = require_tools(["aws", "sam", "python3.11"])
    if missing:
        _eprint(f"Missing required tools on PATH: {', '.join(missing)}")
        return 2

    # Validate credentials.
    run_cmd(["aws", "sts", "get-caller-identity", *aws_cli_args(ctx.env)], env=cmd_env(ctx.env), dry_run=dry_run)
    _eprint("doctor OK")
    return 0


def gui_run(
    ctx: Ctx,
    *,
    dry_run: bool,
    host: str,
    port: int,
    reload: bool,
    stack_prefix: str | None,
) -> int:
    """Start the local GUI server.

    The GUI runs locally (developer laptop or EC2) and connects to deployed
    AWS resources (Aurora Data API, Cognito, S3, SQS) via environment variables.

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 8084)
        reload: Enable auto-reload on code changes
        stack_prefix: Unused (kept for backward CLI compatibility)
    """
    import subprocess

    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    _ = stack_prefix  # Unused but kept for backward CLI compatibility

    repo_root = Path(__file__).parent.parent
    hub_api_dir = repo_root / "functions" / "hub_api"
    shared_layer = repo_root / "layers" / "shared" / "python"

    # Get resources from marvain-config.yaml config
    resources = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("resources", {})
    if not resources:
        _eprint(f"ERROR: No resources found in config for env '{ctx.env.env}'")
        _eprint("Run 'marvain monitor outputs --write-config' to populate resources.")
        return 2

    cmd = ["uvicorn", "app:app", "--host", host, "--port", str(port)]
    if reload:
        cmd.append("--reload")

    redirect_uri = f"http://localhost:{port}/auth/callback"

    _eprint(f"Starting local GUI server at http://{host}:{port}")
    _eprint(f"Using config: {ctx.config_path} (env: {ctx.env.env})")
    _eprint(f"$ cd {hub_api_dir} && {' '.join(cmd)}")

    if dry_run:
        return 0

    # Build environment from marvain-config.yaml resources
    env = os.environ.copy()

    # Map config resource keys to environment variable names
    resource_to_env = {
        "DbClusterArn": "DB_RESOURCE_ARN",
        "DbSecretArn": "DB_SECRET_ARN",
        "DbName": "DB_NAME",
        "CognitoUserPoolId": "COGNITO_USER_POOL_ID",
        "CognitoAppClientId": "COGNITO_APP_CLIENT_ID",
        "CognitoDomain": "COGNITO_DOMAIN",
        "AdminApiKeySecretArn": "ADMIN_SECRET_ARN",
        "OpenAISecretArn": "OPENAI_SECRET_ARN",
        "LiveKitSecretArn": "LIVEKIT_SECRET_ARN",
        "LiveKitUrl": "LIVEKIT_URL",
        "HubWebSocketUrl": "WS_API_URL",
        "AuditBucketName": "AUDIT_BUCKET",
        "ArtifactBucketName": "ARTIFACT_BUCKET",
        "SessionSecretArn": "SESSION_SECRET_ARN",
    }

    for res_key, env_key in resource_to_env.items():
        if res_key in resources and resources[res_key]:
            env[env_key] = str(resources[res_key])

    # Set Cognito redirect URI dynamically
    env["COGNITO_REDIRECT_URI"] = redirect_uri
    env["COGNITO_REGION"] = ctx.env.aws_region

    # Set AWS credentials from config
    env["AWS_PROFILE"] = ctx.env.aws_profile
    env["AWS_REGION"] = ctx.env.aws_region
    env["AWS_DEFAULT_REGION"] = ctx.env.aws_region

    # Local development settings
    env["ENVIRONMENT"] = "local"
    env["LOG_LEVEL"] = env.get("LOG_LEVEL", "DEBUG")
    # For local dev, use a static session secret (Lambda uses SESSION_SECRET_ARN)
    if "SESSION_SECRET_KEY" not in env:
        env["SESSION_SECRET_KEY"] = "local-dev-session-secret-key-change-in-production-123456"

    # Set PYTHONPATH to include shared layer for agent_hub imports
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = f"{shared_layer}:{existing_pythonpath}"
    else:
        env["PYTHONPATH"] = str(shared_layer)

    return subprocess.call(cmd, cwd=str(hub_api_dir), env=env)


# -----------------------------------------------------------------------------
# GUI Lifecycle Management
# -----------------------------------------------------------------------------

GUI_DEFAULT_HOST = "localhost"
GUI_DEFAULT_PORT = 8084
GUI_PID_FILENAME = ".marvain-gui.pid"
GUI_LOG_FILENAME = ".marvain-gui.log"


def _get_gui_pid_file() -> Path:
    """Return the path to the GUI PID file in the repo root."""
    repo_root = Path(__file__).parent.parent
    return repo_root / GUI_PID_FILENAME


def _get_gui_log_file() -> Path:
    """Return the path to the GUI log file in the repo root."""
    repo_root = Path(__file__).parent.parent
    return repo_root / GUI_LOG_FILENAME


def _is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, OSError):
            return False


def _get_pid_on_port(port: int) -> int | None:
    """Get the PID of the process listening on a port (POSIX-portable)."""
    # Try lsof first (macOS and most Linux)
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            # lsof may return multiple PIDs; take the first one
            pids = result.stdout.strip().split("\n")
            return int(pids[0])
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    # Fallback: try ss (Linux)
    try:
        result = subprocess.run(
            ["ss", "-tlnp", f"sport = :{port}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # Parse ss output for PID
            for line in result.stdout.split("\n"):
                if f":{port}" in line and "pid=" in line:
                    import re
                    match = re.search(r"pid=(\d+)", line)
                    if match:
                        return int(match.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass

    return None


def _is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID. Returns True if successful."""
    import signal
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
        # Wait a bit for the process to terminate
        import time
        for _ in range(10):
            time.sleep(0.1)
            if not _is_process_running(pid):
                return True
        # If still running after SIGTERM, try SIGKILL
        if not force:
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            return not _is_process_running(pid)
        return False
    except (OSError, ProcessLookupError):
        return True  # Process already gone


def _read_pid_file() -> int | None:
    """Read PID from the PID file if it exists."""
    pid_file = _get_gui_pid_file()
    if not pid_file.exists():
        return None
    try:
        content = pid_file.read_text().strip()
        return int(content) if content else None
    except (ValueError, OSError):
        return None


def _write_pid_file(pid: int) -> None:
    """Write PID to the PID file."""
    pid_file = _get_gui_pid_file()
    pid_file.write_text(str(pid))


def _remove_pid_file() -> None:
    """Remove the PID file if it exists."""
    pid_file = _get_gui_pid_file()
    if pid_file.exists():
        pid_file.unlink()


def _get_process_start_time(pid: int) -> str | None:
    """Get the start time of a process (POSIX-portable)."""
    try:
        # Works on macOS and Linux
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def gui_status(
    ctx: Ctx,
    *,
    dry_run: bool,
    port: int = GUI_DEFAULT_PORT,
) -> int:
    """Check the status of the GUI server.

    Returns:
        0 if running, 1 if not running
    """
    _ = ctx  # Unused but kept for consistency

    if dry_run:
        _eprint(f"[dry-run] Would check GUI status on port {port}")
        return 0

    pid_from_file = _read_pid_file()
    pid_on_port = _get_pid_on_port(port)
    port_in_use = _is_port_in_use(port)

    # Determine actual status
    if pid_from_file and _is_process_running(pid_from_file):
        start_time = _get_process_start_time(pid_from_file)
        _eprint(f"GUI server is RUNNING")
        _eprint(f"  PID: {pid_from_file}")
        _eprint(f"  Port: {port}")
        if start_time:
            _eprint(f"  Started: {start_time}")
        _eprint(f"  PID file: {_get_gui_pid_file()}")
        return 0
    elif port_in_use and pid_on_port:
        # Port is in use but not by our tracked process
        start_time = _get_process_start_time(pid_on_port)
        _eprint(f"GUI server is RUNNING (untracked)")
        _eprint(f"  PID: {pid_on_port}")
        _eprint(f"  Port: {port}")
        if start_time:
            _eprint(f"  Started: {start_time}")
        _eprint(f"  Note: Process not started via 'marvain gui start'")
        # Clean up stale PID file if it exists
        if pid_from_file:
            _remove_pid_file()
        return 0
    elif port_in_use:
        _eprint(f"Port {port} is in use by an unknown process")
        _eprint(f"  Run: lsof -ti:{port} | xargs kill -9")
        return 1
    else:
        _eprint(f"GUI server is STOPPED")
        _eprint(f"  Port: {port}")
        # Clean up stale PID file
        if pid_from_file:
            _remove_pid_file()
        return 1


def gui_stop(
    ctx: Ctx,
    *,
    dry_run: bool,
    port: int = GUI_DEFAULT_PORT,
    force: bool = False,
) -> int:
    """Stop the GUI server.

    Args:
        port: Port the GUI is running on
        force: Use SIGKILL instead of SIGTERM
    """
    _ = ctx  # Unused but kept for consistency

    if dry_run:
        _eprint(f"[dry-run] Would stop GUI server on port {port}")
        return 0

    # First try PID from file
    pid_from_file = _read_pid_file()
    if pid_from_file and _is_process_running(pid_from_file):
        _eprint(f"Stopping GUI server (PID {pid_from_file})...")
        if _kill_process(pid_from_file, force=force):
            _remove_pid_file()
            _eprint("GUI server stopped.")
            return 0
        else:
            _eprint(f"ERROR: Failed to stop process {pid_from_file}")
            return 1

    # Fallback: find process on port
    pid_on_port = _get_pid_on_port(port)
    if pid_on_port:
        _eprint(f"Stopping process on port {port} (PID {pid_on_port})...")
        if _kill_process(pid_on_port, force=force):
            _remove_pid_file()
            _eprint("GUI server stopped.")
            return 0
        else:
            _eprint(f"ERROR: Failed to stop process {pid_on_port}")
            return 1

    # Check if port is in use but we can't find the PID
    if _is_port_in_use(port):
        _eprint(f"Port {port} is in use but cannot determine PID.")
        _eprint(f"Try: lsof -ti:{port} | xargs kill -9")
        return 1

    _eprint("GUI server is not running.")
    _remove_pid_file()
    return 0


def _get_mkcert_certs_dir() -> Path:
    """Get the directory for mkcert-generated certificates."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(xdg_config) / "marvain" / "certs"


def _ensure_mkcert_certs(dry_run: bool = False) -> tuple[Path, Path] | None:
    """Ensure mkcert certificates exist, generating them if needed.

    Returns:
        Tuple of (cert_path, key_path) if successful, None if mkcert not available.
    """
    certs_dir = _get_mkcert_certs_dir()
    cert_path = certs_dir / "localhost.pem"
    key_path = certs_dir / "localhost-key.pem"

    # Check if certs already exist
    if cert_path.exists() and key_path.exists():
        _eprint(f"Using existing mkcert certificates from {certs_dir}")
        return cert_path, key_path

    # Check if mkcert is available
    mkcert_path = shutil.which("mkcert")
    if not mkcert_path:
        _eprint("WARNING: mkcert not found. Install with: brew install mkcert")
        _eprint("         Falling back to HTTP mode.")
        return None

    # Create certs directory
    if not dry_run:
        certs_dir.mkdir(parents=True, exist_ok=True)

    # Generate certificates with mkcert
    _eprint(f"Generating mkcert certificates in {certs_dir}...")
    cmd = [
        mkcert_path,
        "-cert-file", str(cert_path),
        "-key-file", str(key_path),
        "localhost", "127.0.0.1", "::1",
    ]
    _eprint(f"$ {' '.join(cmd)}")

    if dry_run:
        return cert_path, key_path

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            _eprint(f"ERROR: mkcert failed: {result.stderr}")
            _eprint("Falling back to HTTP mode.")
            return None
        _eprint("Certificates generated successfully.")
        return cert_path, key_path
    except Exception as e:
        _eprint(f"ERROR: Failed to run mkcert: {e}")
        _eprint("Falling back to HTTP mode.")
        return None


def gui_start(
    ctx: Ctx,
    *,
    dry_run: bool,
    host: str = GUI_DEFAULT_HOST,
    port: int = GUI_DEFAULT_PORT,
    reload: bool = True,
    foreground: bool = False,
    https: bool = True,
    cert: str | None = None,
    key: str | None = None,
) -> int:
    """Start the GUI server.

    The GUI runs locally (developer laptop or EC2) and connects to deployed
    AWS resources (Aurora Data API, Cognito, S3, SQS) via environment variables.

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 8084)
        reload: Enable auto-reload on code changes
        foreground: Run in foreground (blocking) instead of background
        https: Enable HTTPS (default: True). Use --no-https to disable.
        cert: Path to SSL certificate file (PEM format). Auto-generated with mkcert if not provided.
        key: Path to SSL private key file (PEM format). Auto-generated with mkcert if not provided.
    """
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    repo_root = Path(__file__).parent.parent
    hub_api_dir = repo_root / "functions" / "hub_api"
    shared_layer = repo_root / "layers" / "shared" / "python"

    # Get resources from marvain-config.yaml
    resources = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("resources", {})
    if not resources:
        _eprint(f"ERROR: No resources found in config for env '{ctx.env.env}'")
        _eprint("Run 'marvain monitor outputs --write-config' to populate resources.")
        return 2

    # SSL certificate handling for HTTPS
    cert_path: Path | None = None
    key_path: Path | None = None
    if https:
        if cert and key:
            # User provided explicit cert/key paths
            cert_path = Path(cert).resolve()
            key_path = Path(key).resolve()
            if not cert_path.exists():
                _eprint(f"ERROR: Certificate file not found: {cert}")
                return 1
            if not key_path.exists():
                _eprint(f"ERROR: Key file not found: {key}")
                return 1
        else:
            # Auto-generate with mkcert
            mkcert_result = _ensure_mkcert_certs(dry_run=dry_run)
            if mkcert_result:
                cert_path, key_path = mkcert_result
            else:
                # mkcert not available, fall back to HTTP
                _eprint("Continuing with HTTP (use --no-https to suppress this warning)")
                https = False

    # Check if port is already in use
    if _is_port_in_use(port, host):
        pid_on_port = _get_pid_on_port(port)
        if pid_on_port:
            _eprint(f"ERROR: Port {port} is already in use by PID {pid_on_port}")
        else:
            _eprint(f"ERROR: Port {port} is already in use")
        _eprint("")
        _eprint("Options:")
        _eprint(f"  1. Stop the existing server: marvain gui stop --port {port}")
        _eprint(f"  2. Restart the server: marvain gui restart --port {port}")
        _eprint(f"  3. Use a different port: marvain gui start --port {port + 1}")
        return 1

    cmd = ["uvicorn", "app:app", "--host", host, "--port", str(port)]
    if reload:
        cmd.append("--reload")

    # Add SSL flags if using HTTPS
    if https and cert_path and key_path:
        cmd.extend(["--ssl-keyfile", str(key_path)])
        cmd.extend(["--ssl-certfile", str(cert_path)])

    scheme = "https" if https else "http"
    redirect_uri = f"{scheme}://localhost:{port}/auth/callback"

    _eprint(f"Starting local GUI server at {scheme}://{host}:{port}")
    _eprint(f"Using config: {ctx.config_path} (env: {ctx.env.env})")
    if https and cert_path and key_path:
        _eprint(f"SSL Certificate: {cert_path}")
        _eprint(f"SSL Key: {key_path}")

    if dry_run:
        _eprint(f"[dry-run] $ cd {hub_api_dir} && {' '.join(cmd)}")
        return 0

    # Build environment from marvain-config.yaml resources
    env = os.environ.copy()

    # Map config resource keys to environment variable names
    resource_to_env = {
        "DbClusterArn": "DB_RESOURCE_ARN",
        "DbSecretArn": "DB_SECRET_ARN",
        "DbName": "DB_NAME",
        "CognitoUserPoolId": "COGNITO_USER_POOL_ID",
        "CognitoAppClientId": "COGNITO_APP_CLIENT_ID",
        "CognitoDomain": "COGNITO_DOMAIN",
        "AdminApiKeySecretArn": "ADMIN_SECRET_ARN",
        "OpenAISecretArn": "OPENAI_SECRET_ARN",
        "LiveKitSecretArn": "LIVEKIT_SECRET_ARN",
        "LiveKitUrl": "LIVEKIT_URL",
        "HubWebSocketUrl": "WS_API_URL",
        "AuditBucketName": "AUDIT_BUCKET",
        "ArtifactBucketName": "ARTIFACT_BUCKET",
        "SessionSecretArn": "SESSION_SECRET_ARN",
    }

    for res_key, env_key in resource_to_env.items():
        if res_key in resources and resources[res_key]:
            env[env_key] = str(resources[res_key])

    # Fallback: read LiveKitUrl from sam.parameter_overrides if not in resources
    # (This can be removed once the stack is redeployed with the LiveKitUrl output)
    if "LIVEKIT_URL" not in env:
        sam_params = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("sam", {}).get("parameter_overrides", {})
        lk_url = sam_params.get("LiveKitUrl", "")
        if lk_url:
            env["LIVEKIT_URL"] = str(lk_url)
            _eprint(f"NOTE: Using LiveKitUrl from sam.parameter_overrides (redeploy stack for proper output)")

    # Set Cognito redirect URI dynamically based on http/https
    env["COGNITO_REDIRECT_URI"] = redirect_uri
    env["COGNITO_REGION"] = ctx.env.aws_region

    # Set AWS credentials from config
    env["AWS_PROFILE"] = ctx.env.aws_profile
    env["AWS_REGION"] = ctx.env.aws_region
    env["AWS_DEFAULT_REGION"] = ctx.env.aws_region

    # Local development settings
    env["ENVIRONMENT"] = "local"
    env["LOG_LEVEL"] = env.get("LOG_LEVEL", "DEBUG")
    # Tell the app whether HTTPS is enabled (for SameSite cookie settings)
    env["HTTPS_ENABLED"] = "true" if https else "false"
    # For local dev, use a static session secret (Lambda uses SESSION_SECRET_ARN)
    if "SESSION_SECRET_KEY" not in env:
        env["SESSION_SECRET_KEY"] = "local-dev-session-secret-key-change-in-production-123456"

    # Set PYTHONPATH to include shared layer for agent_hub imports
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = f"{shared_layer}:{existing_pythonpath}"
    else:
        env["PYTHONPATH"] = str(shared_layer)

    if foreground:
        # Run in foreground (blocking)
        _eprint(f"$ cd {hub_api_dir} && {' '.join(cmd)}")
        _eprint("Press Ctrl+C to stop.")
        return subprocess.call(cmd, cwd=str(hub_api_dir), env=env)
    else:
        # Run in background with output to log file
        log_file = _get_gui_log_file()
        _eprint(f"Logs: {log_file}")
        _eprint(f"$ cd {hub_api_dir} && {' '.join(cmd)} > {log_file} 2>&1 &")

        with open(log_file, "w") as lf:
            proc = subprocess.Popen(
                cmd,
                cwd=str(hub_api_dir),
                env=env,
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # Detach from terminal
            )

        # Write PID file
        _write_pid_file(proc.pid)
        _eprint(f"GUI server started (PID {proc.pid})")
        _eprint(f"  URL: {scheme}://{host}:{port}")
        _eprint(f"  Logs: tail -f {log_file}")
        _eprint(f"  Stop: marvain gui stop")
        return 0


def gui_restart(
    ctx: Ctx,
    *,
    dry_run: bool,
    host: str = GUI_DEFAULT_HOST,
    port: int = GUI_DEFAULT_PORT,
    reload: bool = True,
    foreground: bool = False,
    https: bool = False,
    cert: str | None = None,
    key: str | None = None,
) -> int:
    """Restart the GUI server (stop then start)."""
    if dry_run:
        _eprint(f"[dry-run] Would restart GUI server on port {port}")
        return 0

    # Stop first (ignore errors if not running)
    _eprint("Stopping existing GUI server...")
    gui_stop(ctx, dry_run=False, port=port, force=False)

    # Wait a moment for port to be released
    import time
    for _ in range(10):
        if not _is_port_in_use(port, host):
            break
        time.sleep(0.2)

    # Start
    _eprint("")
    return gui_start(
        ctx,
        dry_run=False,
        host=host,
        port=port,
        reload=reload,
        foreground=foreground,
        https=https,
        cert=cert,
        key=key,
    )


def gui_logs(
    ctx: Ctx,
    *,
    dry_run: bool,
    follow: bool = False,
    lines: int = 50,
) -> int:
    """Show GUI server logs.

    Args:
        follow: Follow log output (like tail -f)
        lines: Number of lines to show (default: 50)
    """
    _ = ctx  # Unused but kept for consistency

    log_file = _get_gui_log_file()

    if dry_run:
        if follow:
            _eprint(f"[dry-run] Would run: tail -f {log_file}")
        else:
            _eprint(f"[dry-run] Would run: tail -n {lines} {log_file}")
        return 0

    if not log_file.exists():
        _eprint(f"No log file found at {log_file}")
        _eprint("The GUI server may not have been started with 'marvain gui start'.")
        return 1

    if follow:
        _eprint(f"Following logs from {log_file} (Ctrl+C to stop)...")
        cmd = ["tail", "-f", str(log_file)]
    else:
        cmd = ["tail", "-n", str(lines), str(log_file)]

    return subprocess.call(cmd)


# -----------------------------------------------------------------------------
# Agent Worker Management
# -----------------------------------------------------------------------------

AGENT_DEFAULT_PORT = 8089  # LiveKit agents default health port

def _get_agent_pid_file() -> Path:
    return Path.cwd() / ".marvain-agent.pid"


def _get_agent_log_file() -> Path:
    return Path.cwd() / ".marvain-agent.log"


def _fetch_secret_json(secret_arn: str, profile: str, region: str) -> dict[str, Any]:
    """Fetch a secret from AWS Secrets Manager."""
    import boto3
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("secretsmanager")
    resp = client.get_secret_value(SecretId=secret_arn)
    import json as json_mod
    return json_mod.loads(resp.get("SecretString", "{}"))


def agent_start(
    ctx: Ctx,
    *,
    dry_run: bool,
    foreground: bool = False,
) -> int:
    """Start the agent worker.

    The agent worker connects to LiveKit Cloud and handles voice sessions.
    Credentials are loaded from AWS Secrets Manager using ARNs in marvain-config.yaml.
    """
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    repo_root = Path(__file__).parent.parent
    agent_worker_dir = repo_root / "apps" / "agent_worker"

    if not agent_worker_dir.exists():
        _eprint(f"ERROR: Agent worker directory not found: {agent_worker_dir}")
        return 1

    # Get resources from marvain-config.yaml
    resources = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("resources", {})
    sam_params = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("sam", {}).get("parameter_overrides", {})

    # Get LiveKit URL
    livekit_url = resources.get("LiveKitUrl") or sam_params.get("LiveKitUrl")
    if not livekit_url:
        _eprint("ERROR: LiveKitUrl not found in config resources or sam.parameter_overrides")
        _eprint("Run 'marvain monitor outputs --write-config' to populate resources.")
        return 2

    # Get secret ARNs
    livekit_secret_arn = resources.get("LiveKitSecretArn")
    openai_secret_arn = resources.get("OpenAISecretArn")

    if not livekit_secret_arn:
        _eprint("ERROR: LiveKitSecretArn not found in config resources")
        _eprint("Run 'marvain monitor outputs --write-config' to populate resources.")
        return 2

    if not openai_secret_arn:
        _eprint("ERROR: OpenAISecretArn not found in config resources")
        _eprint("Run 'marvain monitor outputs --write-config' to populate resources.")
        return 2

    _eprint(f"Loading credentials from AWS Secrets Manager...")

    if dry_run:
        _eprint(f"[dry-run] Would fetch LiveKit secret from: {livekit_secret_arn}")
        _eprint(f"[dry-run] Would fetch OpenAI secret from: {openai_secret_arn}")
        _eprint(f"[dry-run] Would start agent worker in {agent_worker_dir}")
        return 0

    # Fetch secrets
    try:
        livekit_secret = _fetch_secret_json(livekit_secret_arn, ctx.env.aws_profile, ctx.env.aws_region)
        livekit_api_key = livekit_secret.get("api_key", "")
        livekit_api_secret = livekit_secret.get("api_secret", "")
        if not livekit_api_key or not livekit_api_secret:
            _eprint("ERROR: LiveKit secret missing api_key or api_secret")
            return 3
    except Exception as e:
        _eprint(f"ERROR: Failed to fetch LiveKit secret: {e}")
        return 3

    try:
        openai_secret = _fetch_secret_json(openai_secret_arn, ctx.env.aws_profile, ctx.env.aws_region)
        openai_api_key = openai_secret.get("api_key", "")
        if not openai_api_key or openai_api_key == "REPLACE_ME":
            _eprint("ERROR: OpenAI secret missing api_key or has placeholder value")
            return 3
    except Exception as e:
        _eprint(f"ERROR: Failed to fetch OpenAI secret: {e}")
        return 3

    _eprint(f"  LiveKit URL: {livekit_url}")
    _eprint(f"  LiveKit API Key: {livekit_api_key[:8]}...")
    _eprint(f"  OpenAI API Key: {openai_api_key[:12]}...")

    # Build command
    cmd = ["python", "worker.py", "dev"]

    # Build environment
    env = os.environ.copy()
    env["LIVEKIT_URL"] = livekit_url
    env["LIVEKIT_API_KEY"] = livekit_api_key
    env["LIVEKIT_API_SECRET"] = livekit_api_secret
    env["OPENAI_API_KEY"] = openai_api_key
    env["AWS_PROFILE"] = ctx.env.aws_profile
    env["AWS_REGION"] = ctx.env.aws_region
    env["AWS_DEFAULT_REGION"] = ctx.env.aws_region

    # Optional: Hub API base for transcript ingestion
    hub_api_base = resources.get("HubRestApiBase")
    if hub_api_base:
        env["HUB_API_BASE"] = hub_api_base

    # Optional: Device token for Hub auth
    bootstrap = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("bootstrap", {})
    device_token = bootstrap.get("device_token")
    space_id = bootstrap.get("space_id")
    if device_token:
        env["HUB_DEVICE_TOKEN"] = device_token
    if space_id:
        env["SPACE_ID"] = space_id

    _eprint(f"Starting agent worker...")
    _eprint(f"Using config: {ctx.config_path} (env: {ctx.env.env})")

    if foreground:
        _eprint(f"$ cd {agent_worker_dir} && {' '.join(cmd)}")
        _eprint("Press Ctrl+C to stop.")
        return subprocess.call(cmd, cwd=str(agent_worker_dir), env=env)
    else:
        # Run in background
        log_file = _get_agent_log_file()
        _eprint(f"Logs: {log_file}")
        _eprint(f"$ cd {agent_worker_dir} && {' '.join(cmd)} > {log_file} 2>&1 &")

        with open(log_file, "w") as lf:
            # Use DEVNULL for stdin to prevent "Bad file descriptor" errors
            # when LiveKit agents framework spawns subprocesses for jobs.
            # The framework expects valid file descriptors for stdin/stdout/stderr.
            proc = subprocess.Popen(
                cmd,
                cwd=str(agent_worker_dir),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        # Write PID file
        pid_file = _get_agent_pid_file()
        pid_file.write_text(str(proc.pid))

        _eprint(f"Agent worker started (PID {proc.pid})")
        _eprint(f"  Logs: tail -f {log_file}")
        _eprint(f"  Stop: marvain agent stop")
        return 0


def agent_stop(
    ctx: Ctx,
    *,
    dry_run: bool,
    force: bool = False,
) -> int:
    """Stop the agent worker."""
    _ = ctx  # Unused but kept for consistency

    if dry_run:
        _eprint("[dry-run] Would stop agent worker")
        return 0

    pid_file = _get_agent_pid_file()
    if not pid_file.exists():
        _eprint("Agent worker is not running (no PID file found).")
        return 0

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        _eprint("Invalid PID file. Removing.")
        pid_file.unlink(missing_ok=True)
        return 0

    if not _is_process_running(pid):
        _eprint("Agent worker is not running (stale PID file).")
        pid_file.unlink(missing_ok=True)
        return 0

    _eprint(f"Stopping agent worker (PID {pid})...")
    if _kill_process(pid, force=force):
        pid_file.unlink(missing_ok=True)
        _eprint("Agent worker stopped.")
        return 0
    else:
        _eprint(f"ERROR: Failed to stop process {pid}")
        return 1


def agent_status(
    ctx: Ctx,
    *,
    dry_run: bool,
) -> int:
    """Check the status of the agent worker."""
    _ = ctx  # Unused but kept for consistency

    if dry_run:
        _eprint("[dry-run] Would check agent worker status")
        return 0

    pid_file = _get_agent_pid_file()
    if not pid_file.exists():
        _eprint("Agent worker is STOPPED (no PID file)")
        return 1

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        _eprint("Agent worker is STOPPED (invalid PID file)")
        pid_file.unlink(missing_ok=True)
        return 1

    if _is_process_running(pid):
        start_time = _get_process_start_time(pid)
        _eprint("Agent worker is RUNNING")
        _eprint(f"  PID: {pid}")
        if start_time:
            _eprint(f"  Started: {start_time}")
        _eprint(f"  PID file: {pid_file}")
        _eprint(f"  Logs: {_get_agent_log_file()}")
        return 0
    else:
        _eprint("Agent worker is STOPPED (stale PID file)")
        pid_file.unlink(missing_ok=True)
        return 1


def agent_restart(
    ctx: Ctx,
    *,
    dry_run: bool,
    foreground: bool = False,
) -> int:
    """Restart the agent worker (stop then start)."""
    if dry_run:
        _eprint("[dry-run] Would restart agent worker")
        return 0

    _eprint("Stopping existing agent worker...")
    agent_stop(ctx, dry_run=False, force=False)

    import time
    time.sleep(1)

    _eprint("")
    return agent_start(ctx, dry_run=False, foreground=foreground)


def agent_rebuild(
    ctx: Ctx,
    *,
    dry_run: bool,
    foreground: bool = False,
) -> int:
    """Nuclear reset: stop agent, clear all LiveKit rooms, restart agent.

    This is a debugging command that:
    1. Stops the agent worker
    2. Clears all LiveKit rooms (to reset any stuck agent sessions)
    3. Waits for LiveKit Cloud to propagate the deletions
    4. Restarts the agent worker with a clean state

    Use this when agent dispatch is failing, potentially due to hitting
    the 5 concurrent agent session limit on the free LiveKit Build plan.
    """
    if dry_run:
        _eprint("[dry-run] Would rebuild agent worker:")
        _eprint("[dry-run]   1. Stop agent worker")
        _eprint("[dry-run]   2. Clear all LiveKit rooms")
        _eprint("[dry-run]   3. Wait for propagation")
        _eprint("[dry-run]   4. Start agent worker")
        return 0

    _eprint("🔄 Rebuilding agent worker (nuclear reset)...")
    _eprint("")

    # Step 1: Stop the agent worker
    _eprint("1️⃣ Stopping agent worker...")
    agent_stop(ctx, dry_run=False, force=False)
    _eprint("")

    # Step 2: Clear all LiveKit rooms
    _eprint("2️⃣ Clearing all LiveKit rooms...")
    try:
        import subprocess
        import sys
        from pathlib import Path

        # Run the clear_livekit_rooms.py script
        script_path = Path.cwd() / "clear_livekit_rooms.py"
        if not script_path.exists():
            _eprint("⚠️  clear_livekit_rooms.py not found, skipping room clearing")
        else:
            result = subprocess.run([
                sys.executable, str(script_path)
            ], capture_output=True, text=True)

            if result.returncode == 0:
                _eprint("✅ LiveKit rooms cleared successfully")
                if result.stdout.strip():
                    _eprint(f"   Output: {result.stdout.strip()}")
            else:
                _eprint(f"⚠️  Room clearing failed (exit code {result.returncode})")
                if result.stderr.strip():
                    _eprint(f"   Error: {result.stderr.strip()}")
    except Exception as e:
        _eprint(f"⚠️  Error clearing rooms: {e}")

    _eprint("")

    # Step 3: Wait for propagation
    _eprint("3️⃣ Waiting for LiveKit Cloud propagation...")
    import time
    time.sleep(3)  # Give LiveKit Cloud time to propagate room deletions
    _eprint("")

    # Step 4: Start the agent worker
    _eprint("4️⃣ Starting agent worker...")
    result = agent_start(ctx, dry_run=False, foreground=foreground)

    if result == 0:
        _eprint("")
        _eprint("🎉 Agent worker rebuild complete!")
        _eprint("   The agent should now be in a clean state for testing.")
    else:
        _eprint("")
        _eprint("❌ Agent worker failed to start after rebuild")

    return result


def agent_logs(
    ctx: Ctx,
    *,
    dry_run: bool,
    follow: bool = False,
    lines: int = 50,
) -> int:
    """Show agent worker logs."""
    _ = ctx  # Unused but kept for consistency

    log_file = _get_agent_log_file()

    if dry_run:
        if follow:
            _eprint(f"[dry-run] Would run: tail -f {log_file}")
        else:
            _eprint(f"[dry-run] Would run: tail -n {lines} {log_file}")
        return 0

    if not log_file.exists():
        _eprint(f"No log file found at {log_file}")
        _eprint("The agent worker may not have been started with 'marvain agent start'.")
        return 1

    if follow:
        _eprint(f"Following logs from {log_file} (Ctrl+C to stop)...")
        cmd = ["tail", "-f", str(log_file)]
    else:
        cmd = ["tail", "-n", str(lines), str(log_file)]

    return subprocess.call(cmd)


def _split_sql(sql_text: str) -> list[str]:
    # Same basic behavior as scripts/db_init.py: good enough for our schema file.
    stmts: list[str] = []
    buf: list[str] = []
    for line in sql_text.splitlines():
        if line.strip().startswith("--"):
            continue
        buf.append(line)
        if ";" in line:
            joined = "\n".join(buf)
            parts = joined.split(";")
            for p in parts[:-1]:
                s = p.strip()
                if s:
                    stmts.append(s)
            buf = [parts[-1]]
    tail = "\n".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


def _db_outputs(ctx: Ctx, *, dry_run: bool) -> tuple[str, str, str]:
    outs = aws_stack_outputs(ctx, dry_run=dry_run)
    try:
        return outs["DbClusterArn"], outs["DbSecretArn"], outs["DbName"]
    except KeyError as e:
        raise ConfigError(f"Missing required stack output: {e}. Did you deploy the stack?")


def init_db(ctx: Ctx, *, dry_run: bool, sql_file: str | None) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    def _list_sql_migrations() -> list[Path]:
        # Apply all migrations in lexical order (001_..., 002_..., ...).
        # Keep simple: all *.sql files in sql/.
        paths = [p for p in Path("sql").glob("*.sql") if p.is_file()]
        paths.sort(key=lambda p: p.name)
        return paths

    paths = [Path(sql_file)] if sql_file else _list_sql_migrations()
    if not paths:
        raise ConfigError("No SQL migrations found under sql/")

    stmt_sets: list[tuple[Path, list[str]]] = []
    for path in paths:
        sql_text = path.read_text(encoding="utf-8")
        stmt_sets.append((path, _split_sql(sql_text)))

    if dry_run:
        _eprint(f"[dry-run] Would resolve DbClusterArn/DbSecretArn/DbName from stack outputs for {ctx.env.stack_name}")
        for path, stmts in stmt_sets:
            _eprint(f"[dry-run] Would apply {len(stmts)} SQL statements from {path}")
        return 0

    resource_arn, secret_arn, db_name = _db_outputs(ctx, dry_run=dry_run)

    for path, stmts in stmt_sets:
        _eprint(f"Applying {len(stmts)} SQL statements from {path}")
        for s in stmts:
            cmd = [
                "aws",
                "rds-data",
                "execute-statement",
                *aws_cli_args(ctx.env),
                "--resource-arn",
                resource_arn,
                "--secret-arn",
                secret_arn,
                "--database",
                db_name,
                "--sql",
                s,
                "--output",
                "json",
            ]
            run_cmd(cmd, env=cmd_env(ctx.env), dry_run=dry_run)
    return 0


def _rds_execute(
    ctx: Ctx,
    *,
    resource_arn: str,
    secret_arn: str,
    db_name: str,
    sql: str,
    parameters: list[dict[str, Any]] | None,
    dry_run: bool,
) -> Any:
    cmd: list[str] = [
        "aws",
        "rds-data",
        "execute-statement",
        *aws_cli_args(ctx.env),
        "--resource-arn",
        resource_arn,
        "--secret-arn",
        secret_arn,
        "--database",
        db_name,
        "--sql",
        sql,
        "--include-result-metadata",
        "--output",
        "json",
    ]
    if parameters:
        cmd.extend(["--parameters", json.dumps(parameters)])
    return run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)


def _first_cell_as_string(result: Any) -> str:
    recs = (result or {}).get("records") or []
    if not recs or not recs[0]:
        raise ConfigError("Expected a RETURNING value but got none")
    cell = recs[0][0]
    if not isinstance(cell, dict):
        raise ConfigError("Unexpected RDS Data API cell")
    # uuid tends to come back as stringValue
    for k in ("stringValue", "longValue", "doubleValue"):
        if k in cell:
            return str(cell[k])
    raise ConfigError("Unexpected RDS Data API cell value")


def bootstrap(
    ctx: Ctx,
    *,
    dry_run: bool,
    agent_name: str | None,
    space_name: str,
    device_name: str | None,
    force: bool,
) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    if dry_run:
        _eprint(f"[dry-run] Would resolve DB outputs for stack: {ctx.env.stack_name}")
        _eprint("[dry-run] Would create: agent, default space, and device; would update config bootstrap block")
        return 0

    resource_arn, secret_arn, db_name = _db_outputs(ctx, dry_run=dry_run)

    envs = ctx.cfg.get("envs")
    if not isinstance(envs, dict):
        raise ConfigError("config.envs must be a mapping")
    env_cfg = envs.get(ctx.env.env)
    if not isinstance(env_cfg, dict):
        raise ConfigError("env config must be a mapping")
    boot = env_cfg.get("bootstrap")
    if isinstance(boot, dict) and boot.get("agent_id") and not force:
        raise ConfigError("bootstrap already present in config; re-run with --force to overwrite")

    a_name = agent_name or f"{ctx.env.stack_name}"
    d_name = device_name or socket.gethostname()
    token = secrets.token_hex(32)
    import hashlib

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    agent_res = _rds_execute(
        ctx,
        resource_arn=resource_arn,
        secret_arn=secret_arn,
        db_name=db_name,
        sql="INSERT INTO agents (name) VALUES (:n) RETURNING agent_id",
        parameters=[{"name": "n", "value": {"stringValue": a_name}}],
        dry_run=dry_run,
    )
    agent_id = _first_cell_as_string(agent_res)

    space_res = _rds_execute(
        ctx,
        resource_arn=resource_arn,
        secret_arn=secret_arn,
        db_name=db_name,
        # RDS Data API binds :a as text; cast to uuid for Postgres.
        sql="INSERT INTO spaces (agent_id, name) VALUES (CAST(:a AS uuid), :n) RETURNING space_id",
        parameters=[
            {"name": "a", "value": {"stringValue": agent_id}},
            {"name": "n", "value": {"stringValue": space_name}},
        ],
        dry_run=dry_run,
    )
    space_id = _first_cell_as_string(space_res)

    dev_res = _rds_execute(
        ctx,
        resource_arn=resource_arn,
        secret_arn=secret_arn,
        db_name=db_name,
        # RDS Data API binds :a as text; cast to uuid for Postgres.
        sql="INSERT INTO devices (agent_id, name, token_hash) VALUES (CAST(:a AS uuid), :n, :h) RETURNING device_id",
        parameters=[
            {"name": "a", "value": {"stringValue": agent_id}},
            {"name": "n", "value": {"stringValue": d_name}},
            {"name": "h", "value": {"stringValue": token_hash}},
        ],
        dry_run=dry_run,
    )
    device_id = _first_cell_as_string(dev_res)

    print(json.dumps({"agent_id": agent_id, "space_id": space_id, "device_id": device_id, "device_name": d_name, "device_token": token}, indent=2, sort_keys=True))

    if not dry_run:
        env_cfg["bootstrap"] = {
            "agent_id": agent_id,
            "space_id": space_id,
            "device_id": device_id,
            "device_name": d_name,
            "device_token": token,
        }
        save_config_dict(ctx.config_path, ctx.cfg)
        _eprint(f"Updated config bootstrap block: {ctx.config_path}")

    return 0


# ------------------------------------------------------------------------------
# Cognito Admin User Management
# ------------------------------------------------------------------------------


def _get_cognito_client(ctx: Ctx):
    """Get a boto3 cognito-idp client."""
    import boto3

    session = boto3.Session(
        profile_name=ctx.env.aws_profile,
        region_name=ctx.env.aws_region,
    )
    return session.client("cognito-idp")


def _get_user_pool_id(ctx: Ctx) -> str:
    """Get the Cognito User Pool ID from stack resources/outputs.

    First checks config.envs[env].resources (populated by `marvain monitor outputs --write-config`).
    Falls back to live describe-stacks if not in config.
    """
    resources = ctx.cfg.get("envs", {}).get(ctx.env.env, {}).get("resources", {})
    pool_id = resources.get("CognitoUserPoolId")
    if pool_id:
        return pool_id

    # Fallback: fetch from live stack
    outs = aws_stack_outputs(ctx, dry_run=False)
    pool_id = outs.get("CognitoUserPoolId")
    if not pool_id:
        raise ConfigError(
            f"CognitoUserPoolId not found in outputs for env '{ctx.env.env}'. "
            "Run 'marvain monitor outputs --write-config' to update config."
        )
    return pool_id


# Backwards-compatible wrappers used by unit tests / older CLI naming.
def cognito_admin_create_user(ctx: Ctx, *, email: str, dry_run: bool = False) -> dict[str, Any]:
    """Create a Cognito user (admin-create-user).

    This wrapper retains the older function name expected by tests.
    """

    pool_id = _get_user_pool_id(ctx)
    _eprint(
        "aws cognito-idp admin-create-user "
        f"--user-pool-id {pool_id} "
        f"--username {email}"
    )
    if dry_run:
        return {}

    # Default: suppress invite; user can be confirmed via set-password.
    cognito_create_user(ctx, email=email, temporary_password=None, suppress_invite=True, dry_run=False)
    return {}


def cognito_admin_delete_user(ctx: Ctx, *, email: str, dry_run: bool = False) -> int:
    """Delete a Cognito user (admin-delete-user).

    This wrapper retains the older function name expected by tests.
    """

    pool_id = _get_user_pool_id(ctx)
    _eprint(
        "aws cognito-idp admin-delete-user "
        f"--user-pool-id {pool_id} "
        f"--username {email}"
    )
    if dry_run:
        return 0

    cognito_delete_user(ctx, email=email, dry_run=False)
    return 0


def cognito_create_user(
    ctx: Ctx,
    *,
    email: str,
    temporary_password: str | None = None,
    suppress_invite: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create a new Cognito user with the given email."""
    pool_id = _get_user_pool_id(ctx)

    params: dict[str, Any] = {
        "UserPoolId": pool_id,
        "Username": email,
        "UserAttributes": [
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
    }
    if suppress_invite:
        params["MessageAction"] = "SUPPRESS"
    if temporary_password:
        params["TemporaryPassword"] = temporary_password

    _eprint(f"Creating Cognito user: {email} in pool {pool_id}")
    if dry_run:
        _eprint(f"[DRY RUN] cognito-idp.admin_create_user({params})")
        return {"Username": email, "dry_run": True}

    client = _get_cognito_client(ctx)
    response = client.admin_create_user(**params)
    return response.get("User", {})


def cognito_set_password(
    ctx: Ctx,
    *,
    email: str,
    password: str,
    permanent: bool = True,
    dry_run: bool = False,
) -> None:
    """Set a user's password (make it permanent by default)."""
    pool_id = _get_user_pool_id(ctx)

    _eprint(f"Setting password for user: {email}")
    if dry_run:
        _eprint(f"[DRY RUN] cognito-idp.admin_set_user_password(UserPoolId={pool_id}, Username={email}, Permanent={permanent})")
        return

    client = _get_cognito_client(ctx)
    client.admin_set_user_password(
        UserPoolId=pool_id,
        Username=email,
        Password=password,
        Permanent=permanent,
    )
    _eprint("Password set successfully")


def cognito_list_users(
    ctx: Ctx,
    *,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """List all users in the Cognito User Pool."""
    pool_id = _get_user_pool_id(ctx)

    _eprint(f"Listing users in pool: {pool_id}")
    if dry_run:
        _eprint(f"[DRY RUN] cognito-idp.list_users(UserPoolId={pool_id})")
        return []

    client = _get_cognito_client(ctx)
    users = []
    paginator = client.get_paginator("list_users")
    for page in paginator.paginate(UserPoolId=pool_id):
        users.extend(page.get("Users", []))
    return users


def cognito_delete_user(
    ctx: Ctx,
    *,
    email: str,
    dry_run: bool = False,
) -> None:
    """Delete a user from the Cognito User Pool."""
    pool_id = _get_user_pool_id(ctx)

    _eprint(f"Deleting user: {email}")
    if dry_run:
        _eprint(f"[DRY RUN] cognito-idp.admin_delete_user(UserPoolId={pool_id}, Username={email})")
        return

    client = _get_cognito_client(ctx)
    client.admin_delete_user(UserPoolId=pool_id, Username=email)
    _eprint(f"User {email} deleted")


def cognito_get_user(
    ctx: Ctx,
    *,
    email: str,
    dry_run: bool = False,
) -> dict[str, Any] | None:
    """Get a user's details from the Cognito User Pool."""
    pool_id = _get_user_pool_id(ctx)

    if dry_run:
        _eprint(f"[DRY RUN] cognito-idp.admin_get_user(UserPoolId={pool_id}, Username={email})")
        return None

    client = _get_cognito_client(ctx)
    try:
        return client.admin_get_user(UserPoolId=pool_id, Username=email)
    except client.exceptions.UserNotFoundException:
        return None


# ---------------------------------------------------------------------------
# Device Detection (USB and Direct-Attach)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectedDevice:
    """A detected local device (USB or direct-attach)."""

    device_type: str  # "video", "audio_input", "audio_output", "serial"
    name: str
    path: str  # e.g., /dev/video0, /dev/ttyUSB0
    connection_type: str  # "usb" or "direct"
    vendor_id: str | None = None
    product_id: str | None = None
    serial: str | None = None


def _get_linux_video_connection_type(video_path: str) -> str:
    """Determine if a Linux video device is USB or direct-attached.

    Checks the sysfs device path ancestry to determine the bus type.
    USB devices have '/usb' in their resolved sysfs path.

    Args:
        video_path: Path to the video device (e.g., /dev/video0)

    Returns:
        'usb' if the device is connected via USB, 'direct' otherwise
        (includes PCI, platform, virtual devices like v4l2loopback)
    """
    device_name = os.path.basename(video_path)
    sysfs_device_path = f"/sys/class/video4linux/{device_name}/device"

    try:
        # Resolve the symlink to get the actual device path in sysfs
        # USB devices will have paths like:
        #   /sys/devices/pci0000:00/.../usb1/1-2/1-2:1.0/video4linux/video0
        # Built-in/PCI cameras will have paths like:
        #   /sys/devices/pci0000:00/.../0000:00:14.0/video4linux/video0
        # Platform devices (e.g., Raspberry Pi camera):
        #   /sys/devices/platform/.../video4linux/video0
        if os.path.exists(sysfs_device_path):
            real_path = os.path.realpath(sysfs_device_path)
            # Check if 'usb' appears in the path hierarchy
            if "/usb" in real_path:
                return "usb"
    except OSError:
        pass

    # Fallback: check subsystem symlink
    subsystem_path = f"/sys/class/video4linux/{device_name}/device/subsystem"
    try:
        if os.path.islink(subsystem_path):
            subsystem = os.path.basename(os.path.realpath(subsystem_path))
            if subsystem == "usb":
                return "usb"
    except OSError:
        pass

    # Default to direct for non-USB devices (PCI, platform, virtual, etc.)
    return "direct"


def detect_local_devices() -> list[DetectedDevice]:
    """Detect USB and direct-attach devices on the local machine.

    Detects:
    - Video devices (cameras, webcams)
    - Audio input devices (microphones)
    - Audio output devices (speakers)
    - Serial ports (USB-to-serial adapters)

    Returns a list of DetectedDevice objects.
    """
    devices: list[DetectedDevice] = []

    # Detect video devices
    devices.extend(_detect_video_devices())

    # Detect audio devices
    devices.extend(_detect_audio_devices())

    # Detect serial ports
    devices.extend(_detect_serial_ports())

    return devices


def _detect_video_devices() -> list[DetectedDevice]:
    """Detect video capture devices (cameras, webcams)."""
    devices: list[DetectedDevice] = []

    if sys.platform == "darwin":
        # macOS: Use system_profiler to list cameras
        try:
            result = subprocess.run(
                ["system_profiler", "SPCameraDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                cameras = data.get("SPCameraDataType", [])
                for i, cam in enumerate(cameras):
                    name = cam.get("_name", f"Camera {i}")
                    # macOS doesn't expose /dev paths for cameras directly
                    # Use AVFoundation index as identifier
                    path = f"avfoundation:{i}"
                    conn_type = "usb" if "usb" in name.lower() else "direct"
                    devices.append(
                        DetectedDevice(
                            device_type="video",
                            name=name,
                            path=path,
                            connection_type=conn_type,
                            vendor_id=cam.get("spcamera_vendor-id"),
                            product_id=cam.get("spcamera_model-id"),
                        )
                    )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

    else:
        # Linux: Check /dev/video* devices
        import glob

        for video_path in sorted(glob.glob("/dev/video*")):
            try:
                # Try to get device name from v4l2
                result = subprocess.run(
                    ["v4l2-ctl", "--device", video_path, "--info"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                name = video_path
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "Card type" in line:
                            name = line.split(":", 1)[-1].strip()
                            break

                # Determine connection type by checking sysfs device path ancestry
                conn_type = _get_linux_video_connection_type(video_path)

                devices.append(
                    DetectedDevice(
                        device_type="video",
                        name=name,
                        path=video_path,
                        connection_type=conn_type,
                    )
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # v4l2-ctl not installed, try to determine connection type anyway
                conn_type = _get_linux_video_connection_type(video_path)
                devices.append(
                    DetectedDevice(
                        device_type="video",
                        name=video_path,
                        path=video_path,
                        connection_type=conn_type,
                    )
                )

    return devices


def _detect_audio_devices() -> list[DetectedDevice]:
    """Detect audio input/output devices."""
    devices: list[DetectedDevice] = []

    if sys.platform == "darwin":
        # macOS: Use system_profiler for audio devices
        try:
            result = subprocess.run(
                ["system_profiler", "SPAudioDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                audio_devices = data.get("SPAudioDataType", [])
                for device in audio_devices:
                    items = device.get("_items", [])
                    for item in items:
                        name = item.get("_name", "Unknown Audio Device")
                        # Determine if input or output
                        dev_type = "audio_input" if "input" in name.lower() or "microphone" in name.lower() else "audio_output"
                        # macOS uses CoreAudio, no /dev path
                        path = f"coreaudio:{name}"
                        conn_type = "usb" if "usb" in name.lower() else "direct"
                        devices.append(
                            DetectedDevice(
                                device_type=dev_type,
                                name=name,
                                path=path,
                                connection_type=conn_type,
                            )
                        )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

    else:
        # Linux: Check ALSA devices
        try:
            # List capture devices (microphones)
            result = subprocess.run(
                ["arecord", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("card"):
                        # Parse: "card 0: PCH [HDA Intel PCH], device 0: ALC..."
                        parts = line.split(":")
                        if len(parts) >= 2:
                            card_info = parts[0].split()
                            card_num = card_info[1] if len(card_info) > 1 else "0"
                            name = parts[1].strip().split(",")[0].strip()
                            path = f"hw:{card_num}"
                            devices.append(
                                DetectedDevice(
                                    device_type="audio_input",
                                    name=name,
                                    path=path,
                                    connection_type="direct",
                                )
                            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            # List playback devices (speakers)
            result = subprocess.run(
                ["aplay", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("card"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            card_info = parts[0].split()
                            card_num = card_info[1] if len(card_info) > 1 else "0"
                            name = parts[1].strip().split(",")[0].strip()
                            path = f"hw:{card_num}"
                            devices.append(
                                DetectedDevice(
                                    device_type="audio_output",
                                    name=name,
                                    path=path,
                                    connection_type="direct",
                                )
                            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return devices


def _detect_serial_ports() -> list[DetectedDevice]:
    """Detect serial ports (USB-to-serial adapters, etc.)."""
    devices: list[DetectedDevice] = []
    import glob

    # Common serial port patterns
    patterns = [
        "/dev/ttyUSB*",  # USB-to-serial adapters (Linux)
        "/dev/ttyACM*",  # Arduino, etc. (Linux)
        "/dev/tty.usb*",  # USB serial (macOS)
        "/dev/cu.usb*",  # USB serial (macOS)
        "/dev/tty.Bluetooth*",  # Bluetooth serial (macOS)
    ]

    for pattern in patterns:
        for port_path in sorted(glob.glob(pattern)):
            name = os.path.basename(port_path)
            conn_type = "usb" if "usb" in port_path.lower() else "direct"
            devices.append(
                DetectedDevice(
                    device_type="serial",
                    name=name,
                    path=port_path,
                    connection_type=conn_type,
                )
            )

    return devices


def list_detected_devices(
    *,
    device_type: str | None = None,
    connection_type: str | None = None,
    output_format: str = "table",
) -> list[dict[str, Any]]:
    """List detected local devices with optional filtering.

    Args:
        device_type: Filter by type ("video", "audio_input", "audio_output", "serial")
        connection_type: Filter by connection ("usb", "direct")
        output_format: Output format ("table", "json")

    Returns:
        List of device dictionaries.
    """
    devices = detect_local_devices()

    # Apply filters
    if device_type:
        devices = [d for d in devices if d.device_type == device_type]
    if connection_type:
        devices = [d for d in devices if d.connection_type == connection_type]

    # Convert to dicts
    result = []
    for d in devices:
        result.append({
            "device_type": d.device_type,
            "name": d.name,
            "path": d.path,
            "connection_type": d.connection_type,
            "vendor_id": d.vendor_id,
            "product_id": d.product_id,
            "serial": d.serial,
        })

    return result
