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
    # `--clean` avoids stale dependency artifacts (important for Lambda vendored deps).
    return run_cmd(["sam", "build", "--clean", "-t", template], env=None, dry_run=dry_run)


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
        _eprint("Hint: source .env before running deploy")
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


def status(ctx: Ctx, *, dry_run: bool) -> int:
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
        print(json.dumps({"stack": ctx.env.stack_name, "exists": False}, indent=2, sort_keys=True))
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
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def info(ctx: Ctx, *, dry_run: bool) -> int:
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
    print(json.dumps(result, indent=2, sort_keys=True))
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

    # Ensure .env.local exists with stack outputs
    env_local = hub_api_dir / ".env.local"
    if not env_local.exists():
        _eprint(f"ERROR: {env_local} not found")
        _eprint("Create it with stack outputs:")
        _eprint("  ./bin/marvain monitor outputs --write-config")
        return 2

    cmd = ["uvicorn", "app:app", "--host", host, "--port", str(port)]
    if reload:
        cmd.append("--reload")

    _eprint(f"Starting local GUI server at http://{host}:{port}")
    _eprint(f"Using environment from: {env_local}")
    _eprint(f"$ cd {hub_api_dir} && {' '.join(cmd)}")

    if dry_run:
        return 0

    # Build environment: start with current env, add .env.local, set PYTHONPATH
    env = os.environ.copy()

    # Load .env.local variables into environment
    with open(env_local) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()

    # Ensure AWS_DEFAULT_REGION is set (boto3 sometimes prefers this)
    if "AWS_REGION" in env and "AWS_DEFAULT_REGION" not in env:
        env["AWS_DEFAULT_REGION"] = env["AWS_REGION"]

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

GUI_DEFAULT_HOST = "127.0.0.1"
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


def gui_start(
    ctx: Ctx,
    *,
    dry_run: bool,
    host: str = GUI_DEFAULT_HOST,
    port: int = GUI_DEFAULT_PORT,
    reload: bool = True,
    foreground: bool = False,
) -> int:
    """Start the GUI server.

    The GUI runs locally (developer laptop or EC2) and connects to deployed
    AWS resources (Aurora Data API, Cognito, S3, SQS) via environment variables.

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to bind to (default: 8084)
        reload: Enable auto-reload on code changes
        foreground: Run in foreground (blocking) instead of background
    """
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    repo_root = Path(__file__).parent.parent
    hub_api_dir = repo_root / "functions" / "hub_api"
    shared_layer = repo_root / "layers" / "shared" / "python"

    # Ensure .env.local exists with stack outputs
    env_local = hub_api_dir / ".env.local"
    if not env_local.exists():
        _eprint(f"ERROR: {env_local} not found")
        _eprint("Create it with stack outputs:")
        _eprint("  ./bin/marvain monitor outputs --write-config")
        return 2

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

    _eprint(f"Starting local GUI server at http://{host}:{port}")
    _eprint(f"Using environment from: {env_local}")

    if dry_run:
        _eprint(f"[dry-run] $ cd {hub_api_dir} && {' '.join(cmd)}")
        return 0

    # Build environment: start with current env, add .env.local, set PYTHONPATH
    env = os.environ.copy()

    # Load .env.local variables into environment
    with open(env_local) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip()

    # Ensure AWS_DEFAULT_REGION is set (boto3 sometimes prefers this)
    if "AWS_REGION" in env and "AWS_DEFAULT_REGION" not in env:
        env["AWS_DEFAULT_REGION"] = env["AWS_REGION"]

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
        _eprint(f"  URL: http://{host}:{port}")
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
