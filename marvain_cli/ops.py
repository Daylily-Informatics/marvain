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


def cognito_admin_create_user(
    ctx: Ctx,
    *,
    email: str,
    dry_run: bool,
) -> dict[str, Any]:
    user_pool_id = resolve_stack_output(ctx, key="CognitoUserPoolId", dry_run=dry_run)
    cmd = [
        "aws",
        "cognito-idp",
        "admin-create-user",
        *aws_cli_args(ctx.env),
        "--user-pool-id",
        user_pool_id,
        "--username",
        email,
        "--user-attributes",
        f"Name=email,Value={email}",
        "--desired-delivery-mediums",
        "EMAIL",
        "--output",
        "json",
    ]
    return run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)


def cognito_list_users(ctx: Ctx, *, dry_run: bool, limit: int = 60) -> dict[str, Any]:
    user_pool_id = resolve_stack_output(ctx, key="CognitoUserPoolId", dry_run=dry_run)
    cmd = [
        "aws",
        "cognito-idp",
        "list-users",
        *aws_cli_args(ctx.env),
        "--user-pool-id",
        user_pool_id,
        "--max-results",
        str(int(limit)),
        "--output",
        "json",
    ]
    return run_json(cmd, env=cmd_env(ctx.env), dry_run=dry_run)


def cognito_admin_delete_user(ctx: Ctx, *, dry_run: bool, email: str) -> int:
    user_pool_id = resolve_stack_output(ctx, key="CognitoUserPoolId", dry_run=dry_run)
    cmd = [
        "aws",
        "cognito-idp",
        "admin-delete-user",
        *aws_cli_args(ctx.env),
        "--user-pool-id",
        user_pool_id,
        "--username",
        email,
    ]
    return run_cmd(cmd, env=cmd_env(ctx.env), dry_run=dry_run)


def sam_build_simple(*, dry_run: bool, template: str = "template.yaml") -> int:
    """Run `sam build` without requiring a config file."""

    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    return run_cmd(["sam", "build", "-t", template], env=None, dry_run=dry_run)


def sam_build(ctx: Ctx, *, dry_run: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    sam_cfg = (ctx.env.raw.get("sam") or {}) if isinstance(ctx.env.raw.get("sam"), dict) else {}
    template = str(sam_cfg.get("template") or "template.yaml")
    return run_cmd(["sam", "build", "-t", template], env=cmd_env(ctx.env), dry_run=dry_run)


def sam_deploy(ctx: Ctx, *, dry_run: bool, guided: bool) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    sam_cfg = (ctx.env.raw.get("sam") or {}) if isinstance(ctx.env.raw.get("sam"), dict) else {}
    template = str(sam_cfg.get("template") or "template.yaml")
    caps = sam_cfg.get("capabilities") or ["CAPABILITY_IAM"]
    if not isinstance(caps, list):
        caps = ["CAPABILITY_IAM"]
    param_overrides = sam_cfg.get("parameter_overrides") or {}
    if not isinstance(param_overrides, dict):
        param_overrides = {}

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
        # non-interactive default; still shows a changeset prompt unless user adds --no-confirm-changeset.
        cmd.append("--confirm-changeset")

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
    """Show the deployed Hub GUI URL.

    The legacy local GUI in `archive/client/gui.py` has been removed. The GUI is
    now served as routes in the Hub FastAPI app and is accessed via the deployed
    API Gateway URL (stack output `HubRestApiBase`).

    Notes:
    - `--host/--port/--reload/--stack-prefix` are kept for backward CLI
      compatibility but are no longer used.
    """

    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    # Back-compat: these flags used to control a local uvicorn server.
    _ = (host, port, reload, stack_prefix)

    outs = aws_stack_outputs(ctx, dry_run=dry_run)
    hub_base = (outs.get("HubRestApiBase") or "").strip()
    if not hub_base:
        _eprint("Legacy local GUI has been removed.")
        _eprint(f"Stack outputs for {ctx.env.stack_name} do not include HubRestApiBase.")
        _eprint("Try: ./bin/marvain monitor outputs")
        return 2

    hub_base = hub_base.rstrip("/")
    gui_url = hub_base + "/"
    livekit_test_url = hub_base + "/livekit-test"
    hosted_ui = (outs.get("CognitoHostedUiUrl") or "").strip()

    _eprint("Legacy local GUI has been removed.")
    _eprint("Open the deployed GUI:")
    print(gui_url)
    _eprint(f"GUI: {gui_url}")
    _eprint(f"LiveKit test: {livekit_test_url}")
    if hosted_ui:
        _eprint(f"Cognito Hosted UI: {hosted_ui}")
    return 0


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
