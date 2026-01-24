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
from dataclasses import dataclass
from pathlib import Path
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
    _eprint(f"$ {_fmt_cmd(cmd)}")
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
    _eprint(f"$ {_fmt_cmd(cmd)}")
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


def _tail_one(function_name: str, cmd: list[str], env: dict[str, str]) -> None:
    # Prefix every line so multiple streams are usable.
    p = subprocess.Popen(cmd, env={**os.environ, **env}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert p.stdout is not None
    try:
        for line in p.stdout:
            sys.stdout.write(f"[{function_name}] {line}")
            sys.stdout.flush()
    finally:
        try:
            p.terminate()
        except Exception:
            pass


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


def sam_logs(ctx: Ctx, *, dry_run: bool, functions: list[str] | None, tail: bool, since: str | None) -> int:
    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc
    fnames = functions or [
        # "more than less" default, per Major
        "HubApiFunction",
        "PlannerFunction",
        "ToolRunnerFunction",
        "WsConnectFunction",
        "WsDisconnectFunction",
        "WsMessageFunction",
    ]
    base = ["sam", "logs", *sam_cli_args(ctx.env), "--stack-name", ctx.env.stack_name]
    if since:
        # SAM CLI uses -s/--start-time (not --since).
        base.extend(["-s", _since_to_sam_start_time(since)])
    if tail:
        base.append("--tail")

    if dry_run:
        for f in fnames:
            _eprint(f"$ {_fmt_cmd([*base, '--name', f])}")
        return 0

    threads: list[threading.Thread] = []
    env = cmd_env(ctx.env)
    for f in fnames:
        cmd = [*base, "--name", f]
        t = threading.Thread(target=_tail_one, args=(f, cmd, env), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return 0


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
    """Run the local FastAPI/Jinja2 GUI (in archive/).

    The legacy GUI lives in `archive/client/gui.py` and expects to be run with
    CWD=archive so its relative template/static paths resolve.
    """

    rc = _conda_preflight(enforce=not dry_run)
    if rc != 0:
        return rc

    archive_dir = Path("archive")
    if not archive_dir.exists():
        _eprint("archive/ directory not found (GUI is not present in this checkout)")
        return 2

    # Default stack prefix from stack name like `marvain-foo-dev` -> `marvain`.
    prefix = stack_prefix
    if not prefix:
        prefix = (ctx.env.stack_name.split("-", 1)[0] if "-" in ctx.env.stack_name else ctx.env.stack_name)

    cmd: list[str] = [
        "python3",
        "-m",
        "uvicorn",
        "client.gui:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        cmd.append("--reload")

    extra_env = cmd_env(ctx.env)
    extra_env["AGENT_RESOURCE_STACK_PREFIX"] = prefix
    return run_cmd(cmd, env=extra_env, dry_run=dry_run, cwd=str(archive_dir))


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
    path = Path(sql_file or "sql/001_init.sql")
    sql_text = path.read_text(encoding="utf-8")
    stmts = _split_sql(sql_text)

    if dry_run:
        _eprint(f"[dry-run] Would resolve DbClusterArn/DbSecretArn/DbName from stack outputs for {ctx.env.stack_name}")
        _eprint(f"[dry-run] Would apply {len(stmts)} SQL statements from {path}")
        return 0

    resource_arn, secret_arn, db_name = _db_outputs(ctx, dry_run=dry_run)

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
