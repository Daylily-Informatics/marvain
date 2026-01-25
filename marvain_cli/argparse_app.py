from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
from pathlib import Path

from marvain_cli import __version__
from marvain_cli.config import ConfigError, render_config_yaml, sanitize_name_for_stack
from marvain_cli.ops import (
    bootstrap,
	cognito_admin_create_user,
	cognito_admin_delete_user,
	cognito_list_users,
    doctor,
    gui_run,
	hub_claim_first_owner,
	hub_grant_membership,
	hub_list_memberships,
	hub_register_device,
	hub_revoke_membership,
	hub_update_membership,
    init_db,
    load_ctx,
    monitor_outputs,
    monitor_status,
    sam_build,
    sam_build_simple,
    sam_deploy,
    sam_logs,
    teardown,
)


def _git_user_name() -> str | None:
    try:
        out = subprocess.check_output(["git", "config", "user.name"], stderr=subprocess.DEVNULL)
        name = out.decode("utf-8").strip()
        return name or None
    except Exception:
        return None


def run(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="marvain")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--config", default=None)
    ap.add_argument("--env", default=None)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--region", default=None)
    ap.add_argument("--stack", default=None)
    ap.add_argument("--dry-run", action="store_true")

    sub = ap.add_subparsers(dest="cmd")

    cfg = sub.add_parser("config", help="Configuration management")
    cfg_sub = cfg.add_subparsers(dest="cfg_cmd")
    cfg_sub.add_parser("path", help="Print resolved config path")
    cfg_sub.add_parser("show", help="Print loaded config (JSON)")
    cfg_sub.add_parser("validate", help="Validate config for selected env")
    cfg_init = cfg_sub.add_parser("init", help="Create a config file")
    cfg_init.add_argument("--write", default=None, help="Write config to this path")
    cfg_init.add_argument("--env", default="dev")
    cfg_init.add_argument("--profile", default=None)
    cfg_init.add_argument("--region", default=None)
    cfg_init.add_argument("--stack", default=None)

    build = sub.add_parser("build", help="Run sam build")
    build.add_argument("--dry-run", action="store_true")
    dep = sub.add_parser("deploy", help="Deploy SAM stack")
    dep.add_argument("--guided", action="store_true")
    dep.add_argument("--no-guided", action="store_true")
    dep.add_argument("--dry-run", action="store_true")

    logs = sub.add_parser("logs", help="Tail SAM logs")
    logs.add_argument("--function", action="append", default=None)
    logs.add_argument("--tail", action="store_true")
    logs.add_argument("--no-tail", action="store_true")
    logs.add_argument("--since", default=None)
    logs.add_argument("--output-file", default=None, help="Write a copy of logs to this file (append)")
    logs.add_argument(
        "--suppress-sam-warnings",
        action="store_true",
        help="Suppress known, non-actionable SAM CLI Python warnings (does not hide errors)",
    )
    logs.add_argument("--dry-run", action="store_true")

    mon = sub.add_parser("monitor", help="Monitoring helpers")
    mon_sub = mon.add_subparsers(dest="mon_cmd")
    mo = mon_sub.add_parser("outputs", help="Print CloudFormation outputs")
    mo.add_argument("--write-config", action="store_true")
    mo.add_argument("--dry-run", action="store_true")

    ms = mon_sub.add_parser("status", help="Print stack status")
    ms.add_argument("--dry-run", action="store_true")

    td = sub.add_parser("teardown", help="Delete CloudFormation stack")
    td.add_argument("--yes", action="store_true")
    td.add_argument("--no-wait", action="store_true")
    td.add_argument("--dry-run", action="store_true")

    doc = sub.add_parser("doctor", help="Check local toolchain + AWS credentials")
    doc.add_argument("--dry-run", action="store_true")

    init = sub.add_parser("init", help="Initialization helpers")
    init_sub = init.add_subparsers(dest="init_cmd")
    init_db_p = init_sub.add_parser("db", help="Initialize Aurora schema via RDS Data API")
    init_db_p.add_argument("--sql-file", default=None)
    init_db_p.add_argument("--dry-run", action="store_true")

    bs = sub.add_parser("bootstrap", help="Create agent/space/device and store token")
    bs.add_argument("--agent-name", default=None)
    bs.add_argument("--space-name", default="default")
    bs.add_argument("--device-name", default=None)
    bs.add_argument("--force", action="store_true")
    bs.add_argument("--dry-run", action="store_true")

    gui = sub.add_parser("gui", help="Run the local GUI (archive/client/gui.py)")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8000)
    gui.add_argument("--reload", action="store_true")
    gui.add_argument("--no-reload", action="store_true")
    gui.add_argument("--stack-prefix", default=None)
    gui.add_argument("--dry-run", action="store_true")

    tst = sub.add_parser("test", help="Run tests")
    tst.add_argument("kind", nargs="?", default="unit", choices=["unit", "all"])
    tst.add_argument("--dry-run", action="store_true")

    users = sub.add_parser("users", help="Cognito user administration")
    users_sub = users.add_subparsers(dest="users_cmd")
    u_create = users_sub.add_parser("create", help="Invite/create a Cognito user")
    u_create.add_argument("--email", required=True)
    u_create.add_argument("--dry-run", action="store_true")
    u_list = users_sub.add_parser("list", help="List Cognito users")
    u_list.add_argument("--limit", type=int, default=60)
    u_list.add_argument("--dry-run", action="store_true")
    u_delete = users_sub.add_parser("delete", help="Delete a Cognito user")
    u_delete.add_argument("--email", required=True)
    u_delete.add_argument("--dry-run", action="store_true")

    members = sub.add_parser("members", help="Agent membership management (Hub API)")
    members_sub = members.add_subparsers(dest="members_cmd")
    m_claim = members_sub.add_parser("claim-owner", help="Claim first owner for an agent")
    m_claim.add_argument("--agent-id", required=True)
    m_claim.add_argument("--access-token", default=None)
    m_claim.add_argument("--hub-rest-api-base", default=None)
    m_claim.add_argument("--dry-run", action="store_true")
    m_list = members_sub.add_parser("list", help="List members for an agent")
    m_list.add_argument("--agent-id", required=True)
    m_list.add_argument("--access-token", default=None)
    m_list.add_argument("--hub-rest-api-base", default=None)
    m_list.add_argument("--dry-run", action="store_true")
    m_grant = members_sub.add_parser("grant", help="Grant membership by email")
    m_grant.add_argument("--agent-id", required=True)
    m_grant.add_argument("--email", required=True)
    m_grant.add_argument("--role", required=True)
    m_grant.add_argument("--relationship-label", default=None)
    m_grant.add_argument("--access-token", default=None)
    m_grant.add_argument("--hub-rest-api-base", default=None)
    m_grant.add_argument("--dry-run", action="store_true")
    m_update = members_sub.add_parser("update", help="Update membership role/relationship")
    m_update.add_argument("--agent-id", required=True)
    m_update.add_argument("--user-id", required=True)
    m_update.add_argument("--role", required=True)
    m_update.add_argument("--relationship-label", default=None)
    m_update.add_argument("--access-token", default=None)
    m_update.add_argument("--hub-rest-api-base", default=None)
    m_update.add_argument("--dry-run", action="store_true")
    m_revoke = members_sub.add_parser("revoke", help="Revoke membership")
    m_revoke.add_argument("--agent-id", required=True)
    m_revoke.add_argument("--user-id", required=True)
    m_revoke.add_argument("--access-token", default=None)
    m_revoke.add_argument("--hub-rest-api-base", default=None)
    m_revoke.add_argument("--dry-run", action="store_true")

    devices = sub.add_parser("devices", help="Device token management (Hub API)")
    devices_sub = devices.add_subparsers(dest="devices_cmd")
    d_register = devices_sub.add_parser("register", help="Register a new device (mint device token)")
    d_register.add_argument("--agent-id", required=True)
    d_register.add_argument("--name", default=None)
    d_register.add_argument("--scope", action="append", default=[])
    d_register.add_argument("--access-token", default=None)
    d_register.add_argument("--hub-rest-api-base", default=None)
    d_register.add_argument("--dry-run", action="store_true")

    args = ap.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    if args.cmd == "config":
        if args.cfg_cmd == "path":
            from marvain_cli.config import find_config_path

            p = find_config_path(args.config)
            if p is None:
                return 1
            print(str(p))
            return 0

        if args.cfg_cmd == "init":
            if args.write:
                write_path = Path(args.write).expanduser().resolve()
            else:
                xdg_home = Path(os.getenv("XDG_CONFIG_HOME") or (Path.home() / ".config")).expanduser()
                write_path = (xdg_home / "marvain" / "marvain.yaml").resolve()
            write_path.parent.mkdir(parents=True, exist_ok=True)

            env = args.env
            git_name = _git_user_name() or os.getenv("USER") or "user"
            suggested_stack = f"marvain-{sanitize_name_for_stack(git_name)}-{env}"
            aws_profile = args.profile or os.getenv("AWS_PROFILE") or ""
            aws_region = args.region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""
            stack_name = args.stack or suggested_stack

            if not aws_profile or aws_profile == "default":
                print("ERROR: --profile (non-default) is required for config init", file=os.sys.stderr)
                return 2
            if not aws_region:
                print("ERROR: --region is required for config init", file=os.sys.stderr)
                return 2

            text = render_config_yaml(env=env, aws_profile=aws_profile, aws_region=aws_region, stack_name=stack_name)
            write_path.write_text(text, encoding="utf-8")
            print(f"Wrote config: {write_path}")
            print(f"Suggested device_name (bootstrap default): {socket.gethostname()}")
            return 0

        # load + validate/show
        try:
            ctx = load_ctx(
                config_override=args.config,
                env=args.env,
                profile=args.profile,
                region=args.region,
                stack=args.stack,
            )
        except ConfigError as e:
            print(f"ERROR: {e}", file=os.sys.stderr)
            return 2

        if args.cfg_cmd == "validate":
            return 0

        if args.cfg_cmd == "show":
            print(
                json.dumps(
                    {
                        "config_path": str(ctx.config_path),
                        "env": ctx.env.env,
                        "aws_profile": ctx.env.aws_profile,
                        "aws_region": ctx.env.aws_region,
                        "stack_name": ctx.env.stack_name,
                        "env_config": ctx.env.raw,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        cfg.print_help()
        return 2

    # Commands that do not require config.
    if args.cmd == "test":
        return run_tests(dry_run=bool(args.dry_run))

    if args.cmd == "build":
        # Build can run without config; if config exists we'll respect its
        # `sam.template` setting.
        try:
            ctx = load_ctx(
                config_override=args.config,
                env=args.env,
                profile=args.profile,
                region=args.region,
                stack=args.stack,
            )
            return sam_build(ctx, dry_run=bool(args.dry_run))
        except ConfigError:
            return sam_build_simple(dry_run=bool(args.dry_run), template="template.yaml")

    # Non-config commands require config.
    try:
        ctx = load_ctx(
            config_override=args.config,
            env=args.env,
            profile=args.profile,
            region=args.region,
            stack=args.stack,
        )
    except ConfigError as e:
        print(f"ERROR: {e}", file=os.sys.stderr)
        return 2

    try:
        if args.cmd == "deploy":
            # Default to guided (matches prior Makefile's `sam deploy --guided`).
            guided = True
            if bool(args.no_guided):
                guided = False
            if bool(args.guided):
                guided = True
            return sam_deploy(ctx, dry_run=bool(args.dry_run), guided=guided)
        if args.cmd == "logs":
            tail = True
            if args.no_tail:
                tail = False
            if args.tail:
                tail = True
            return sam_logs(
                ctx,
                dry_run=bool(args.dry_run),
                functions=args.function,
                tail=tail,
                since=args.since,
                output_file=args.output_file,
                suppress_sam_warnings=bool(args.suppress_sam_warnings),
            )
        if args.cmd == "monitor":
            if args.mon_cmd == "outputs":
                return monitor_outputs(ctx, dry_run=bool(args.dry_run), write_config=bool(args.write_config))
            if args.mon_cmd == "status":
                return monitor_status(ctx, dry_run=bool(args.dry_run))
            mon.print_help()
            return 2
        if args.cmd == "teardown":
            return teardown(ctx, dry_run=bool(args.dry_run), yes=bool(args.yes), wait=not bool(args.no_wait))
        if args.cmd == "doctor":
            return doctor(ctx, dry_run=bool(args.dry_run))
        if args.cmd == "init":
            if args.init_cmd == "db":
                return init_db(ctx, dry_run=bool(args.dry_run), sql_file=args.sql_file)
            init.print_help()
            return 2
        if args.cmd == "bootstrap":
            return bootstrap(
                ctx,
                dry_run=bool(args.dry_run),
                agent_name=args.agent_name,
                space_name=args.space_name,
                device_name=args.device_name,
                force=bool(args.force),
            )
        if args.cmd == "gui":
            reload = True
            if bool(args.no_reload):
                reload = False
            if bool(args.reload):
                reload = True
            return gui_run(
                ctx,
                dry_run=bool(args.dry_run),
                host=str(args.host),
                port=int(args.port),
                reload=reload,
                stack_prefix=args.stack_prefix,
            )

        if args.cmd == "users":
            if args.users_cmd == "create":
                data = cognito_admin_create_user(ctx, email=str(args.email), dry_run=bool(args.dry_run))
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.users_cmd == "list":
                data = cognito_list_users(ctx, dry_run=bool(args.dry_run), limit=int(args.limit))
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.users_cmd == "delete":
                return int(cognito_admin_delete_user(ctx, dry_run=bool(args.dry_run), email=str(args.email)))
            users.print_help()
            return 2

        if args.cmd == "members":
            if args.members_cmd == "claim-owner":
                data = hub_claim_first_owner(
                    ctx,
                    agent_id=str(args.agent_id),
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.members_cmd == "list":
                data = hub_list_memberships(
                    ctx,
                    agent_id=str(args.agent_id),
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.members_cmd == "grant":
                data = hub_grant_membership(
                    ctx,
                    agent_id=str(args.agent_id),
                    email=str(args.email),
                    role=str(args.role),
                    relationship_label=args.relationship_label,
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.members_cmd == "update":
                data = hub_update_membership(
                    ctx,
                    agent_id=str(args.agent_id),
                    user_id=str(args.user_id),
                    role=str(args.role),
                    relationship_label=args.relationship_label,
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            if args.members_cmd == "revoke":
                data = hub_revoke_membership(
                    ctx,
                    agent_id=str(args.agent_id),
                    user_id=str(args.user_id),
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            members.print_help()
            return 2

        if args.cmd == "devices":
            if args.devices_cmd == "register":
                data = hub_register_device(
                    ctx,
                    agent_id=str(args.agent_id),
                    name=args.name,
                    scopes=(list(args.scope) if args.scope else None),
                    access_token=args.access_token,
                    hub_rest_api_base=args.hub_rest_api_base,
                    dry_run=bool(args.dry_run),
                )
                if not bool(args.dry_run):
                    print(json.dumps(data, indent=2, sort_keys=True))
                return 0
            devices.print_help()
            return 2

        ap.print_help()
        return 2
    except subprocess.CalledProcessError as e:
        print(f"ERROR: command failed ({e.returncode}): {e.cmd}", file=os.sys.stderr)
        return e.returncode



def run_tests(*, dry_run: bool) -> int:
    from pathlib import Path

    cmd = ["python3", "-m", "unittest", "discover", "-s", "tests", "-q"]
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    pythonpath_parts = [str(repo_root), str(shared)]
    old_pp = os.environ.get("PYTHONPATH")
    if old_pp:
        pythonpath_parts.append(old_pp)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    if dry_run:
        print(f"$ PYTHONPATH={env['PYTHONPATH']} " + " ".join(cmd), file=os.sys.stderr)
        return 0
    return subprocess.call(cmd, env=env)
