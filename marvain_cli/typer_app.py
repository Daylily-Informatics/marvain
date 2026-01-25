def run(argv: list[str]) -> int:
    # Import lazily so the repo can run without Typer installed.
    import typer  # type: ignore

    from typing import NoReturn

    from subprocess import CalledProcessError

    from marvain_cli import __version__
    from marvain_cli.config import ConfigError, find_config_path, render_config_yaml, sanitize_name_for_stack
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

    app = typer.Typer(
        add_completion=True,
        help="marvain CLI (Makefile replacement)",
        invoke_without_command=True,
        no_args_is_help=True,
    )

    def _die(msg: str, code: int = 2) -> NoReturn:
        typer.echo(f"ERROR: {msg}", err=True)
        raise typer.Exit(code=code)

    def _load(ctx: typer.Context):
        try:
            return load_ctx(
                config_override=ctx.obj.get("config"),
                env=ctx.obj.get("env"),
                profile=ctx.obj.get("profile"),
                region=ctx.obj.get("region"),
                stack=ctx.obj.get("stack"),
            )
        except ConfigError as e:
            _die(str(e), code=2)

    @app.callback()
    def _root(
        ctx: typer.Context,
        config: str | None = typer.Option(None, "--config", help="Path to config YAML"),
        env: str | None = typer.Option(None, "--env", help="Environment name (from config)"),
        profile: str | None = typer.Option(None, "--profile", help="AWS profile override"),
        region: str | None = typer.Option(None, "--region", help="AWS region override"),
        stack: str | None = typer.Option(None, "--stack", help="Stack name override"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
        version: bool = typer.Option(False, "--version", help="Print version and exit"),
    ) -> None:
        if version:
            typer.echo(__version__)
            raise typer.Exit(code=0)
        ctx.obj = {
            "config": config,
            "env": env,
            "profile": profile,
            "region": region,
            "stack": stack,
            "dry_run": dry_run,
        }

    # ---- config ----
    cfg_app = typer.Typer(help="Configuration management")
    app.add_typer(cfg_app, name="config")

    @cfg_app.command("path")
    def cfg_path(ctx: typer.Context) -> None:
        p = find_config_path(ctx.obj.get("config"))
        if p is None:
            raise typer.Exit(code=1)
        typer.echo(str(p))

    @cfg_app.command("init")
    def cfg_init(
        write: str | None = typer.Option(None, "--write", help="Write config to this path"),
        env: str = typer.Option("dev", "--env"),
        profile: str | None = typer.Option(None, "--profile"),
        region: str | None = typer.Option(None, "--region"),
        stack: str | None = typer.Option(None, "--stack"),
    ) -> None:
        import os
        import socket
        import subprocess
        from pathlib import Path

        def git_user_name() -> str | None:
            try:
                out = subprocess.check_output(["git", "config", "user.name"], stderr=subprocess.DEVNULL)
                s = out.decode("utf-8").strip()
                return s or None
            except Exception:
                return None

        if write:
            write_path = Path(write).expanduser().resolve()
        else:
            xdg_home = Path(os.getenv("XDG_CONFIG_HOME") or (Path.home() / ".config")).expanduser()
            write_path = (xdg_home / "marvain" / "marvain.yaml").resolve()
        write_path.parent.mkdir(parents=True, exist_ok=True)

        git_name = git_user_name() or os.getenv("USER") or "user"
        suggested_stack = f"marvain-{sanitize_name_for_stack(git_name)}-{env}"
        aws_profile = profile or os.getenv("AWS_PROFILE") or ""
        aws_region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""
        stack_name = stack or suggested_stack

        if not aws_profile or aws_profile == "default":
            _die("--profile (non-default) is required for config init", code=2)
        if not aws_region:
            _die("--region is required for config init", code=2)

        txt = render_config_yaml(env=env, aws_profile=aws_profile, aws_region=aws_region, stack_name=stack_name)
        write_path.write_text(txt, encoding="utf-8")
        typer.echo(f"Wrote config: {write_path}")
        typer.echo(f"Suggested device_name (bootstrap default): {socket.gethostname()}")

    @cfg_app.command("validate")
    def cfg_validate(ctx: typer.Context) -> None:
        _load(ctx)

    @cfg_app.command("show")
    def cfg_show(ctx: typer.Context) -> None:
        import json

        c = _load(ctx)
        typer.echo(
            json.dumps(
                {
                    "config_path": str(c.config_path),
                    "env": c.env.env,
                    "aws_profile": c.env.aws_profile,
                    "aws_region": c.env.aws_region,
                    "stack_name": c.env.stack_name,
                    "env_config": c.env.raw,
                },
                indent=2,
                sort_keys=True,
            )
        )

    # ---- lifecycle ----
    @app.command("build")
    def _build(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        # Build can run without config; if config exists we'll respect its
        # `sam.template` setting.
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        p = find_config_path(ctx.obj.get("config"))
        if p is None:
            raise typer.Exit(code=sam_build_simple(dry_run=dr, template="template.yaml"))

        c = _load(ctx)
        raise typer.Exit(code=sam_build(c, dry_run=dr))

    @app.command("deploy")
    def _deploy(
        ctx: typer.Context,
        guided: bool = typer.Option(True, "--guided/--no-guided", help="Use SAM guided deploy"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=sam_deploy(c, dry_run=dr, guided=guided))

    @app.command("logs")
    def _logs(
        ctx: typer.Context,
        function: list[str] = typer.Option([], "--function", "-f", help="Function logical id (repeatable)"),
        tail: bool = typer.Option(True, "--tail/--no-tail", help="Tail logs"),
        since: str | None = typer.Option(None, "--since", help="Since (e.g. 10m, 1h)"),
        output_file: str | None = typer.Option(None, "--output-file", help="Write a copy of logs to this file (append)"),
        suppress_sam_warnings: bool = typer.Option(
            False,
            "--suppress-sam-warnings",
            help="Suppress known, non-actionable SAM CLI Python warnings (does not hide errors)",
        ),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(
            code=sam_logs(
                c,
                dry_run=dr,
                functions=function or None,
                tail=tail,
                since=since,
                output_file=output_file,
                suppress_sam_warnings=bool(suppress_sam_warnings),
            )
        )

    mon_app = typer.Typer(help="Monitoring helpers")
    app.add_typer(mon_app, name="monitor")

    @mon_app.command("outputs")
    def mon_outputs(
        ctx: typer.Context,
        write_config: bool = typer.Option(False, "--write-config"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=monitor_outputs(c, dry_run=dr, write_config=write_config))

    @mon_app.command("status")
    def mon_status(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=monitor_status(c, dry_run=dr))

    @app.command("teardown")
    def _teardown(
        ctx: typer.Context,
        yes: bool = typer.Option(False, "--yes", help="Confirm deletion"),
        wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for delete completion"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=teardown(c, dry_run=dr, yes=yes, wait=wait))

    @app.command("doctor")
    def _doctor(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=doctor(c, dry_run=dr))

    @app.command("gui", help="Show the deployed Hub GUI URL (legacy local GUI removed)")
    def gui_run_cmd(
        ctx: typer.Context,
        host: str = typer.Option("127.0.0.1", "--host"),
        port: int = typer.Option(8000, "--port"),
        reload: bool = typer.Option(True, "--reload/--no-reload"),
        stack_prefix: str | None = typer.Option(None, "--stack-prefix"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(
            code=gui_run(
                c,
                dry_run=dr,
                host=host,
                port=port,
                reload=reload,
                stack_prefix=stack_prefix,
            )
        )

    init_app = typer.Typer(help="Initialization helpers")
    app.add_typer(init_app, name="init")

    @init_app.command("db")
    def init_db_cmd(
        ctx: typer.Context,
        sql_file: str | None = typer.Option(None, "--sql-file"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=init_db(c, dry_run=dr, sql_file=sql_file))

    @app.command("bootstrap")
    def _bootstrap(
        ctx: typer.Context,
        agent_name: str | None = typer.Option(None, "--agent-name"),
        space_name: str = typer.Option("default", "--space-name"),
        device_name: str | None = typer.Option(None, "--device-name"),
        force: bool = typer.Option(False, "--force"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))

        raise typer.Exit(
            code=bootstrap(
                c,
                dry_run=dr,
                agent_name=agent_name,
                space_name=space_name,
                device_name=device_name,
                force=force,
            )
        )


    # ---- users (Cognito) ----
    users_app = typer.Typer(help="Cognito user administration")
    app.add_typer(users_app, name="users")

    @users_app.command("create")
    def users_create(
        ctx: typer.Context,
        email: str = typer.Option(..., "--email"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = cognito_admin_create_user(c, email=email, dry_run=dr)
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @users_app.command("list")
    def users_list(
        ctx: typer.Context,
        limit: int = typer.Option(60, "--limit"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = cognito_list_users(c, dry_run=dr, limit=limit)
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @users_app.command("delete")
    def users_delete(
        ctx: typer.Context,
        email: str = typer.Option(..., "--email"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        rc = cognito_admin_delete_user(c, dry_run=dr, email=email)
        raise typer.Exit(code=int(rc))

    # ---- members (Hub API) ----
    members_app = typer.Typer(help="Agent membership management (Hub API)")
    app.add_typer(members_app, name="members")

    @members_app.command("claim-owner")
    def members_claim_owner(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_claim_first_owner(
            c,
            agent_id=agent_id,
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @members_app.command("list")
    def members_list(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_list_memberships(
            c,
            agent_id=agent_id,
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @members_app.command("grant")
    def members_grant(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        email: str = typer.Option(..., "--email"),
        role: str = typer.Option(..., "--role"),
        relationship_label: str | None = typer.Option(None, "--relationship-label"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_grant_membership(
            c,
            agent_id=agent_id,
            email=email,
            role=role,
            relationship_label=relationship_label,
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @members_app.command("update")
    def members_update(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        user_id: str = typer.Option(..., "--user-id"),
        role: str = typer.Option(..., "--role"),
        relationship_label: str | None = typer.Option(None, "--relationship-label"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_update_membership(
            c,
            agent_id=agent_id,
            user_id=user_id,
            role=role,
            relationship_label=relationship_label,
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @members_app.command("revoke")
    def members_revoke(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        user_id: str = typer.Option(..., "--user-id"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_revoke_membership(
            c,
            agent_id=agent_id,
            user_id=user_id,
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    # ---- devices (Hub API) ----
    devices_app = typer.Typer(help="Device token management (Hub API)")
    app.add_typer(devices_app, name="devices")

    @devices_app.command("register")
    def devices_register(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        name: str | None = typer.Option(None, "--name"),
        scopes: list[str] = typer.Option([], "--scope", help="Repeatable"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        import json

        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        data = hub_register_device(
            c,
            agent_id=agent_id,
            name=name,
            scopes=(scopes if scopes else None),
            access_token=access_token,
            hub_rest_api_base=hub_rest_api_base,
            dry_run=dr,
        )
        if not dr:
            typer.echo(json.dumps(data, indent=2, sort_keys=True))
        raise typer.Exit(code=0)

    @app.command("test")
    def _test(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        # Keep tests stdlib-first.
        import os
        import subprocess
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

        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        if dr:
            typer.echo(f"$ PYTHONPATH={env['PYTHONPATH']} " + " ".join(cmd), err=True)
            raise typer.Exit(code=0)
        raise typer.Exit(code=int(subprocess.call(cmd, env=env)))

    # Execute without letting Click `sys.exit()`.
    command = typer.main.get_command(app)
    try:
        rv = command.main(args=argv, prog_name="marvain", standalone_mode=False)
        # In Click, when standalone_mode=False, Exit exceptions are converted into
        # an integer return value rather than sys.exit(). Propagate it.
        if isinstance(rv, int):
            return int(rv)
        return 0
    except ConfigError as e:
        typer.echo(f"ERROR: {e}", err=True)
        return 2
    except CalledProcessError as e:
        typer.echo(f"ERROR: command failed ({e.returncode}): {e.cmd}", err=True)
        return int(e.returncode)
    except SystemExit as e:  # pragma: no cover
        return int(e.code or 0)
