def run(argv: list[str]) -> int:
    # Import lazily so the repo can run without Typer installed.
    import json

    import typer  # type: ignore

    from typing import NoReturn

    from subprocess import CalledProcessError

    from marvain_cli import __version__
    from marvain_cli.config import ConfigError, find_config_path, render_config_yaml, sanitize_name_for_stack
    from marvain_cli.ops import (
        GUI_DEFAULT_HOST,
        GUI_DEFAULT_PORT,
        agent_logs,
        agent_rebuild,
        agent_restart,
        agent_start,
        agent_status,
        agent_stop,
        bootstrap,
        cognito_create_user,
        cognito_delete_user,
        cognito_get_user,
        cognito_list_users,
        cognito_set_password,
        doctor,
        gui_logs,
        gui_restart,
        gui_run,
        gui_start,
        gui_status,
        gui_stop,
        hub_claim_first_owner,
        hub_grant_membership,
        hub_list_memberships,
        hub_register_device,
        hub_revoke_membership,
        hub_update_membership,
        info,
        init_db,
        load_ctx,
        monitor_outputs,
        monitor_status,
        sam_build,
        sam_build_simple,
        sam_deploy,
        sam_logs,
        status,
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
            write_path = (xdg_home / "marvain" / "marvain-config.yaml").resolve()
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
        no_confirm: bool = typer.Option(False, "--no-confirm", help="Skip changeset confirmation (non-interactive)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=sam_deploy(c, dry_run=dr, guided=guided, no_confirm=no_confirm))

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

    @app.command("status", help="Show deployment status (stack existence, status, outputs)")
    def _status(
        ctx: typer.Context,
        output_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of pretty print"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=status(c, dry_run=dr, output_json=output_json))

    @app.command("info", help="Show deployment info (stack name, region, profile, resources)")
    def _info(
        ctx: typer.Context,
        output_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of pretty print"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=info(c, dry_run=dr, output_json=output_json))

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

    # GUI subcommands
    gui_app = typer.Typer(help="Local GUI server management")
    app.add_typer(gui_app, name="gui")

    @gui_app.callback(invoke_without_command=True)
    def gui_default(
        ctx: typer.Context,
        host: str = typer.Option(GUI_DEFAULT_HOST, "--host", help="Host to bind to"),
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port", help="Port to bind to"),
        reload: bool = typer.Option(True, "--reload/--no-reload", help="Enable auto-reload"),
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Start local GUI server (default action when no subcommand given)."""
        if ctx.invoked_subcommand is None:
            c = _load(ctx)
            dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
            raise typer.Exit(
                code=gui_start(c, dry_run=dr, host=host, port=port, reload=reload, foreground=foreground)
            )

    @gui_app.command("start", help="Start the local GUI server")
    def gui_start_cmd(
        ctx: typer.Context,
        host: str = typer.Option(GUI_DEFAULT_HOST, "--host", help="Host to bind to"),
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port", help="Port to bind to"),
        reload: bool = typer.Option(True, "--reload/--no-reload", help="Enable auto-reload"),
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        https: bool = typer.Option(True, "--https/--no-https", help="Enable HTTPS (default: on, uses mkcert if no cert/key provided)"),
        cert: str = typer.Option(None, "--cert", help="Path to SSL certificate file (PEM format)"),
        key: str = typer.Option(None, "--key", help="Path to SSL private key file (PEM format)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(
            code=gui_start(c, dry_run=dr, host=host, port=port, reload=reload, foreground=foreground, https=https, cert=cert, key=key)
        )

    @gui_app.command("stop", help="Stop the running GUI server")
    def gui_stop_cmd(
        ctx: typer.Context,
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port", help="Port the GUI is running on"),
        force: bool = typer.Option(False, "--force", help="Force kill (SIGKILL instead of SIGTERM)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=gui_stop(c, dry_run=dr, port=port, force=force))

    @gui_app.command("restart", help="Restart the GUI server (stop then start)")
    def gui_restart_cmd(
        ctx: typer.Context,
        host: str = typer.Option(GUI_DEFAULT_HOST, "--host", help="Host to bind to"),
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port", help="Port to bind to"),
        reload: bool = typer.Option(True, "--reload/--no-reload", help="Enable auto-reload"),
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        https: bool = typer.Option(True, "--https/--no-https", help="Enable HTTPS (default: on, uses mkcert if no cert/key provided)"),
        cert: str = typer.Option(None, "--cert", help="Path to SSL certificate file (PEM format)"),
        key: str = typer.Option(None, "--key", help="Path to SSL private key file (PEM format)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(
            code=gui_restart(c, dry_run=dr, host=host, port=port, reload=reload, foreground=foreground, https=https, cert=cert, key=key)
        )

    @gui_app.command("status", help="Show GUI server status")
    def gui_status_cmd(
        ctx: typer.Context,
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port", help="Port to check"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=gui_status(c, dry_run=dr, port=port))

    @gui_app.command("logs", help="Show GUI server logs")
    def gui_logs_cmd(
        ctx: typer.Context,
        follow: bool = typer.Option(False, "--follow", "-f", help="Follow log output (like tail -f)"),
        lines: int = typer.Option(50, "--lines", "-n", help="Number of lines to show"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=gui_logs(c, dry_run=dr, follow=follow, lines=lines))

    # Agent worker subcommands
    agent_app = typer.Typer(help="Agent worker management")
    app.add_typer(agent_app, name="agent")

    @agent_app.callback(invoke_without_command=True)
    def agent_default(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        if ctx.invoked_subcommand is None:
            c = _load(ctx)
            dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
            raise typer.Exit(code=agent_status(c, dry_run=dr))

    @agent_app.command("start", help="Start the agent worker")
    def agent_start_cmd(
        ctx: typer.Context,
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_start(c, dry_run=dr, foreground=foreground))

    @agent_app.command("stop", help="Stop the agent worker")
    def agent_stop_cmd(
        ctx: typer.Context,
        force: bool = typer.Option(False, "--force", help="Force kill (SIGKILL instead of SIGTERM)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_stop(c, dry_run=dr, force=force))

    @agent_app.command("restart", help="Restart the agent worker (stop then start)")
    def agent_restart_cmd(
        ctx: typer.Context,
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_restart(c, dry_run=dr, foreground=foreground))

    @agent_app.command("rebuild", help="Nuclear reset: stop agent, clear LiveKit rooms, restart agent")
    def agent_rebuild_cmd(
        ctx: typer.Context,
        foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (blocking)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_rebuild(c, dry_run=dr, foreground=foreground))

    @agent_app.command("status", help="Show agent worker status")
    def agent_status_cmd(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_status(c, dry_run=dr))

    @agent_app.command("logs", help="Show agent worker logs")
    def agent_logs_cmd(
        ctx: typer.Context,
        follow: bool = typer.Option(False, "--follow", "-f", help="Follow log output (like tail -f)"),
        lines: int = typer.Option(50, "--lines", "-n", help="Number of lines to show"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        raise typer.Exit(code=agent_logs(c, dry_run=dr, follow=follow, lines=lines))

    # Legacy command for backward compatibility
    @app.command("gui-legacy", hidden=True, help="[DEPRECATED] Use 'marvain gui start --foreground' instead")
    def gui_run_cmd(
        ctx: typer.Context,
        host: str = typer.Option(GUI_DEFAULT_HOST, "--host"),
        port: int = typer.Option(GUI_DEFAULT_PORT, "--port"),
        reload: bool = typer.Option(True, "--reload/--no-reload"),
        stack_prefix: str | None = typer.Option(None, "--stack-prefix"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        _ = stack_prefix  # Unused
        raise typer.Exit(
            code=gui_run(c, dry_run=dr, host=host, port=port, reload=reload, stack_prefix=None)
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


    # ---- members (Hub API) ----
    members_app = typer.Typer(help="Agent membership management (Hub API)")
    app.add_typer(members_app, name="members")

    @members_app.command("claim-owner")
    def members_claim_owner(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id"),
        access_token: str | None = typer.Option(None, "--access-token", help="User access token"),
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
        access_token: str | None = typer.Option(None, "--access-token", help="User access token"),
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
    devices_app = typer.Typer(help="Device token management and detection")
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

    @devices_app.command("detect")
    def devices_detect(
        device_type: str | None = typer.Option(None, "--type", "-t", help="Filter by type: video, audio_input, audio_output, serial"),
        connection_type: str | None = typer.Option(None, "--connection", "-c", help="Filter by connection: usb, direct"),
        output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    ) -> None:
        """Detect USB and direct-attach devices on the local machine.

        Scans for:
        - Video devices (cameras, webcams)
        - Audio input devices (microphones)
        - Audio output devices (speakers)
        - Serial ports (USB-to-serial adapters)
        """
        import json
        from marvain_cli.ops import list_detected_devices

        devices = list_detected_devices(
            device_type=device_type,
            connection_type=connection_type,
            output_format=output_format,
        )

        if output_format == "json":
            typer.echo(json.dumps(devices, indent=2))
        else:
            # Table format
            if not devices:
                typer.echo("No devices detected.")
                raise typer.Exit(code=0)

            # Print header
            typer.echo(f"{'TYPE':<14} {'CONNECTION':<10} {'NAME':<40} {'PATH'}")
            typer.echo("-" * 90)

            for d in devices:
                name = d["name"][:38] + ".." if len(d["name"]) > 40 else d["name"]
                typer.echo(f"{d['device_type']:<14} {d['connection_type']:<10} {name:<40} {d['path']}")

            typer.echo(f"\nTotal: {len(devices)} device(s) detected")

        raise typer.Exit(code=0)

    # ---- members (agent memberships via Hub API) ----
    members_app = typer.Typer(help="Agent membership management (Hub API)")
    app.add_typer(members_app, name="members")

    @members_app.command("invite")
    def members_invite(
        ctx: typer.Context,
        email: str = typer.Option(..., "--email", help="Email of the user to invite"),
        agent_id: str = typer.Option(..., "--agent-id", help="Agent ID to add the user to"),
        role: str = typer.Option("member", "--role", help="Role: owner, admin, member, guest, blocked"),
        relationship_label: str | None = typer.Option(None, "--relationship-label", help="Relationship label (e.g. 'father', 'friend')"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Invite a user to an agent with specified role."""
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

    @members_app.command("list")
    def members_list(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id", help="Agent ID to list members for"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """List users (members) of an agent."""
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

    @members_app.command("update")
    def members_update(
        ctx: typer.Context,
        agent_id: str = typer.Option(..., "--agent-id", help="Agent ID"),
        user_id: str = typer.Option(..., "--user-id", help="User ID to update"),
        role: str = typer.Option(..., "--role", help="New role: owner, admin, member, guest, blocked"),
        relationship_label: str | None = typer.Option(None, "--relationship-label", help="Relationship label (e.g. 'father', 'friend')"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Update a user's role or relationship in an agent."""
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
        agent_id: str = typer.Option(..., "--agent-id", help="Agent ID"),
        user_id: str = typer.Option(..., "--user-id", help="User ID to revoke"),
        access_token: str | None = typer.Option(None, "--access-token", help="Cognito access token"),
        hub_rest_api_base: str | None = typer.Option(None, "--hub-rest-api-base"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Revoke a user's membership from an agent."""
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

    # ---- cognito user management ----
    cognito_app = typer.Typer(help="Cognito user management commands")
    app.add_typer(cognito_app, name="cognito")

    @cognito_app.command("create-user")
    def _cognito_create_user(
        ctx: typer.Context,
        email: str = typer.Argument(..., help="Email address for the new user"),
        password: str = typer.Option(None, "--password", "-p", help="Set permanent password (if not provided, user will need to set on first login)"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Create a new Cognito user."""
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))

        # Create user with temporary password if password is provided
        temp_pw = None
        if password:
            temp_pw = "TempPw123!"  # Cognito requires initial temp password

        user = cognito_create_user(c, email=email, temporary_password=temp_pw, dry_run=dr)

        # If password provided, set it as permanent
        if password and not dr:
            cognito_set_password(c, email=email, password=password, permanent=True, dry_run=dr)

        if not dr:
            typer.echo(json.dumps(user, indent=2, sort_keys=True, default=str))
        raise typer.Exit(code=0)

    @cognito_app.command("set-password")
    def _cognito_set_password(
        ctx: typer.Context,
        email: str = typer.Argument(..., help="Email address of the user"),
        password: str = typer.Argument(..., help="New password"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Set a user's password (makes it permanent)."""
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        cognito_set_password(c, email=email, password=password, permanent=True, dry_run=dr)
        if not dr:
            typer.echo(f"Password set for {email}")
        raise typer.Exit(code=0)

    @cognito_app.command("list-users")
    def _cognito_list_users(
        ctx: typer.Context,
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """List all users in the Cognito User Pool."""
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        users = cognito_list_users(c, dry_run=dr)
        if not dr:
            # Format for display
            for user in users:
                username = user.get("Username", "")
                status = user.get("UserStatus", "")
                attrs = {a["Name"]: a["Value"] for a in user.get("Attributes", [])}
                email = attrs.get("email", username)
                typer.echo(f"{email} (status={status})")
        raise typer.Exit(code=0)

    @cognito_app.command("get-user")
    def _cognito_get_user(
        ctx: typer.Context,
        email: str = typer.Argument(..., help="Email address of the user"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Get details of a specific user."""
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))
        user = cognito_get_user(c, email=email, dry_run=dr)
        if not dr:
            if user:
                typer.echo(json.dumps(user, indent=2, sort_keys=True, default=str))
            else:
                typer.echo(f"User {email} not found", err=True)
                raise typer.Exit(code=1)
        raise typer.Exit(code=0)

    @cognito_app.command("delete-user")
    def _cognito_delete_user(
        ctx: typer.Context,
        email: str = typer.Argument(..., help="Email address of the user to delete"),
        yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
        dry_run: bool = typer.Option(False, "--dry-run", help="Print commands, do not execute"),
    ) -> None:
        """Delete a user from the Cognito User Pool."""
        c = _load(ctx)
        dr = bool(dry_run) or bool(ctx.obj.get("dry_run"))

        if not yes and not dr:
            confirm = typer.confirm(f"Delete user {email}?")
            if not confirm:
                typer.echo("Aborted")
                raise typer.Exit(code=0)

        cognito_delete_user(c, email=email, dry_run=dr)
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
