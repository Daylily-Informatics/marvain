from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cli_core_yo import output
from cli_core_yo.runtime import get_context
from click import ClickException
from typer import Argument, Exit, Option, confirm

from marvain_cli._registry_v2 import (
    EXEMPT,
    EXEMPT_MUTATING_DRY_RUN,
    MARVAIN_AWS_TAG,
    MARVAIN_SAM_TAG,
    register_group_commands,
    register_root_command,
    required_policy,
)
from marvain_cli.config import ConfigError, find_config_path, render_config_yaml, sanitize_name_for_stack
from marvain_cli.ops import (
    GUI_DEFAULT_HOST,
    GUI_DEFAULT_PORT,
    agent_export,
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
    examples_create,
    finalize_agent_worker_deployment,
    gui_logs,
    gui_restart,
    gui_start,
    gui_status,
    gui_stop,
    hub_claim_first_owner,
    hub_grant_membership,
    hub_list_memberships,
    hub_register_device,
    hub_revoke_membership,
    hub_update_membership,
    init_db,
    init_tapdb,
    load_ctx,
    monitor_outputs,
    monitor_status,
    prepare_agent_worker_deployment,
    publish_agent_worker_image,
    read_password_stdin,
    sam_build,
    sam_build_simple,
    sam_deploy,
    sam_logs,
    status,
    teardown,
)

if TYPE_CHECKING:
    from cli_core_yo.registry import CommandRegistry
    from cli_core_yo.spec import CliSpec


def _invocation(name: str) -> str | None:
    value = get_context().invocation.get(name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _config_override() -> str | None:
    explicit = _invocation("config_path")
    if explicit:
        return explicit
    path = get_context().config_path
    if path is None:
        return None
    return str(path) if path.exists() else None


def _dry_run() -> bool:
    return bool(get_context().dry_run)


def _load():
    try:
        return load_ctx(
            config_override=_config_override(),
            env=_invocation("env"),
            profile=_invocation("profile"),
            region=_invocation("region"),
            stack=_invocation("stack"),
        )
    except ConfigError as exc:
        raise ClickException(str(exc)) from exc


def _exit(code: int) -> None:
    raise Exit(code=int(code))


def _json(data: object) -> None:
    if get_context().json_mode:
        output.emit_json(data)
        return
    output.print_text(json.dumps(data, indent=2, sort_keys=True, default=str))


def deployment_inspect(
    target_profile: str = Option(..., "--target-profile", help="Explicit AWS profile for the selected target."),
    target_region: str = Option(..., "--target-region", help="Explicit AWS region for the selected target."),
    stack_name: str | None = Option(None, "--stack-name", help="Exact Marvain stack name, if already selected."),
) -> None:
    """Inspect the selected deployment account and region without changing resources."""
    from marvain_cli.deployment import inspect_target

    try:
        result = inspect_target(profile=target_profile, region=target_region, stack_name=stack_name)
    except ValueError as exc:
        raise ClickException(str(exc)) from exc
    _json(result)
    if result.get("errors"):
        raise Exit(code=1)


def deployment_source_inputs(
    source_config: str = Option(..., "--source-config", help="Absolute path to the source Marvain config."),
    source_env: str = Option(..., "--source-env", help="Explicit source environment."),
    livekit_url_source: str = Option(..., "--livekit-url-source", help="Select parameter_overrides or resources."),
    source_profile: str = Option(..., "--source-profile", help="Explicit source AWS profile."),
    source_region: str = Option(..., "--source-region", help="Explicit source AWS region."),
) -> None:
    """Show selected source secret ARNs and LiveKit URL without secret values."""
    from marvain_cli.deployment import source_inputs
    try:
        _json(source_inputs(source_config=source_config, source_env=source_env, livekit_url_source=livekit_url_source, source_profile=source_profile, source_region=source_region))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_launch_builder(
    public_key: str = Option(..., "--public-key", help="Absolute path to the selected ed25519 public key."),
    ssh_cidr: str = Option(..., "--ssh-cidr", help="Selected operator IPv4 /32."),
) -> None:
    """Create the selected isolated builder and image prerequisites."""
    from marvain_cli.deployment import launch_builder
    try:
        _json(launch_builder(ctx=_load(), public_key_path=public_key, ssh_cidr=ssh_cidr))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_builder_status() -> None:
    """Read the prerequisite stack status and returned builder outputs."""
    from marvain_cli.deployment import builder_status
    try:
        _json(builder_status(ctx=_load()))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_complete_target(
    source_config: str = Option(..., "--source-config"), source_env: str = Option(..., "--source-env"),
    source_profile: str = Option(..., "--source-profile"), source_region: str = Option(..., "--source-region"),
    livekit_url_source: str = Option(..., "--livekit-url-source"),
    worker_desired_count: int = Option(..., "--worker-desired-count"),
) -> None:
    """Complete selected target prerequisites and copy the selected credentials."""
    from marvain_cli.deployment import complete_target
    try:
        _json(complete_target(ctx=_load(), source_config=source_config, source_env=source_env,
                              source_profile=source_profile, source_region=source_region,
                              livekit_url_source=livekit_url_source, worker_desired_count=worker_desired_count))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_publish_image(
    target_profile: str = Option(..., "--target-profile"), target_region: str = Option(..., "--target-region"),
    repository_uri: str = Option(..., "--repository-uri"), release_version: str = Option(..., "--release-version"),
    source_dir: str = Option(..., "--source-dir"), builder_instance_id: str = Option(..., "--builder-instance-id"),
    image_kind: str = Option(..., "--image-kind"),
) -> None:
    """Publish a final tagged worker or dot image on the selected EC2 builder."""
    from marvain_cli.deployment import publish_image
    try:
        _json(publish_image(profile=target_profile, region=target_region, repository_uri=repository_uri,
                            release_version=release_version, source_dir=source_dir,
                            builder_instance_id=builder_instance_id, image_kind=image_kind))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_create_dot_edge() -> None:
    """Create the selected dot edge with its runtime explicitly disabled."""
    from marvain_cli.deployment import deploy_dot_disabled
    try:
        _json(deploy_dot_disabled(ctx=_load()))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_dot_status() -> None:
    """Read the selected dot stack status and outputs."""
    from marvain_cli.deployment import dot_status
    try:
        _json(dot_status(ctx=_load()))
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc


def deployment_set_parameter(
    name: str = Option(..., "--name", help="Parameter declared by the selected SAM template."),
    value: str = Option(..., "--value", help="Explicit non-secret parameter value or secret ARN."),
) -> None:
    """Set one declared SAM deployment parameter in the selected config."""
    from marvain_cli.deployment import set_parameter
    try:
        ctx = _load()
        set_parameter(ctx, name=name, value=value, dry_run=_dry_run())
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc
    output.detail(f"{'Would set' if _dry_run() else 'Set'} {name} in {ctx.config_path}")


def deployment_set_packaging_bucket(
    bucket: str = Option(..., "--bucket", help="Explicit existing SAM packaging bucket name."),
) -> None:
    """Set the SAM packaging bucket in the selected config."""
    from marvain_cli.deployment import set_packaging_bucket
    try:
        ctx = _load()
        set_packaging_bucket(ctx, bucket=bucket, dry_run=_dry_run())
    except (ConfigError, OSError) as exc:
        raise ClickException(str(exc)) from exc
    output.detail(f"{'Would set' if _dry_run() else 'Set'} SAM packaging bucket in {ctx.config_path}")


def config_path() -> None:
    """Print the resolved Marvain config path."""
    path = find_config_path(_config_override())
    if path is None:
        _exit(1)
    output.print_text(str(path))


def config_init(
    write: str | None = Option(None, "--write", help="Write config to this path"),
    env: str = Option("dev", "--env"),
    region: str | None = Option(None, "--region"),
    stack: str | None = Option(None, "--stack"),
) -> None:
    """Create a Marvain config file."""

    def git_user_name() -> str | None:
        try:
            raw = subprocess.check_output(["git", "config", "user.name"], stderr=subprocess.DEVNULL)
        except Exception:
            return None
        text = raw.decode("utf-8").strip()
        return text or None

    if write:
        write_path = Path(write).expanduser().resolve()
    else:
        xdg_home = Path(os.getenv("XDG_CONFIG_HOME") or (Path.home() / ".config")).expanduser()
        write_path = (xdg_home / "marvain" / "marvain-config.yaml").resolve()

    git_name = git_user_name() or os.getenv("USER") or "user"
    suggested_stack = f"marvain-{sanitize_name_for_stack(git_name)}-{env}"
    aws_region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""
    stack_name = stack or suggested_stack

    if not aws_region:
        raise ClickException("--region is required for config init")

    text = render_config_yaml(env=env, aws_region=aws_region, stack_name=stack_name)
    if _dry_run():
        output.detail(f"Would write config: {write_path}")
        output.detail(f"Suggested device_name: {socket.gethostname()}")
        return

    write_path.parent.mkdir(parents=True, exist_ok=True)
    write_path.write_text(text, encoding="utf-8")
    output.print_text(f"Wrote config: {write_path}")
    output.print_text(f"Suggested device_name (bootstrap default): {socket.gethostname()}")


def config_validate() -> None:
    """Validate the active Marvain config."""
    _load()


def config_show() -> None:
    """Show the resolved Marvain config context."""
    ctx = _load()
    _json(
        {
            "aws_profile": ctx.env.aws_profile,
            "aws_region": ctx.env.aws_region,
            "config_path": str(ctx.config_path),
            "env": ctx.env.env,
            "env_config": ctx.env.raw,
            "stack_name": ctx.env.stack_name,
        }
    )


def build() -> None:
    """Build the SAM application."""
    path = find_config_path(_config_override())
    if path is None:
        _exit(sam_build_simple(dry_run=_dry_run(), template="template.yaml"))
    _exit(sam_build(_load(), dry_run=_dry_run()))


def deploy(
    guided: bool = Option(True, "--guided/--no-guided", help="Use SAM guided deploy"),
    no_confirm: bool = Option(False, "--no-confirm", help="Skip changeset confirmation"),
    prebuilt_template: str | None = Option(None, "--prebuilt-template", help="Absolute path to the selected SAM-built template."),
) -> None:
    """Deploy the SAM application."""
    _exit(sam_deploy(_load(), dry_run=_dry_run(), guided=guided, no_confirm=no_confirm,
                     prebuilt_template=prebuilt_template))


def logs(
    function: list[str] = Option([], "--function", "-f", help="Function logical id"),
    tail: bool = Option(True, "--tail/--no-tail", help="Tail logs"),
    since: str | None = Option(None, "--since", help="Since, for example 10m or 1h"),
    output_file: str | None = Option(None, "--output-file", help="Append logs to this file"),
    suppress_sam_warnings: bool = Option(False, "--suppress-sam-warnings"),
) -> None:
    """Show SAM logs."""
    _exit(
        sam_logs(
            _load(),
            dry_run=_dry_run(),
            functions=function or None,
            tail=tail,
            since=since,
            output_file=output_file,
            suppress_sam_warnings=bool(suppress_sam_warnings),
        )
    )


def monitor_outputs_cmd(write_config: bool = Option(False, "--write-config")) -> None:
    """Show CloudFormation outputs."""
    _exit(monitor_outputs(_load(), dry_run=_dry_run(), write_config=write_config))


def monitor_status_cmd() -> None:
    """Show CloudFormation stack status."""
    _exit(monitor_status(_load(), dry_run=_dry_run()))


def status_cmd() -> None:
    """Show deployment status."""
    _exit(status(_load(), dry_run=_dry_run(), output_json=get_context().json_mode))


def teardown_cmd(
    yes: bool = Option(False, "--yes", help="Confirm deletion"),
    wait: bool = Option(True, "--wait/--no-wait", help="Wait for delete completion"),
) -> None:
    """Delete the SAM stack."""
    _exit(teardown(_load(), dry_run=_dry_run(), yes=yes, wait=wait))


def doctor_cmd() -> None:
    """Run Marvain diagnostics."""
    _exit(doctor(_load(), dry_run=_dry_run()))


def gui_start_cmd(
    host: str = Option(GUI_DEFAULT_HOST, "--host", help="Host to bind to"),
    port: int = Option(GUI_DEFAULT_PORT, "--port", help="Port to bind to"),
    reload: bool = Option(True, "--reload/--no-reload", help="Enable auto-reload"),
    foreground: bool = Option(False, "--foreground", "-f", help="Run in foreground"),
    https: bool = Option(True, "--https/--no-https", help="Enable HTTPS"),
    cert: str | None = Option(None, "--cert", help="TLS certificate path"),
    key: str | None = Option(None, "--key", help="TLS private key path"),
) -> None:
    """Start the local GUI server."""
    _exit(
        gui_start(
            _load(),
            dry_run=_dry_run(),
            host=host,
            port=port,
            reload=reload,
            foreground=foreground,
            https=https,
            cert=cert,
            key=key,
        )
    )


def gui_stop_cmd(
    port: int = Option(GUI_DEFAULT_PORT, "--port", help="Port the GUI is running on"),
    force: bool = Option(False, "--force", help="Force kill"),
) -> None:
    """Stop the local GUI server."""
    _exit(gui_stop(_load(), dry_run=_dry_run(), port=port, force=force))


def gui_restart_cmd(
    host: str = Option(GUI_DEFAULT_HOST, "--host", help="Host to bind to"),
    port: int = Option(GUI_DEFAULT_PORT, "--port", help="Port to bind to"),
    reload: bool = Option(True, "--reload/--no-reload", help="Enable auto-reload"),
    foreground: bool = Option(False, "--foreground", "-f", help="Run in foreground"),
    https: bool = Option(True, "--https/--no-https", help="Enable HTTPS"),
    cert: str | None = Option(None, "--cert", help="TLS certificate path"),
    key: str | None = Option(None, "--key", help="TLS private key path"),
) -> None:
    """Restart the local GUI server."""
    _exit(
        gui_restart(
            _load(),
            dry_run=_dry_run(),
            host=host,
            port=port,
            reload=reload,
            foreground=foreground,
            https=https,
            cert=cert,
            key=key,
        )
    )


def gui_status_cmd(port: int = Option(GUI_DEFAULT_PORT, "--port", help="Port to check")) -> None:
    """Show GUI server status."""
    _exit(gui_status(_load(), dry_run=_dry_run(), port=port))


def gui_logs_cmd(
    follow: bool = Option(False, "--follow", "-f", help="Follow log output"),
    lines: int = Option(50, "--lines", "-n", help="Number of lines to show"),
) -> None:
    """Show GUI server logs."""
    _exit(gui_logs(_load(), dry_run=_dry_run(), follow=follow, lines=lines))


def agent_start_cmd(foreground: bool = Option(False, "--foreground", "-f", help="Run in foreground")) -> None:
    """Start the agent worker."""
    _exit(agent_start(_load(), dry_run=_dry_run(), foreground=foreground))


def agent_stop_cmd(force: bool = Option(False, "--force", help="Force kill")) -> None:
    """Stop the agent worker."""
    _exit(agent_stop(_load(), dry_run=_dry_run(), force=force))


def agent_restart_cmd(foreground: bool = Option(False, "--foreground", "-f", help="Run in foreground")) -> None:
    """Restart the agent worker."""
    _exit(agent_restart(_load(), dry_run=_dry_run(), foreground=foreground))


def agent_rebuild_cmd(foreground: bool = Option(False, "--foreground", "-f", help="Run in foreground")) -> None:
    """Reset and restart the agent worker."""
    _exit(agent_rebuild(_load(), dry_run=_dry_run(), foreground=foreground))


def agent_status_cmd() -> None:
    """Show agent worker status."""
    _exit(agent_status(_load(), dry_run=_dry_run()))


def agent_logs_cmd(
    follow: bool = Option(False, "--follow", "-f", help="Follow log output"),
    lines: int = Option(50, "--lines", "-n", help="Number of lines to show"),
) -> None:
    """Show agent worker logs."""
    _exit(agent_logs(_load(), dry_run=_dry_run(), follow=follow, lines=lines))


def agent_export_cmd(
    agent_id: str = Option(..., "--agent-id", help="Agent ID to export"),
    output_path: str | None = Option(None, "--output", "-o", help="Write export JSON to this path"),
) -> None:
    """Export agent-defining backup records."""
    data = agent_export(_load(), agent_id=agent_id, dry_run=_dry_run())
    if output_path is None:
        _json(data)
        return

    path = Path(output_path).expanduser().resolve()
    if path.exists():
        raise ClickException(f"Output path already exists: {path}")
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    if get_context().json_mode:
        output.emit_json(
            {
                "agent_id": data.get("agent_id"),
                "checksum": data.get("checksum"),
                "output_path": str(path),
                "schema": data.get("schema"),
            }
        )
        return
    output.print_text(f"Wrote agent export: {path}")
    output.print_text(f"Checksum: {data.get('checksum')}")


def init_db_cmd(
    sql_file: str | None = Option(
        None,
        "--sql-file",
        help="Use an explicit operator-supplied schema file instead of sql/schema.sql",
    ),
) -> None:
    """Initialize a blank database from the canonical schema."""
    _exit(init_db(_load(), dry_run=_dry_run(), sql_file=sql_file))


def init_tapdb_cmd(overwrite: bool = Option(True, "--overwrite/--no-overwrite")) -> None:
    """Seed Marvain TapDB semantic templates."""
    _exit(init_tapdb(_load(), dry_run=_dry_run(), overwrite=overwrite))


def bootstrap_cmd(
    agent_name: str | None = Option(None, "--agent-name"),
    space_name: str = Option("default", "--space-name"),
    device_name: str | None = Option(None, "--device-name"),
    force: bool = Option(False, "--force"),
    worker_device_token: bool = Option(
        False,
        "--worker-device-token",
        help="Register the token from AgentWorkerHubDeviceTokenSecretArn without exposing it locally",
    ),
) -> None:
    """Bootstrap an agent, space, and device."""
    _exit(
        bootstrap(
            _load(),
            dry_run=_dry_run(),
            agent_name=agent_name,
            space_name=space_name,
            device_name=device_name,
            force=force,
            worker_device_token=worker_device_token,
        )
    )


def agent_prepare_deployment_cmd(
    worker_version: str = Option(..., "--worker-version", help="Immutable source or release identity"),
    image_tag: str | None = Option(None, "--image-tag", help="Explicit immutable ECR tag; defaults to worker version"),
) -> None:
    """Create and configure fresh ECR and worker-token prerequisites."""

    receipt = prepare_agent_worker_deployment(
        _load(),
        dry_run=_dry_run(),
        worker_version=worker_version,
        image_tag=image_tag,
    )
    _json(receipt)


def agent_publish_image_cmd(
    source_commit: str = Option(..., "--source-commit", help="Exact 40-character Git commit SHA to build and publish"),
) -> None:
    """Publish one immutable worker image to the already-configured ECR repository."""

    receipt = publish_agent_worker_image(
        _load(),
        source_commit=source_commit,
        dry_run=_dry_run(),
    )
    _json(receipt)


def agent_finalize_deployment_cmd(
    agent_id: str = Option(..., "--agent-id", help="Configured bootstrap agent ID"),
    device_id: str = Option(..., "--device-id", help="Configured bootstrap worker device ID"),
    cognito_email: str | None = Option(
        None,
        "--cognito-email",
        help="Cognito email used only with --password-stdin",
    ),
    password_stdin: bool = Option(
        False,
        "--password-stdin",
        help="Read a password from stdin or a hidden TTY prompt without storing it",
    ),
    reconcile_only: bool = Option(
        False,
        "--reconcile-only",
        help="Verify an already-rotated worker secret/service and finish local config reconciliation",
    ),
) -> None:
    """Rotate and bind the deployed worker device token without exposing it."""

    receipt = finalize_agent_worker_deployment(
        _load(),
        agent_id=agent_id,
        device_id=device_id,
        access_token=None,
        reconcile_only=reconcile_only,
        dry_run=_dry_run(),
        cognito_email=cognito_email,
        password_stdin=password_stdin,
    )
    _json(receipt)


def members_claim_owner(
    agent_id: str = Option(..., "--agent-id"),
    cognito_email: str | None = Option(
        None,
        "--cognito-email",
        help="Cognito email used only with --password-stdin",
    ),
    password_stdin: bool = Option(
        False,
        "--password-stdin",
        help="Read a password from stdin or a hidden TTY prompt without storing it",
    ),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """Claim first owner membership for an agent."""
    data = hub_claim_first_owner(
        _load(),
        agent_id=agent_id,
        access_token=None,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
        cognito_email=cognito_email,
        password_stdin=password_stdin,
    )
    if not _dry_run():
        _json(data)


def devices_register(
    agent_id: str = Option(..., "--agent-id"),
    name: str | None = Option(None, "--name"),
    scopes: list[str] = Option([], "--scope", help="Repeatable"),
    access_token: str | None = Option(None, "--access-token", help="Cognito access token"),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """Register a device token through the Hub API."""
    data = hub_register_device(
        _load(),
        agent_id=agent_id,
        name=name,
        scopes=(scopes if scopes else None),
        access_token=access_token,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
    )
    if not _dry_run():
        _json(data)


def devices_detect(
    device_type: str | None = Option(None, "--type", "-t", help="Filter device type"),
    connection_type: str | None = Option(None, "--connection", "-c", help="Filter connection"),
    output_format: str = Option("table", "--format", "-f", help="table or json"),
) -> None:
    """Detect USB and direct-attach devices."""
    from marvain_cli.ops import list_detected_devices

    devices = list_detected_devices(
        device_type=device_type, connection_type=connection_type, output_format=output_format
    )
    if output_format == "json":
        output.print_text(json.dumps(devices, indent=2))
        return
    if not devices:
        output.print_text("No devices detected.")
        return
    output.print_text(f"{'TYPE':<14} {'CONNECTION':<10} {'NAME':<40} {'PATH'}")
    output.print_text("-" * 90)
    for item in devices:
        name = item["name"][:38] + ".." if len(item["name"]) > 40 else item["name"]
        output.print_text(f"{item['device_type']:<14} {item['connection_type']:<10} {name:<40} {item['path']}")
    output.print_text(f"\nTotal: {len(devices)} device(s) detected")


def members_invite(
    email: str = Option(..., "--email", help="Email of the user to invite"),
    agent_id: str = Option(..., "--agent-id", help="Agent ID"),
    role: str = Option("member", "--role", help="Role"),
    relationship_label: str | None = Option(None, "--relationship-label"),
    access_token: str | None = Option(None, "--access-token", help="Cognito access token"),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """Invite a user to an agent."""
    data = hub_grant_membership(
        _load(),
        agent_id=agent_id,
        email=email,
        role=role,
        relationship_label=relationship_label,
        access_token=access_token,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
    )
    if not _dry_run():
        _json(data)


def members_list(
    agent_id: str = Option(..., "--agent-id", help="Agent ID"),
    cognito_email: str | None = Option(
        None,
        "--cognito-email",
        help="Cognito email used only with --password-stdin",
    ),
    password_stdin: bool = Option(
        False,
        "--password-stdin",
        help="Read a password from stdin or a hidden TTY prompt without storing it",
    ),
    owner_count_only: bool = Option(
        False,
        "--owner-count-only",
        help="Return only the active owner-membership count",
    ),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """List agent members."""
    data = hub_list_memberships(
        _load(),
        agent_id=agent_id,
        access_token=None,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
        cognito_email=cognito_email,
        password_stdin=password_stdin,
    )
    if not _dry_run():
        if not owner_count_only:
            _json(data)
            return
        memberships = data.get("memberships")
        if not isinstance(memberships, list):
            raise ClickException("Membership response did not contain a memberships list")
        if not all(isinstance(item, dict) for item in memberships):
            raise ClickException("Membership response contained a non-object membership")
        _json({"active_owner_memberships": sum(1 for item in memberships if item.get("role") == "owner")})


def members_update(
    agent_id: str = Option(..., "--agent-id", help="Agent ID"),
    user_id: str = Option(..., "--user-id", help="User ID"),
    role: str = Option(..., "--role", help="New role"),
    relationship_label: str | None = Option(None, "--relationship-label"),
    access_token: str | None = Option(None, "--access-token", help="Cognito access token"),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """Update an agent member."""
    data = hub_update_membership(
        _load(),
        agent_id=agent_id,
        user_id=user_id,
        role=role,
        relationship_label=relationship_label,
        access_token=access_token,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
    )
    if not _dry_run():
        _json(data)


def members_revoke(
    agent_id: str = Option(..., "--agent-id", help="Agent ID"),
    user_id: str = Option(..., "--user-id", help="User ID"),
    access_token: str | None = Option(None, "--access-token", help="Cognito access token"),
    hub_rest_api_base: str | None = Option(None, "--hub-rest-api-base"),
) -> None:
    """Revoke an agent member."""
    data = hub_revoke_membership(
        _load(),
        agent_id=agent_id,
        user_id=user_id,
        access_token=access_token,
        hub_rest_api_base=hub_rest_api_base,
        dry_run=_dry_run(),
    )
    if not _dry_run():
        _json(data)


def cognito_create_user_cmd(
    email: str = Argument(..., help="Email address for the new user"),
    password_stdin: bool = Option(
        False,
        "--password-stdin",
        help="Read a password from stdin or a hidden TTY prompt without storing it",
    ),
) -> None:
    """Create a Cognito user."""
    ctx = _load()
    password = "dry-run-password" if password_stdin and _dry_run() else None
    if password_stdin and not _dry_run():
        password = read_password_stdin()
    user = cognito_create_user(ctx, email=email, temporary_password=None, dry_run=_dry_run())
    if password is not None:
        cognito_set_password(ctx, email=email, password=password, permanent=True, dry_run=_dry_run())
    if not _dry_run():
        _json(user)


def cognito_set_password_cmd(
    email: str = Argument(..., help="Email address of the user"),
    password_stdin: bool = Option(
        False,
        "--password-stdin",
        help="Read a password from stdin or a hidden TTY prompt without storing it",
    ),
) -> None:
    """Set a Cognito user's password."""
    if not password_stdin:
        raise ClickException("cognito set-password requires --password-stdin")
    password = "dry-run-password" if _dry_run() else read_password_stdin()
    cognito_set_password(_load(), email=email, password=password, permanent=True, dry_run=_dry_run())
    if not _dry_run():
        output.print_text(f"Password set for {email}")


def cognito_list_users_cmd() -> None:
    """List Cognito users."""
    users = cognito_list_users(_load(), dry_run=_dry_run())
    if _dry_run():
        return
    if get_context().json_mode:
        output.emit_json(users)
        return
    for user in users:
        username = user.get("Username", "")
        status_value = user.get("UserStatus", "")
        attrs = {item["Name"]: item["Value"] for item in user.get("Attributes", [])}
        email = attrs.get("email", username)
        output.print_text(f"{email} (status={status_value})")


def cognito_get_user_cmd(email: str = Argument(..., help="Email address of the user")) -> None:
    """Get a Cognito user."""
    user = cognito_get_user(_load(), email=email, dry_run=_dry_run())
    if _dry_run():
        return
    if user:
        _json(user)
        return
    output.error(f"User {email} not found")
    _exit(1)


def cognito_delete_user_cmd(
    email: str = Argument(..., help="Email address of the user to delete"),
    yes: bool = Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Delete a Cognito user."""
    if not yes and not _dry_run():
        if not confirm(f"Delete user {email}?"):
            output.print_text("Aborted")
            return
    cognito_delete_user(_load(), email=email, dry_run=_dry_run())


def examples_create_cmd(
    agent_name: str = Option("example-agent", "--agent-name", help="Example agent name"),
    space_name: str = Option("example-space", "--space-name", help="Example space name"),
    device_name: str | None = Option(None, "--device-name", help="Device name"),
    seed_memories: bool = Option(True, "--seed-memories/--no-seed-memories", help="Seed example memories"),
) -> None:
    """Create a reference example agent, space, and device."""
    _exit(
        examples_create(
            _load(),
            dry_run=_dry_run(),
            agent_name=agent_name,
            space_name=space_name,
            device_name=device_name,
            seed_memories=seed_memories,
        )
    )


def test_cmd() -> None:
    """Run the local unit test suite."""
    cmd = [sys.executable, "-m", "pytest"]
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    pythonpath_parts = [str(repo_root), str(shared)]
    old_pythonpath = os.environ.get("PYTHONPATH")
    if old_pythonpath:
        pythonpath_parts.append(old_pythonpath)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
    if _dry_run():
        output.print_text(f"$ PYTHONPATH={env['PYTHONPATH']} " + " ".join(cmd))
        return
    _exit(int(subprocess.call(cmd, cwd=str(repo_root), env=env)))


def recognition_install_service_cmd(
    python_executable: str = Option(..., "--python-executable", help="Absolute Python 3.12 executable path"),
    worker_source: str = Option(..., "--worker-source", help="Absolute recognition worker.py path"),
    wheelhouse: str = Option(..., "--wheelhouse", help="Absolute offline wheelhouse directory"),
    package_version: str = Option(..., "--package-version", help="Exact Marvain package version"),
    environment_source: str = Option(..., "--environment-source", help="Absolute populated environment file"),
    model_manifest_source: str = Option(..., "--model-manifest-source", help="Absolute pinned model manifest"),
    unit_source: str = Option(..., "--unit-source", help="Absolute checked-in systemd unit path"),
) -> None:
    """Install the recognition worker service on an Amazon Linux 2023 host."""
    from marvain_cli.recognition_service import RecognitionInstallSpec, install_command_plan, run_install

    spec = RecognitionInstallSpec(
        service_user="marvain-recognition",
        service_group="marvain-recognition",
        unit_name="marvain-recognition.service",
        python_executable=Path(python_executable),
        install_root=Path("/opt/marvain-recognition"),
        worker_source=Path(worker_source),
        wheelhouse=Path(wheelhouse),
        package_version=package_version,
        environment_source=Path(environment_source),
        environment_destination=Path("/etc/marvain/recognition.env"),
        model_manifest_source=Path(model_manifest_source),
        model_manifest_destination=Path("/etc/marvain/recognition-models.json"),
        unit_source=Path(unit_source),
        unit_destination=Path("/etc/systemd/system/marvain-recognition.service"),
        health_path=Path("/var/lib/marvain-recognition/health.json"),
    ).validate()
    if _dry_run():
        _json({"dry_run": True, "commands": install_command_plan(spec, create_user=True, create_group=True)})
        return
    results = run_install(spec)
    _json({"installed": True, "commands_completed": len(results), "unit_name": spec.unit_name})


def _recognition_control(action: str) -> None:
    from marvain_cli.recognition_service import control_command

    command = control_command(action=action, unit_name="marvain-recognition.service")
    if _dry_run():
        _json({"dry_run": True, "command": command})
        return
    subprocess.run(command, check=True)
    _json({"ok": True, "action": action, "unit_name": "marvain-recognition.service"})


def recognition_start_cmd() -> None:
    """Start the recognition service."""
    _recognition_control("start")


def recognition_stop_cmd() -> None:
    """Stop the recognition service."""
    _recognition_control("stop")


def recognition_restart_cmd() -> None:
    """Restart the recognition service."""
    _recognition_control("restart")


def recognition_status_cmd() -> None:
    """Report systemd and worker-health state."""
    from marvain_cli.recognition_service import run_commands, status_commands

    commands = status_commands(
        unit_name="marvain-recognition.service",
        health_path=Path("/var/lib/marvain-recognition/health.json"),
    )
    if _dry_run():
        _json({"dry_run": True, "commands": commands})
        return
    results = run_commands(commands)
    _json(
        {
            "unit": results[0].stdout,
            "health": json.loads(results[1].stdout),
        }
    )


def recognition_logs_cmd(
    lines: int = Option(200, "--lines", min=1, help="Journal lines to return"),
    follow: bool = Option(False, "--follow", help="Follow the journal"),
) -> None:
    """Read recognition service logs."""
    from marvain_cli.recognition_service import logs_command

    command = logs_command(unit_name="marvain-recognition.service", lines=lines, follow=follow)
    if _dry_run():
        _json({"dry_run": True, "command": command})
        return
    _exit(subprocess.call(command))


def register(registry: CommandRegistry, spec: CliSpec) -> None:
    _ = spec
    register_group_commands(
        registry,
        "deployment",
        "Read-only deployment target inspection.",
        [
            ("inspect", deployment_inspect, required_policy(supports_json=True)),
            ("source-inputs", deployment_source_inputs, required_policy(supports_json=True)),
            ("launch-builder", deployment_launch_builder, required_policy(mutates_state=True)),
            ("builder-status", deployment_builder_status, required_policy(supports_json=True)),
            ("complete-target", deployment_complete_target, required_policy(mutates_state=True)),
            ("publish-image", deployment_publish_image, required_policy(mutates_state=True, long_running=True, supports_json=True)),
            ("create-dot-edge", deployment_create_dot_edge, required_policy(mutates_state=True, supports_json=True)),
            ("dot-status", deployment_dot_status, required_policy(supports_json=True)),
            ("set-parameter", deployment_set_parameter, required_policy(mutates_state=True, supports_dry_run=True)),
            ("set-packaging-bucket", deployment_set_packaging_bucket, required_policy(mutates_state=True, supports_dry_run=True)),
        ],
    )
    register_group_commands(
        registry,
        "config",
        "Configuration management.",
        [
            ("path", config_path, EXEMPT),
            ("init", config_init, EXEMPT_MUTATING_DRY_RUN),
            ("validate", config_validate, required_policy()),
            ("show", config_show, required_policy(supports_json=True)),
        ],
    )
    register_root_command(
        registry,
        "build",
        build,
        required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_SAM_TAG}),
    )
    register_root_command(
        registry,
        "deploy",
        deploy,
        required_policy(
            mutates_state=True,
            supports_dry_run=True,
            interactive=True,
            prereq_tags={MARVAIN_SAM_TAG},
        ),
    )
    register_root_command(
        registry,
        "logs",
        logs,
        required_policy(mutates_state=True, supports_dry_run=True, long_running=True, prereq_tags={MARVAIN_SAM_TAG}),
    )
    register_root_command(
        registry,
        "status",
        status_cmd,
        required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
    )
    register_root_command(
        registry,
        "teardown",
        teardown_cmd,
        required_policy(
            mutates_state=True,
            supports_dry_run=True,
            interactive=True,
            prereq_tags={MARVAIN_AWS_TAG},
        ),
    )
    register_root_command(
        registry,
        "doctor",
        doctor_cmd,
        required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG, MARVAIN_SAM_TAG}),
    )
    register_root_command(
        registry,
        "bootstrap",
        bootstrap_cmd,
        required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
    )
    register_root_command(
        registry,
        "test",
        test_cmd,
        required_policy(mutates_state=True, supports_dry_run=True),
    )
    from marvain_cli.smoke import smoke_gui_guide_cmd, smoke_v1_dev_cmd, smoke_v1_local_cmd

    register_group_commands(
        registry,
        "smoke",
        "V1 runtime smoke commands.",
        [
            ("v1-local", smoke_v1_local_cmd, required_policy(supports_json=True)),
            ("v1-dev", smoke_v1_dev_cmd, required_policy(supports_json=True, prereq_tags={MARVAIN_AWS_TAG})),
            ("gui-guide", smoke_gui_guide_cmd, required_policy(supports_json=True)),
        ],
    )
    from marvain_cli.dot import serve_cmd as dot_serve_cmd

    register_group_commands(
        registry,
        "dot",
        "Dedicated dot MCP service.",
        [("serve", dot_serve_cmd, required_policy(mutates_state=True, long_running=True))],
    )
    from marvain_cli.simulate import two_devices_cmd

    register_group_commands(
        registry,
        "simulate",
        "Local deterministic simulation reports.",
        [
            ("two-devices", two_devices_cmd, required_policy(supports_json=True)),
        ],
    )
    from marvain_cli.failure import inject_cmd

    register_group_commands(
        registry,
        "failure",
        "Local deterministic failure-injection reports.",
        [
            ("inject", inject_cmd, required_policy(supports_json=True)),
        ],
    )
    register_group_commands(
        registry,
        "monitor",
        "Monitoring helpers.",
        [
            (
                "outputs",
                monitor_outputs_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "status",
                monitor_status_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
        ],
    )
    register_group_commands(
        registry,
        "gui",
        "Local GUI server management.",
        [
            ("start", gui_start_cmd, required_policy(mutates_state=True, supports_dry_run=True, long_running=True)),
            ("stop", gui_stop_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("restart", gui_restart_cmd, required_policy(mutates_state=True, supports_dry_run=True, long_running=True)),
            ("status", gui_status_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("logs", gui_logs_cmd, required_policy(mutates_state=True, supports_dry_run=True, long_running=True)),
        ],
    )
    register_group_commands(
        registry,
        "agent",
        "Agent worker management.",
        [
            (
                "publish-image",
                agent_publish_image_cmd,
                required_policy(
                    supports_json=True,
                    mutates_state=True,
                    supports_dry_run=True,
                    long_running=True,
                    prereq_tags={MARVAIN_AWS_TAG},
                ),
            ),
            (
                "prepare-deployment",
                agent_prepare_deployment_cmd,
                required_policy(
                    supports_json=True,
                    mutates_state=True,
                    supports_dry_run=True,
                    long_running=True,
                    prereq_tags={MARVAIN_AWS_TAG},
                ),
            ),
            (
                "finalize-deployment",
                agent_finalize_deployment_cmd,
                required_policy(
                    supports_json=True,
                    mutates_state=True,
                    supports_dry_run=True,
                    long_running=True,
                    prereq_tags={MARVAIN_AWS_TAG},
                ),
            ),
            ("start", agent_start_cmd, required_policy(mutates_state=True, supports_dry_run=True, long_running=True)),
            ("stop", agent_stop_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            (
                "restart",
                agent_restart_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, long_running=True),
            ),
            (
                "rebuild",
                agent_rebuild_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, long_running=True),
            ),
            ("status", agent_status_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("logs", agent_logs_cmd, required_policy(mutates_state=True, supports_dry_run=True, long_running=True)),
            ("export", agent_export_cmd, required_policy(supports_json=True, prereq_tags={MARVAIN_AWS_TAG})),
            ("backup", agent_export_cmd, required_policy(supports_json=True, prereq_tags={MARVAIN_AWS_TAG})),
        ],
    )
    register_group_commands(
        registry,
        "recognition",
        "Recognition worker service management.",
        [
            (
                "install-service",
                recognition_install_service_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, interactive=True),
            ),
            ("start", recognition_start_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("stop", recognition_stop_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("restart", recognition_restart_cmd, required_policy(mutates_state=True, supports_dry_run=True)),
            ("status", recognition_status_cmd, required_policy(supports_json=True)),
            (
                "logs",
                recognition_logs_cmd,
                required_policy(long_running=True),
            ),
        ],
    )
    register_group_commands(
        registry,
        "init",
        "Initialization helpers.",
        [
            (
                "db",
                init_db_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "tapdb",
                init_tapdb_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
        ],
    )
    register_group_commands(
        registry,
        "members",
        "Agent membership management.",
        [
            (
                "claim-owner",
                members_claim_owner,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "invite",
                members_invite,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "list",
                members_list,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "update",
                members_update,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "revoke",
                members_revoke,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
        ],
    )
    register_group_commands(
        registry,
        "devices",
        "Device token management and detection.",
        [
            (
                "register",
                devices_register,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            ("detect", devices_detect, required_policy()),
        ],
    )
    register_group_commands(
        registry,
        "cognito",
        "Cognito user management commands.",
        [
            (
                "create-user",
                cognito_create_user_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            (
                "set-password",
                cognito_set_password_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            ),
            ("list-users", cognito_list_users_cmd, required_policy(supports_json=True, prereq_tags={MARVAIN_AWS_TAG})),
            ("get-user", cognito_get_user_cmd, required_policy(supports_json=True, prereq_tags={MARVAIN_AWS_TAG})),
            (
                "delete-user",
                cognito_delete_user_cmd,
                required_policy(
                    mutates_state=True,
                    supports_dry_run=True,
                    interactive=True,
                    prereq_tags={MARVAIN_AWS_TAG},
                ),
            ),
        ],
    )
    register_group_commands(
        registry,
        "examples",
        "Example configuration management.",
        [
            (
                "create",
                examples_create_cmd,
                required_policy(mutates_state=True, supports_dry_run=True, prereq_tags={MARVAIN_AWS_TAG}),
            )
        ],
    )
