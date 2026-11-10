"""Explicit operator workflow for the selected hosted browser activation."""
from __future__ import annotations

import json
from uuid import uuid4
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import boto3

from marvain_cli.config import ConfigError, save_config_dict
from marvain_cli.ops import aws_stack_outputs


def browser_activation(ctx, *, phase: str, agent_id: str | None, owner_email: str | None,
                       space_name: str | None, person_name: str | None) -> dict:
    if phase not in {"prepare", "status", "bind", "worker-status"}:
        raise ConfigError("phase must be prepare, status, bind or worker-status")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    secrets = session.client("secretsmanager")
    outputs = aws_stack_outputs(ctx, dry_run=False)
    if phase == "worker-status":
        response = session.client("ecs").describe_services(cluster=outputs["AgentWorkerClusterName"],
                                                           services=[outputs["AgentWorkerServiceName"]])
        if response.get("failures") or len(response.get("services", [])) != 1:
            raise ConfigError("Selected ECS worker service was not returned")
        service = response["services"][0]
        logs = session.client("logs").filter_log_events(logGroupName=outputs["AgentWorkerLogGroupName"],
            filterPattern='"registered worker"', limit=5)
        return {"service": service["serviceName"], "desired": service["desiredCount"], "running": service["runningCount"],
                "pending": service["pendingCount"], "registrations": [event["message"] for event in logs["events"]]}
    env = ctx.cfg["envs"][ctx.env.env]
    params = env["sam"]["parameter_overrides"]
    secret = json.loads(secrets.get_secret_value(SecretId=outputs["AdminApiKeySecretArn"])["SecretString"])
    admin_key = secret["admin_api_key"]

    def request(method, path, payload=None):
        req = Request(outputs["HubRestApiBase"].rstrip("/") + path, method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"X-Admin-Key": admin_key, "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=60) as response:
                return json.load(response)
        except HTTPError as exc:
            # Never print request payloads: preparation contains the worker token.
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(raw).get("detail", "Request failed")
                if isinstance(detail, list):
                    detail = [{"loc": item.get("loc"), "msg": item.get("msg")} for item in detail]
            except (ValueError, AttributeError):
                detail = "Non-JSON error response"
            raise ConfigError(f"Browser activation HTTP {exc.code}: {detail}") from exc

    if phase == "prepare":
        if not all((agent_id, owner_email, space_name, person_name)):
            raise ConfigError("prepare requires explicit agent ID, owner email, space name and person name")
        intent = {"agent_id": agent_id, "owner_email": owner_email, "space_name": space_name,
                  "person_name": person_name, "room_mode": "stable", "retention": "retain_until_revoked",
                  "raw_capture_allowed": True, "audience": "owner_and_agent"}
        saved = env.get("browser_activation")
        if saved is None:
            saved = {**intent, "operation_id": str(uuid4())}
            env["browser_activation"] = saved
            save_config_dict(ctx.config_path, ctx.cfg)
        elif any(saved.get(key) != value for key, value in intent.items()):
            raise ConfigError("The selected activation differs from the persisted operation; do not overwrite it")
        worker = json.loads(secrets.get_secret_value(SecretId=params["AgentWorkerHubDeviceTokenSecretArn"])["SecretString"])
        return request("POST", "/v1/admin/browser-activation", {**saved, "worker_device_token": worker["device_token"]})
    saved = env.get("browser_activation")
    if not saved or not saved.get("operation_id"):
        raise ConfigError("Prepare the selected browser activation first")
    result = request("GET", "/v1/admin/browser-activation/" + saved["operation_id"])
    if phase == "status" or result["status"] != "written":
        return result
    if phase != "bind":
        raise ConfigError("phase must be prepare, status or bind")
    arn = params["MarvainV4BindingsSecretArn"]
    bindings = json.loads(secrets.get_secret_value(SecretId=arn)["SecretString"])
    if not isinstance(bindings, dict):
        raise ConfigError("Binding secret must be a JSON object")
    identities = {"routes": ("device_id", "agent_id", "space_id"), "callers": ("device_id", "agent_id"),
                  "humans": ("user_id", "subject"), "browsers": ("user_id", "subject", "agent_id", "space_id")}
    for group, additions in result["bindings"].items():
        current = bindings.setdefault(group, [])
        if not isinstance(current, list):
            raise ConfigError(f"{group} bindings must be an array")
        for item in additions:
            matches = [old for old in current if all(old.get(key) == item[key] for key in identities[group])]
            if matches and (len(matches) != 1 or matches[0] != item):
                raise ConfigError(f"Existing {group} binding conflicts; explicit reconciliation is required")
            if not matches:
                current.append(item)
    write = secrets.put_secret_value(SecretId=arn, SecretString=json.dumps(bindings))
    env["bootstrap"] = {"agent_id": result["agent_id"], "space_id": result["space_id"],
                        "device_id": result["worker_device_id"],
                        "device_token_secret_arn": params["AgentWorkerHubDeviceTokenSecretArn"]}
    params["AgentWorkerDesiredCount"] = "1"
    save_config_dict(ctx.config_path, ctx.cfg)
    return {"status": "bound", "operation_id": saved["operation_id"], "space_id": result["space_id"],
            "bindings_secret_version": write["VersionId"], "configured_worker_count": 1,
            "next": "Deploy the selected tagged template to apply worker desired count"}
