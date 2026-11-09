"""Read-only inspection of an explicitly selected Marvain deployment target."""
from __future__ import annotations

from typing import Any
import re
from pathlib import Path

from marvain_cli.config import ConfigError, save_config_dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError


_REQUIRED_SOURCE_PARAMETERS = (
    "LiveKitUrl", "OpenAICredentialsSecretArn", "LiveKitCredentialsSecretArn",
    "AgentWorkerImageUri", "AgentWorkerVersion", "AgentWorkerHubDeviceTokenSecretArn",
    "AgentWorkerDesiredCount", "ArtifactCorsAllowedOrigins", "MarvainV4BindingsSecretArn", "OpenAIEmbedModel",
    "DotEventsMode", "DotEventsSecretArn",
)


def inspect_target(*, profile: str, region: str, stack_name: str | None) -> dict[str, Any]:
    """Inspect only the selected account and region; never fetch secret values."""
    if profile != "lsmc" or region != "us-east-2":
        raise ValueError("This inspection requires explicit target profile lsmc and region us-east-2")
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
    except BotoCoreError as exc:
        raise ValueError(f"Cannot initialize selected AWS profile: {type(exc).__name__}") from exc
    result: dict[str, Any] = {"profile": profile, "region": region, "required_sam_parameters": _REQUIRED_SOURCE_PARAMETERS}
    errors: dict[str, str] = {}

    def capture(label: str, operation: Any) -> None:
        try:
            result[label] = operation()
        except (ClientError, BotoCoreError) as exc:
            code = exc.response.get("Error", {}).get("Code", type(exc).__name__) if isinstance(exc, ClientError) else type(exc).__name__
            errors[label] = str(code)

    def identity() -> dict[str, str]:
        caller = session.client("sts").get_caller_identity()
        return {"account": caller["Account"], "arn": caller["Arn"]}

    def region_state() -> dict[str, str]:
        response = session.client("ec2").describe_regions(RegionNames=[region], AllRegions=True)
        selected = response["Regions"][0]
        return {"region": selected["RegionName"], "opt_in_status": selected.get("OptInStatus", "unknown")}

    def instances(*, cluster: bool) -> list[dict[str, str]]:
        filters = [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
        filters.append({"Name": "tag-key", "Values": ["parallelcluster:cluster-name"]} if cluster else
                       {"Name": "tag:Name", "Values": ["*build*", "*Build*", "*deploy*", "*Deploy*"]})
        rows = []
        for page in session.client("ec2").get_paginator("describe_instances").paginate(Filters=filters):
            for reservation in page.get("Reservations", []):
                for item in reservation.get("Instances", []):
                    tags = {tag["Key"]: tag["Value"] for tag in item.get("Tags", [])}
                    rows.append({"instance_id": item["InstanceId"], "state": item["State"]["Name"],
                                 "instance_type": item["InstanceType"], "name": tags.get("Name", ""),
                                 "parallelcluster": tags.get("parallelcluster:cluster-name", "")})
        return rows

    def secrets_metadata() -> list[dict[str, str]]:
        found: dict[str, dict[str, str]] = {}
        for term in ("marvain", "openai", "livekit"):
            pages = session.client("secretsmanager").get_paginator("list_secrets").paginate(
                Filters=[{"Key": "name", "Values": [term]}]
            )
            for page in pages:
                for item in page.get("SecretList", []):
                    if "DeletedDate" not in item:
                        found[item["ARN"]] = {"name": item["Name"], "arn": item["ARN"]}
        return list(found.values())

    def exact_stack() -> dict[str, str]:
        selected = session.client("cloudformation").describe_stacks(StackName=stack_name)["Stacks"][0]
        return {"name": selected["StackName"], "status": selected["StackStatus"], "stack_id": selected["StackId"]}

    capture("identity", identity)
    capture("region_status", region_state)
    capture("parallelcluster_tagged_instances", lambda: instances(cluster=True))
    capture("builder_name_candidates", lambda: instances(cluster=False))
    capture("matching_secret_metadata", secrets_metadata)
    if stack_name:
        capture("exact_stack", exact_stack)
    result["inspection_limits"] = [
        "ParallelCluster detection covers EC2 instances with the parallelcluster:cluster-name tag, not all DYEC history.",
        "Builder candidates are name-filtered and do not establish authorization, software, or availability.",
        "Secret search covers name prefixes marvain, openai, or livekit; it does not read secret values.",
    ]
    if errors:
        result["errors"] = errors
    return result


def set_parameter(ctx: Any, *, name: str, value: str, dry_run: bool) -> None:
    """Set exactly one declared SAM parameter without printing its value."""
    sam = ctx.env.raw.get("sam")
    if not isinstance(sam, dict) or not isinstance(sam.get("parameter_overrides"), dict):
        raise ConfigError("Selected environment requires sam.parameter_overrides mapping")
    template_path = Path(str(sam.get("template") or "template.yaml"))
    if not template_path.is_absolute():
        template_path = Path(__file__).resolve().parents[1] / template_path
    text = template_path.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^Parameters:\s*\n(.*?)(?=^[A-Za-z][A-Za-z0-9]*:\s*(?:\n|$))", text)
    if match is None:
        raise ConfigError("SAM template has no Parameters section")
    names = set(re.findall(r"(?m)^  ([A-Za-z][A-Za-z0-9]*):\s*$", match.group(1)))
    if name not in names:
        raise ConfigError("Parameter is not declared by the selected SAM template")
    if not value.strip():
        raise ConfigError("Parameter value is required")
    if "SecretArn" in name and not re.fullmatch(r"arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:.+", value):
        raise ConfigError("Secret ARN parameter requires a Secrets Manager ARN, not credential material")
    if not dry_run:
        sam["parameter_overrides"][name] = value
        save_config_dict(ctx.config_path, ctx.cfg)


def set_packaging_bucket(ctx: Any, *, bucket: str, dry_run: bool) -> None:
    """Set the selected environment's explicit SAM packaging bucket."""
    sam = ctx.env.raw.get("sam")
    if not isinstance(sam, dict):
        raise ConfigError("Selected environment requires a sam mapping")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        raise ConfigError("A valid explicit S3 bucket name is required")
    if not dry_run:
        sam["s3_bucket"] = bucket
        save_config_dict(ctx.config_path, ctx.cfg)


def source_inputs(*, source_config: str, source_env: str, livekit_url_source: str, source_profile: str, source_region: str) -> dict[str, Any]:
    """Expose only selected non-secret source references for target preparation."""
    from marvain_cli.config import load_config_dict

    path = Path(source_config)
    if not path.is_absolute():
        raise ConfigError("source_config must be an absolute path")
    env = load_config_dict(path).get("envs", {}).get(source_env)
    if not isinstance(env, dict):
        raise ConfigError("source environment is not configured")
    sam = env.get("sam")
    params = sam.get("parameter_overrides") if isinstance(sam, dict) else None
    if not isinstance(params, dict):
        raise ConfigError("source SAM parameter overrides are not configured")
    keys = ("OpenAICredentialsSecretArn", "LiveKitCredentialsSecretArn", "LiveKitUrl")
    if livekit_url_source not in {"parameter_overrides", "resources"}:
        raise ConfigError("livekit_url_source must explicitly select parameter_overrides or resources")
    url_data = params if livekit_url_source == "parameter_overrides" else env.get("resources")
    if not isinstance(url_data, dict):
        raise ConfigError("selected LiveKit URL source is not configured")
    selected = {key: str(params.get(key) or "").strip() for key in keys[:2]}
    selected["LiveKitUrl"] = str(url_data.get("LiveKitUrl") or "").strip()
    missing = [key for key, value in selected.items() if not value]
    if missing:
        raise ConfigError("source config lacks explicit references: " + ", ".join(missing))
    for key in keys[:2]:
        if not re.fullmatch(r"arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:.+", selected[key]):
            raise ConfigError(f"{key} is not a Secrets Manager ARN")
    profile, region = source_profile.strip(), source_region.strip()
    if not profile or profile == "default" or not region:
        raise ConfigError("source profile and region must be explicitly selected")
    return {"config_path": str(path), "environment": source_env, "profile": profile, "region": region, **selected}


def launch_builder(*, ctx: Any, public_key_path: str, ssh_cidr: str) -> dict[str, str]:
    """Create the explicitly selected, isolated builder prerequisites without rollback."""
    import ipaddress

    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Builder target must explicitly be profile lsmc in us-east-2")
    key_path = Path(public_key_path)
    if not key_path.is_absolute():
        raise ConfigError("public key path must be absolute")
    public_key = key_path.read_text(encoding="utf-8").strip()
    if not public_key.startswith("ssh-ed25519 "):
        raise ConfigError("the selected builder key must be an ed25519 public key")
    try:
        network = ipaddress.ip_network(ssh_cidr, strict=True)
    except ValueError as exc:
        raise ConfigError("SSH access must be an explicit IPv4 /32") from exc
    if network.version != 4 or network.prefixlen != 32:
        raise ConfigError("SSH access must be an explicit IPv4 /32")
    env = ctx.env.raw
    deployment = env.setdefault("deployment", {})
    if not isinstance(deployment, dict):
        raise ConfigError("environment deployment field must be a mapping")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    account = session.client("sts").get_caller_identity()["Account"]
    stack_name = f"{ctx.env.stack_name}-release-prerequisites"
    role_arn = f"arn:aws:iam::{account}:role/{stack_name}-builder-role"
    root = Path(__file__).resolve().parents[1]
    user_data = (root / "infrastructure" / "builder_bootstrap.sh").read_text(encoding="utf-8").replace(
        "__BUILDER_ROLE_ARN__", role_arn
    )
    image_id = session.client("ssm").get_parameter(
        Name="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
    )["Parameter"]["Value"]
    response = session.client("cloudformation").create_stack(
        StackName=stack_name,
        TemplateBody=(root / "infrastructure" / "deployment_prerequisites.yaml").read_text(encoding="utf-8"),
        Parameters=[{"ParameterKey": "BuilderImageId", "ParameterValue": image_id},
                    {"ParameterKey": "BuilderPublicKey", "ParameterValue": public_key},
                    {"ParameterKey": "BuilderSshCidr", "ParameterValue": str(network)},
                    {"ParameterKey": "BuilderUserData", "ParameterValue": user_data}],
        Capabilities=["CAPABILITY_NAMED_IAM"], DisableRollback=True,
        Tags=[{"Key": "project", "Value": "marvain"}],
    )
    env["aws_profile"], env["aws_region"] = ctx.env.aws_profile, ctx.env.aws_region
    deployment["prerequisite_stack_name"] = stack_name
    deployment["prerequisite_stack_id"] = response["StackId"]
    save_config_dict(ctx.config_path, ctx.cfg)
    return {"stack_name": stack_name, "stack_id": response["StackId"], "status": "create_submitted",
            "config_path": str(ctx.config_path)}


def builder_status(*, ctx: Any) -> dict[str, Any]:
    """Read the selected prerequisite stack's controlling status and outputs."""
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("prerequisite_stack_id"):
        raise ConfigError("selected config has no prerequisite stack receipt")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    stack = session.client("cloudformation").describe_stacks(StackName=deployment["prerequisite_stack_id"])["Stacks"][0]
    return {"stack_id": stack["StackId"], "stack_name": stack["StackName"], "status": stack["StackStatus"],
            "reason": stack.get("StackStatusReason", ""),
            "outputs": {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}}


def complete_target(*, ctx: Any, source_config: str, source_env: str, source_profile: str,
                    source_region: str, livekit_url_source: str, worker_desired_count: int) -> dict[str, Any]:
    """Persist prerequisite outputs and create only explicitly selected target secrets."""
    import json
    import secrets

    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Target must explicitly be profile lsmc in us-east-2")
    if source_profile != "lsmc" or source_region != "us-west-1":
        raise ConfigError("Source must explicitly be profile lsmc in us-west-1")
    if worker_desired_count not in (0, 1):
        raise ConfigError("worker desired count must be explicitly 0 or 1")
    source = source_inputs(source_config=source_config, source_env=source_env, source_profile=source_profile,
                           source_region=source_region, livekit_url_source=livekit_url_source)
    state = builder_status(ctx=ctx)
    if state["status"] != "CREATE_COMPLETE":
        raise ConfigError(f"Prerequisite stack is {state['status']}; create must complete first")
    outputs = state["outputs"]
    for field in ("SourceBucket", "WorkerRepositoryUri", "DotRepositoryUri", "BuilderInstanceId", "BuilderPublicIp"):
        if not outputs.get(field):
            raise ConfigError(f"Prerequisite stack is missing required output {field}")
    target = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    target_account = target.client("sts").get_caller_identity()["Account"]
    for field in ("OpenAICredentialsSecretArn", "LiveKitCredentialsSecretArn"):
        parts = source[field].split(":")
        if parts[3] != source_region or parts[4] != target_account:
            raise ConfigError(f"{field} must refer to the selected source region and target account")
    source_client = boto3.Session(profile_name=source_profile, region_name=source_region).client("secretsmanager")
    target_client = target.client("secretsmanager")
    sam = ctx.env.raw.get("sam")
    if not isinstance(sam, dict) or not isinstance(sam.get("parameter_overrides"), dict):
        raise ConfigError("Selected environment requires sam.parameter_overrides mapping")
    params = sam["parameter_overrides"]
    deployment = ctx.env.raw["deployment"]
    deployment["worker_repository_uri"] = outputs["WorkerRepositoryUri"]
    deployment["dot_repository_uri"] = outputs["DotRepositoryUri"]
    deployment["builder_instance_id"] = outputs["BuilderInstanceId"]
    deployment["builder_public_ip"] = outputs["BuilderPublicIp"]
    sam["s3_bucket"] = outputs["SourceBucket"]
    params["LiveKitUrl"] = source["LiveKitUrl"]
    params["AgentWorkerDesiredCount"] = str(worker_desired_count)
    save_config_dict(ctx.config_path, ctx.cfg)

    def create_target(parameter: str, suffix: str, value: dict[str, Any]) -> None:
        if params.get(parameter):
            return
        response = target_client.create_secret(
            Name=f"{ctx.env.stack_name}/{suffix}", **value,
            Tags=[{"Key": "project", "Value": "marvain"}],
        )
        params[parameter] = response["ARN"]
        save_config_dict(ctx.config_path, ctx.cfg)

    for parameter, suffix in (("OpenAICredentialsSecretArn", "openai"),
                              ("LiveKitCredentialsSecretArn", "livekit")):
        if not params.get(parameter):
            value = source_client.get_secret_value(SecretId=source[parameter])
            if "SecretString" in value:
                secret_value = {"SecretString": value["SecretString"]}
            elif "SecretBinary" in value:
                secret_value = {"SecretBinary": value["SecretBinary"]}
            else:
                raise ConfigError(f"Source {parameter} has no secret value")
            create_target(parameter, suffix, secret_value)
    create_target("AgentWorkerHubDeviceTokenSecretArn", "agent-worker-device-token",
                  {"SecretString": json.dumps({"device_token": secrets.token_hex(32)})})
    create_target("MarvainV4BindingsSecretArn", "v4-bindings", {"SecretString": "{}"})
    return {"status": "prerequisites_ready", "config_path": str(ctx.config_path), "builder": outputs["BuilderInstanceId"],
            "builder_public_ip": outputs["BuilderPublicIp"], "packaging_bucket": outputs["SourceBucket"],
            "worker_repository_uri": outputs["WorkerRepositoryUri"], "dot_repository_uri": outputs["DotRepositoryUri"],
            "target_secret_arns": {key: params[key] for key in ("OpenAICredentialsSecretArn", "LiveKitCredentialsSecretArn",
                                                                  "AgentWorkerHubDeviceTokenSecretArn", "MarvainV4BindingsSecretArn")}}


def publish_image(*, profile: str, region: str, repository_uri: str, release_version: str,
                  source_dir: str, builder_instance_id: str, image_kind: str) -> dict[str, str]:
    """Build and publish the final image on the explicitly selected EC2 builder."""
    import base64
    import json
    import platform
    import subprocess
    import urllib.request

    if profile != "lsmc" or region != "us-east-2":
        raise ConfigError("Image publication requires profile lsmc and region us-east-2")
    if platform.system() != "Linux":
        raise ConfigError("Container images may be built only on the selected Linux EC2 builder")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", release_version):
        raise ConfigError("release_version must be an explicit numeric semver tag")
    if image_kind not in {"worker", "dot"}:
        raise ConfigError("image_kind must be worker or dot")
    if not re.fullmatch(r"[0-9]{12}\.dkr\.ecr\.us-east-2\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*", repository_uri):
        raise ConfigError("repository_uri must identify the selected us-east-2 ECR repository")
    root = Path(source_dir)
    if not root.is_absolute() or not root.is_dir():
        raise ConfigError("source_dir must be the absolute path to the selected release archive")
    try:
        token_req = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(token_req, timeout=5) as response:
            token = response.read().decode("ascii")
        identity_req = urllib.request.Request("http://169.254.169.254/latest/dynamic/instance-identity/document",
                    headers={"X-aws-ec2-metadata-token": token})
        with urllib.request.urlopen(identity_req, timeout=5) as response:
            identity = json.load(response)
    except Exception as exc:
        raise ConfigError("Selected EC2 builder identity is unavailable") from exc
    if identity.get("instanceId") != builder_instance_id or identity.get("region") != region:
        raise ConfigError("Current EC2 instance does not match the selected builder and region")
    dockerfile = "apps/agent_worker/Dockerfile" if image_kind == "worker" else "apps/dot_service/Dockerfile"
    argument = "MARVAIN_WORKER_VERSION" if image_kind == "worker" else "MARVAIN_RELEASE_VERSION"
    image_tag = f"{repository_uri}:{release_version}"
    session = boto3.Session(profile_name=profile, region_name=region)
    authorization = session.client("ecr").get_authorization_token(registryIds=[repository_uri.split(".", 1)[0]])
    entry = authorization["authorizationData"][0]
    username, password = base64.b64decode(entry["authorizationToken"]).decode("utf-8").split(":", 1)
    login = subprocess.run(["docker", "login", "--username", username, "--password-stdin", entry["proxyEndpoint"]],
                           input=password, text=True, capture_output=True, cwd=root)
    if login.returncode != 0:
        raise ConfigError("Docker registry login failed")
    built = subprocess.run(["docker", "build", "--file", dockerfile, "--build-arg", f"{argument}={release_version}",
                            "--tag", image_tag, "."], cwd=root)
    if built.returncode != 0:
        raise ConfigError("Final tagged container image build failed")
    pushed = subprocess.run(["docker", "push", image_tag], cwd=root, text=True, capture_output=True)
    if pushed.returncode != 0:
        raise ConfigError(f"Final image push failed: {pushed.stderr.strip()}")
    match = re.search(r"digest:\s*(sha256:[0-9a-f]{64})", pushed.stdout)
    if not match:
        raise ConfigError("Image push succeeded but did not return a digest")
    return {"kind": image_kind, "version": release_version, "image_uri": f"{repository_uri}@{match.group(1)}",
            "builder_instance_id": builder_instance_id, "status": "published"}


def deploy_dot_disabled(*, ctx: Any) -> dict[str, str]:
    """Create the dedicated dot edge in explicitly disabled runtime mode."""
    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Dot target must explicitly be profile lsmc in us-east-2")
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("dot_repository_uri"):
        raise ConfigError("Dot repository receipt is required in the selected config")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    cloudformation = session.client("cloudformation")
    hub = cloudformation.describe_stacks(StackName=ctx.env.stack_name)["Stacks"][0]
    outputs = {item["OutputKey"]: item["OutputValue"] for item in hub.get("Outputs", [])}
    mapping = {"VpcId": "MarvainVpcId", "PrivateSubnetAId": "MarvainPrivateSubnetAId",
               "PrivateSubnetBId": "MarvainPrivateSubnetBId", "EcsClusterName": "AgentWorkerClusterName",
               "AuroraSecurityGroupId": "MarvainAuroraSecurityGroupId", "AuroraEndpoint": "MarvainAuroraEndpoint",
               "AuroraPort": "MarvainAuroraPort", "AuroraDatabaseName": "MarvainAuroraDatabaseName",
               "AuroraSecretArn": "MarvainAuroraSecretArn",
               "SecretsEndpointSecurityGroupId": "MarvainSecretsEndpointSecurityGroupId"}
    missing = [name for name in mapping.values() if not outputs.get(name)]
    if missing:
        raise ConfigError("Selected Hub stack lacks required dot outputs: " + ", ".join(missing))
    params = [{"ParameterKey": key, "ParameterValue": outputs[value]} for key, value in mapping.items()]
    params.extend([{"ParameterKey": "DotRuntimeMode", "ParameterValue": "disabled"},
                   {"ParameterKey": "DotImageRepositoryUri", "ParameterValue": str(deployment["dot_repository_uri"])}])
    path = Path(__file__).resolve().parents[1] / "infrastructure" / "dot_service.yaml"
    name = f"{ctx.env.stack_name}-dot"
    result = cloudformation.create_stack(StackName=name, TemplateBody=path.read_text(encoding="utf-8"),
        Parameters=params, Capabilities=["CAPABILITY_IAM"], DisableRollback=True,
        Tags=[{"Key": "project", "Value": "marvain"}])
    deployment["dot_stack_id"] = result["StackId"]
    save_config_dict(ctx.config_path, ctx.cfg)
    return {"stack_name": name, "stack_id": result["StackId"], "status": "create_submitted"}


def dot_status(*, ctx: Any) -> dict[str, Any]:
    """Read the selected dot edge's controlling stack result and outputs."""
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("dot_stack_id"):
        raise ConfigError("selected config has no dot stack receipt")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    stack = session.client("cloudformation").describe_stacks(StackName=deployment["dot_stack_id"])["Stacks"][0]
    return {"stack_id": stack["StackId"], "stack_name": stack["StackName"], "status": stack["StackStatus"],
            "reason": stack.get("StackStatusReason", ""),
            "outputs": {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}}


def repair_builder_push(*, ctx: Any) -> dict[str, str]:
    """Submit the ECR push-permission repair without replacing builder inputs."""
    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Builder target must explicitly be profile lsmc in us-east-2")
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("prerequisite_stack_id"):
        raise ConfigError("selected config has no prerequisite stack receipt")
    path = Path(__file__).resolve().parents[1] / "infrastructure" / "deployment_prerequisites.yaml"
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    response = session.client("cloudformation").update_stack(
        StackName=deployment["prerequisite_stack_id"], TemplateBody=path.read_text(encoding="utf-8"),
        Parameters=[{"ParameterKey": name, "UsePreviousValue": True} for name in
                    ("BuilderImageId", "BuilderPublicKey", "BuilderSshCidr", "BuilderUserData")],
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    return {"stack_id": response["StackId"], "status": "update_submitted"}


def publish_built_image(*, profile: str, region: str, repository_uri: str, release_version: str,
                        builder_instance_id: str) -> dict[str, str]:
    """Push an already-built final tag on the selected builder, without rebuilding."""
    import base64
    import json
    import platform
    import subprocess
    import urllib.request

    if profile != "lsmc" or region != "us-east-2" or platform.system() != "Linux":
        raise ConfigError("Publication requires profile lsmc on the selected Linux EC2 builder in us-east-2")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", release_version):
        raise ConfigError("release_version must be an explicit numeric semver tag")
    if not re.fullmatch(r"[0-9]{12}\.dkr\.ecr\.us-east-2\.amazonaws\.com/[a-z0-9][a-z0-9._/-]*", repository_uri):
        raise ConfigError("repository_uri must identify the selected us-east-2 ECR repository")
    try:
        request = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(request, timeout=5) as response:
            token = response.read().decode("ascii")
        request = urllib.request.Request("http://169.254.169.254/latest/dynamic/instance-identity/document",
                  headers={"X-aws-ec2-metadata-token": token})
        with urllib.request.urlopen(request, timeout=5) as response:
            identity = json.load(response)
    except Exception as exc:
        raise ConfigError("Selected EC2 builder identity is unavailable") from exc
    if identity.get("instanceId") != builder_instance_id or identity.get("region") != region:
        raise ConfigError("Current EC2 instance does not match the selected builder and region")
    session = boto3.Session(profile_name=profile, region_name=region)
    entry = session.client("ecr").get_authorization_token(registryIds=[repository_uri.split(".", 1)[0]])["authorizationData"][0]
    username, password = base64.b64decode(entry["authorizationToken"]).decode("utf-8").split(":", 1)
    login = subprocess.run(["docker", "login", "--username", username, "--password-stdin", entry["proxyEndpoint"]],
                           input=password, text=True, capture_output=True)
    if login.returncode != 0:
        raise ConfigError("Docker registry login failed")
    pushed = subprocess.run(["docker", "push", f"{repository_uri}:{release_version}"], text=True, capture_output=True)
    if pushed.returncode != 0:
        raise ConfigError(f"Existing final image push failed: {pushed.stderr.strip()}")
    match = re.search(r"digest:\s*(sha256:[0-9a-f]{64})", pushed.stdout)
    if not match:
        raise ConfigError("Image push succeeded but did not return a digest")
    return {"version": release_version, "image_uri": f"{repository_uri}@{match.group(1)}",
            "builder_instance_id": builder_instance_id, "status": "published"}


def create_bootstrap_network(*, ctx: Any) -> dict[str, str]:
    """Connect the selected builder to the selected Hub Aurora for TapDB setup."""
    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Bootstrap network requires profile lsmc and region us-east-2")
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("prerequisite_stack_id"):
        raise ConfigError("selected config has no prerequisite stack receipt")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    cloudformation = session.client("cloudformation")
    builder_stack = deployment["prerequisite_stack_id"]
    hub_stack = ctx.env.stack_name

    def resource(stack: str, logical_id: str) -> str:
        return str(cloudformation.describe_stack_resource(
            StackName=stack, LogicalResourceId=logical_id
        )["StackResourceDetail"]["PhysicalResourceId"])

    hub = cloudformation.describe_stacks(StackName=hub_stack)["Stacks"][0]
    outputs = {item["OutputKey"]: item["OutputValue"] for item in hub.get("Outputs", [])}
    for key in ("MarvainAuroraEndpoint", "MarvainAuroraPort", "MarvainAuroraDatabaseName", "MarvainAuroraSecretArn"):
        if not outputs.get(key):
            raise ConfigError(f"Selected Hub stack lacks required output {key}")
    selected = {
        "BuilderVpcId": resource(builder_stack, "BuilderVpc"),
        "HubVpcId": resource(hub_stack, "HubVpc"),
        "BuilderRouteTableId": resource(builder_stack, "PublicRouteTable"),
        "HubPrivateRouteTableId": resource(hub_stack, "PrivateRouteTable"),
        "BuilderSecurityGroupId": resource(builder_stack, "BuilderSecurityGroup"),
        "AuroraSecurityGroupId": resource(hub_stack, "DbSecurityGroup"),
        "BuilderRoleName": resource(builder_stack, "BuilderRole"),
        "AuroraSecretArn": outputs["MarvainAuroraSecretArn"],
    }
    path = Path(__file__).resolve().parents[1] / "infrastructure" / "tapdb_bootstrap_network.yaml"
    name = f"{ctx.env.stack_name}-tapdb-bootstrap-network"
    result = cloudformation.create_stack(
        StackName=name, TemplateBody=path.read_text(encoding="utf-8"),
        Parameters=[{"ParameterKey": key, "ParameterValue": value} for key, value in selected.items()],
        Capabilities=["CAPABILITY_NAMED_IAM"], DisableRollback=True,
        Tags=[{"Key": "project", "Value": "marvain"}],
    )
    deployment["tapdb_bootstrap_network_stack_id"] = result["StackId"]
    deployment["tapdb_bootstrap"] = {
        "host": outputs["MarvainAuroraEndpoint"], "port": outputs["MarvainAuroraPort"],
        "database": outputs["MarvainAuroraDatabaseName"], "secret_arn": outputs["MarvainAuroraSecretArn"],
        "builder_instance_id": deployment.get("builder_instance_id"),
    }
    save_config_dict(ctx.config_path, ctx.cfg)
    return {"stack_name": name, "stack_id": result["StackId"], "status": "create_submitted"}


def bootstrap_network_status(*, ctx: Any) -> dict[str, Any]:
    """Read the selected TapDB bootstrap connectivity stack's controlling status."""
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("tapdb_bootstrap_network_stack_id"):
        raise ConfigError("selected config has no TapDB bootstrap network receipt")
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    stack = session.client("cloudformation").describe_stacks(
        StackName=deployment["tapdb_bootstrap_network_stack_id"]
    )["Stacks"][0]
    return {"stack_id": stack["StackId"], "stack_name": stack["StackName"], "status": stack["StackStatus"],
            "reason": stack.get("StackStatusReason", ""),
            "outputs": {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}}


def initialize_canonical(*, profile: str, region: str, host: str, port: int, database: str,
                         secret_arn: str, builder_instance_id: str, registry_root: str) -> dict[str, str]:
    """Invoke the pinned TapDB owner CLI on the selected networked EC2 builder."""
    import json
    import os
    import platform
    import tempfile
    import urllib.request

    if profile != "lsmc" or region != "us-east-2" or platform.system() != "Linux":
        raise ConfigError("TapDB initialization requires profile lsmc on the selected Linux EC2 builder in us-east-2")
    if not re.fullmatch(r"arn:aws:secretsmanager:us-east-2:[0-9]{12}:secret:.+", secret_arn):
        raise ConfigError("an explicit us-east-2 Aurora secret ARN is required")
    root = Path(registry_root)
    if not root.is_absolute():
        raise ConfigError("registry_root must be the absolute path to the selected release template directory")
    try:
        request = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                  headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        with urllib.request.urlopen(request, timeout=5) as response:
            token = response.read().decode("ascii")
        request = urllib.request.Request("http://169.254.169.254/latest/dynamic/instance-identity/document",
                  headers={"X-aws-ec2-metadata-token": token})
        with urllib.request.urlopen(request, timeout=5) as response:
            identity = json.load(response)
    except Exception as exc:
        raise ConfigError("Selected EC2 builder identity is unavailable") from exc
    if identity.get("instanceId") != builder_instance_id or identity.get("region") != region:
        raise ConfigError("Current EC2 instance does not match the selected builder and region")
    session = boto3.Session(profile_name=profile, region_name=region)
    secret = session.client("secretsmanager").get_secret_value(SecretId=secret_arn)
    try:
        credential = json.loads(secret["SecretString"])
        username, password = credential["username"], credential["password"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError("Aurora secret lacks the required database credentials") from exc
    config = {"meta": {"config_version": 3, "client_id": "marvain", "database_name": database, "owner_repo_name": "marvain",
                       "domain_registry_path": str(root / "domain_code_registry.json"),
                       "prefix_ownership_registry_path": str(root / "prefix_ownership_registry.json")},
              "environments": {"prod": {"engine_type": "aurora", "host": host, "port": port,
                       "database": database, "user": username, "region": region, "iam_auth": "false",
                       "secret_arn": secret_arn, "domain_code": "V"}}}
    env = os.environ.copy()
    env.update({"AWS_PROFILE": profile, "AWS_REGION": region, "AWS_DEFAULT_REGION": region})
    with tempfile.TemporaryDirectory(prefix="marvain-tapdb-owner-") as directory:
        path = Path(directory) / "tapdb-config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        from agent_hub.semantic_tapdb import initialize_aurora_schema
        previous = {key: os.environ.get(key) for key in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION")}
        try:
            os.environ.update({key: env[key] for key in previous})
            initialize_aurora_schema(config_path=path, host=host, port=port, username=username,
                                     password=password, database=database, region=region)
        except RuntimeError as exc:
            raise ConfigError(str(exc)) from exc
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    return {"status": "schema_initialized", "database": database, "builder_instance_id": builder_instance_id}


def stop_builder(*, ctx: Any) -> dict[str, str]:
    """Request a normal stop of the selected dedicated builder instance."""
    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Builder target must explicitly be profile lsmc in us-east-2")
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("builder_instance_id"):
        raise ConfigError("selected config has no builder instance receipt")
    instance_id = str(deployment["builder_instance_id"])
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    response = session.client("ec2").stop_instances(InstanceIds=[instance_id])
    stopped = response["StoppingInstances"][0]
    return {"instance_id": stopped["InstanceId"], "previous_state": stopped["PreviousState"]["Name"],
            "current_state": stopped["CurrentState"]["Name"]}


def builder_power_state(*, ctx: Any) -> dict[str, str]:
    """Read lifecycle state for the selected dedicated builder instance."""
    if ctx.env.aws_profile != "lsmc" or ctx.env.aws_region != "us-east-2":
        raise ConfigError("Builder target must explicitly be profile lsmc in us-east-2")
    deployment = ctx.env.raw.get("deployment")
    if not isinstance(deployment, dict) or not deployment.get("builder_instance_id"):
        raise ConfigError("selected config has no builder instance receipt")
    instance_id = str(deployment["builder_instance_id"])
    session = boto3.Session(profile_name=ctx.env.aws_profile, region_name=ctx.env.aws_region)
    response = session.client("ec2").describe_instances(InstanceIds=[instance_id])
    instance = response["Reservations"][0]["Instances"][0]
    return {"instance_id": instance["InstanceId"], "state": instance["State"]["Name"]}
