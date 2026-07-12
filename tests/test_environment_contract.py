from __future__ import annotations

import os
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import yaml

from marvain_cli import ops

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_cloudformation_tag(
    loader: _CloudFormationLoader,
    _tag_suffix: str,
    node: yaml.Node,
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


_CloudFormationLoader.add_multi_constructor("!", _construct_cloudformation_tag)


def _values_for_key(node: Any, key: str) -> list[Any]:
    values: list[Any] = []
    if isinstance(node, dict):
        for candidate, value in node.items():
            if candidate == key:
                values.append(value)
            values.extend(_values_for_key(value, key))
    elif isinstance(node, list):
        for value in node:
            values.extend(_values_for_key(value, key))
    return values


def test_root_activation_contract_replaces_old_wrapper_files() -> None:
    activate = REPO_ROOT / "activate"

    assert activate.exists()
    assert os.access(activate, os.X_OK)
    assert (REPO_ROOT / "environment.yaml").exists()
    assert not (REPO_ROOT / "marvain_activate").exists()
    assert not (REPO_ROOT / "config" / "marvain_conda.yaml").exists()
    assert not (REPO_ROOT / "bin" / "marvain").exists()


def test_activate_stays_minimal_and_environment_declares_sam_cli() -> None:
    activate_text = (REPO_ROOT / "activate").read_text(encoding="utf-8")
    env_text = (REPO_ROOT / "environment.yaml").read_text(encoding="utf-8")
    environment = yaml.safe_load(env_text)
    dependencies = environment["dependencies"]
    pip_sections = [dependency["pip"] for dependency in dependencies if isinstance(dependency, dict)]

    assert "Usage: source ./activate" in activate_text
    assert "MARVAIN_REPO_ROOT" in activate_text
    assert "conda env create -n marvain -f" in activate_text
    assert "MARVAIN_REPO_CFG" not in activate_text
    assert "COMPLETE" not in activate_text
    assert "PATH=" not in activate_text
    assert "python=3.12" in dependencies
    assert pip_sections == [["aws-sam-cli==1.147.1"]]
    assert "awscli" not in env_text
    assert "aws-session-manager-plugin" not in env_text
    assert "daylily-auth-cognito" not in env_text
    assert "daylily-tapdb" not in env_text
    assert "cli-core-yo" not in env_text


def test_pyproject_owns_python_dependencies_and_console_script() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    dependencies = set(pyproject["project"]["dependencies"])
    assert "cli-core-yo==2.1.1" in dependencies
    assert "cli-core-yo==2.1.0" not in dependencies
    assert pyproject["project"]["requires-python"] == ">=3.12"
    assert "daylily-auth-cognito==2.1.5" in dependencies
    assert "daylily-auth-cognito==2.1.4" not in dependencies
    assert "daylily-tapdb[admin]==6.0.8" in dependencies
    assert "daylily-tapdb[admin]==6.0.7" not in dependencies
    assert pyproject["tool"]["marvain"]["python"] == "3.12"
    assert pyproject["project"]["scripts"]["marvain"] == "marvain_cli.__main__:main"
    assert pyproject["tool"]["marvain"]["conda_file"] == "environment.yaml"


def test_deployment_runtime_contract_is_python_312() -> None:
    template = yaml.load(
        (REPO_ROOT / "template.yaml").read_text(encoding="utf-8"),
        Loader=_CloudFormationLoader,
    )
    runtime = template["Globals"]["Function"]["Runtime"]
    resources = template["Resources"]

    functions = {
        name: resource for name, resource in resources.items() if resource.get("Type") == "AWS::Serverless::Function"
    }
    layers = {
        name: resource
        for name, resource in resources.items()
        if resource.get("Type") == "AWS::Serverless::LayerVersion"
    }

    assert runtime == "python3.12"
    assert functions
    assert layers
    for name, function in functions.items():
        assert function.get("Properties", {}).get("Runtime", runtime) == runtime, name
    for name, layer in layers.items():
        assert layer["Properties"]["CompatibleRuntimes"] == [runtime], name

    dockerfile = (REPO_ROOT / "apps" / "agent_worker" / "Dockerfile").read_text(encoding="utf-8")
    base_images = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert base_images == ["FROM python:3.12-slim"]


def test_cli_runtime_preflight_uses_the_python_312_contract() -> None:
    ops_text = (REPO_ROOT / "marvain_cli" / "ops.py").read_text(encoding="utf-8")
    device_guide = (REPO_ROOT / "functions" / "hub_api" / "templates" / "device_detail.html").read_text(
        encoding="utf-8"
    )

    assert ops.MARVAIN_PYTHON_VERSION == (3, 12)
    assert ops.MARVAIN_PYTHON_EXECUTABLE == "python3.12"
    assert ops._python_matches_runtime()
    assert "python3.11" not in ops_text
    assert "Python 3.11" not in ops_text
    assert "Python 3.12+" in device_guide
    assert "Python 3.11" not in device_guide


def test_agent_worker_is_an_explicit_egress_only_fargate_service() -> None:
    template = yaml.load(
        (REPO_ROOT / "template.yaml").read_text(encoding="utf-8"),
        Loader=_CloudFormationLoader,
    )
    parameters = template["Parameters"]
    resources = template["Resources"]
    outputs = template["Outputs"]

    for name in (
        "LiveKitUrl",
        "OpenAICredentialsSecretArn",
        "LiveKitCredentialsSecretArn",
        "AgentWorkerImageUri",
        "AgentWorkerVersion",
        "AgentWorkerHubDeviceTokenSecretArn",
        "AgentWorkerDesiredCount",
    ):
        assert "Default" not in parameters[name], name

    assert "@sha256:" in parameters["AgentWorkerImageUri"]["AllowedPattern"]
    assert "OpenAISecret" not in resources
    assert "LiveKitSecret" not in resources
    assert resources["GoogleOAuthSecret"]["Properties"].get("SecretString") is None

    service = resources["AgentWorkerService"]["Properties"]
    assert service["LaunchType"] == "FARGATE"
    assert service["PlatformVersion"] == "1.4.0"
    assert service["DesiredCount"] == "AgentWorkerDesiredCount"
    assert service["EnableExecuteCommand"] is False
    assert service["Tags"] == [{"Key": "project", "Value": "marvain"}]
    assert service["PropagateTags"] == "SERVICE"
    assert service["DeploymentConfiguration"]["DeploymentCircuitBreaker"] == {
        "Enable": True,
        "Rollback": True,
    }
    network = service["NetworkConfiguration"]["AwsvpcConfiguration"]
    assert network["AssignPublicIp"] == "ENABLED"
    assert network["SecurityGroups"] == ["AgentWorkerSecurityGroup"]
    assert network["Subnets"] == ["AgentWorkerPublicSubnetA", "AgentWorkerPublicSubnetB"]

    security_group = resources["AgentWorkerSecurityGroup"]["Properties"]
    assert "SecurityGroupIngress" not in security_group
    assert security_group["SecurityGroupEgress"] == [
        {
            "Description": "Outbound LiveKit, OpenAI, and Hub traffic",
            "IpProtocol": -1,
            "CidrIp": "0.0.0.0/0",
        }
    ]

    task = resources["AgentWorkerTaskDefinition"]["Properties"]
    assert task["Tags"] == [{"Key": "project", "Value": "marvain"}]
    assert task["RequiresCompatibilities"] == ["FARGATE"]
    assert task["RuntimePlatform"] == {
        "CpuArchitecture": "X86_64",
        "OperatingSystemFamily": "LINUX",
    }
    container = task["ContainerDefinitions"][0]
    assert container["Image"] == "AgentWorkerImageUri"
    assert "PortMappings" not in container
    assert {entry["Name"] for entry in container["Secrets"]} == {
        "OPENAI_API_KEY",
        "LIVEKIT_API_KEY",
        "LIVEKIT_API_SECRET",
        "HUB_DEVICE_TOKEN",
    }
    environment = {entry["Name"]: entry["Value"] for entry in container["Environment"]}
    assert environment == {
        "ENV_FILE": "/dev/null",
        "LIVEKIT_URL": "LiveKitUrl",
        "HUB_API_BASE": "https://${HubApi}.execute-api.${AWS::Region}.amazonaws.com/${StageName}",
        "MARVAIN_WORKER_VERSION": "AgentWorkerVersion",
    }
    assert container["HealthCheck"]["Retries"] == 3
    assert container["LogConfiguration"]["LogDriver"] == "awslogs"

    execution_policy = resources["AgentWorkerExecutionRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    secret_resources = execution_policy["Statement"][0]["Resource"]
    assert secret_resources == [
        "OpenAICredentialsSecretArn",
        "LiveKitCredentialsSecretArn",
        "AgentWorkerHubDeviceTokenSecretArn",
    ]
    assert "Policies" not in resources["AgentWorkerTaskRole"]["Properties"]
    assert resources["AgentWorkerRunningTaskAlarm"]["Condition"] == "AgentWorkerEnabled"
    assert resources["AgentWorkerCluster"]["Properties"]["Tags"] == [{"Key": "project", "Value": "marvain"}]

    for name in (
        "AgentWorkerClusterName",
        "AgentWorkerServiceName",
        "AgentWorkerTaskDefinitionArn",
        "AgentWorkerLogGroupName",
        "AgentWorkerImageUri",
        "AgentWorkerVersion",
        "AgentWorkerHubDeviceTokenSecretArn",
    ):
        assert name in outputs


def test_sam_stack_and_lambda_resources_require_the_marvain_project_tag() -> None:
    template = yaml.load(
        (REPO_ROOT / "template.yaml").read_text(encoding="utf-8"),
        Loader=_CloudFormationLoader,
    )

    assert ops.MARVAIN_PROJECT_TAG == "project=marvain"
    assert template["Globals"]["Function"]["Tags"] == {"project": "marvain"}


def test_ci_workflows_are_python_312_gates() -> None:
    workflows = {
        path.name: yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for path in sorted(WORKFLOW_DIR.glob("*.yml"))
    }
    setup_python_versions: list[str] = []

    assert workflows
    for name, workflow in workflows.items():
        assert workflow.get("jobs"), name
        assert not _values_for_key(workflow, "continue-on-error"), name
        for condition in _values_for_key(workflow, "if"):
            assert "secrets." not in str(condition), name
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/setup-python@"):
                    setup_python_versions.append(step["with"]["python-version"])

    assert setup_python_versions
    assert set(setup_python_versions) == {"3.12"}

    ci_jobs = workflows["ci.yml"]["jobs"]
    sam_job = ci_jobs["sam-build"]
    sam_commands = "\n".join(str(step.get("run", "")) for step in sam_job["steps"])
    assert sam_job["env"]["AWS_SAM_CLI_VERSION"] == "1.147.1"
    assert "aws-sam-cli==${AWS_SAM_CLI_VERSION}" in sam_commands
    assert "sam validate --template-file template.yaml" in sam_commands
    assert "sam build --template-file template.yaml" in sam_commands

    e2e_jobs = workflows["e2e-contracts.yml"]["jobs"]
    assert e2e_jobs["e2e"]["needs"] == "preflight"
    preflight_commands = "\n".join(str(step.get("run", "")) for step in e2e_jobs["preflight"]["steps"])
    subprocess.run(["bash", "-n"], input=preflight_commands, text=True, check=True)
    for secret_name in (
        "MARVAIN_AWS_ROLE_TO_ASSUME",
        "MARVAIN_HUB_REST_API_BASE",
        "MARVAIN_HUB_WS_URL",
        "MARVAIN_ADMIN_API_KEY",
        "MARVAIN_COGNITO_USER_POOL_CLIENT_ID",
        "MARVAIN_COGNITO_TEST_USERNAME",
        "MARVAIN_COGNITO_TEST_PASSWORD",
    ):
        assert secret_name in preflight_commands


def test_lambda_requirements_use_current_runtime_pins() -> None:
    hub_api_requirements = (REPO_ROOT / "functions" / "hub_api" / "requirements.txt").read_text(encoding="utf-8")
    ws_message_requirements = (REPO_ROOT / "functions" / "ws_message" / "requirements.txt").read_text(encoding="utf-8")
    tapdb_writer_requirements = (REPO_ROOT / "functions" / "tapdb_writer" / "requirements.txt").read_text(
        encoding="utf-8"
    )

    assert "daylily-auth-cognito==2.1.5" in hub_api_requirements
    assert "daylily-auth-cognito==2.1.4" not in hub_api_requirements
    assert "daylily-auth-cognito==2.1.5" in ws_message_requirements
    assert "daylily-auth-cognito==2.1.4" not in ws_message_requirements
    assert "daylily-tapdb[admin]==6.0.8" in tapdb_writer_requirements
    assert "daylily-tapdb[admin]==6.0.7" not in tapdb_writer_requirements


def test_active_files_do_not_reference_obsolete_activation_or_bin_wrapper() -> None:
    active_paths = [
        REPO_ROOT / "AGENTS.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "QUICKSTART.md",
        REPO_ROOT / "QUICKSTART_GUI.md",
        REPO_ROOT / "bin" / "init_setup.sh",
        REPO_ROOT / "functions" / "hub_api" / "start_server.sh",
        REPO_ROOT / "functions" / "hub_api" / "templates" / "profile.html",
        REPO_ROOT / "functions" / "hub_api" / "templates" / "device_detail.html",
        REPO_ROOT / "scripts" / "nuke_dev.sh",
    ]
    obsolete = [
        "marvain_activate",
        "config/marvain_conda.yaml",
        "./bin/marvain",
        "MARVAIN_ALLOW_VENV",
    ]

    for path in active_paths:
        text = path.read_text(encoding="utf-8")
        for needle in obsolete:
            assert needle not in text, f"{needle!r} remains in {path.relative_to(REPO_ROOT)}"
