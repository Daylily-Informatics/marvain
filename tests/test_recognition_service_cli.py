from __future__ import annotations

from pathlib import Path

import pytest

from marvain_cli.recognition_service import (
    RecognitionInstallSpec,
    RecognitionServiceCommandError,
    control_command,
    install_command_plan,
    logs_command,
    status_commands,
)


def _install_spec(tmp_path: Path) -> RecognitionInstallSpec:
    worker = tmp_path / "worker.py"
    worker.write_text("raise SystemExit(0)\n", encoding="utf-8")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    environment = tmp_path / "recognition.env"
    environment.write_text("HUB_DEVICE_TOKEN=secret-reference\n", encoding="utf-8")
    manifest = tmp_path / "models.json"
    manifest.write_text('{"schema":"marvain.recognition.models.v1"}\n', encoding="utf-8")
    unit = tmp_path / "marvain-recognition.service"
    unit.write_text("[Service]\n", encoding="utf-8")
    return RecognitionInstallSpec(
        service_user="marvain-recognition",
        service_group="marvain-recognition",
        unit_name="marvain-recognition.service",
        python_executable=Path("/usr/bin/python3.12"),
        install_root=Path("/opt/marvain-recognition"),
        worker_source=worker,
        wheelhouse=wheelhouse,
        package_version="1.2.3",
        environment_source=environment,
        environment_destination=Path("/etc/marvain/recognition.env"),
        model_manifest_source=manifest,
        model_manifest_destination=Path("/etc/marvain/recognition-models.json"),
        unit_source=unit,
        unit_destination=Path("/etc/systemd/system/marvain-recognition.service"),
        health_path=Path("/var/lib/marvain-recognition/health.json"),
    )


def test_install_plan_uses_exact_offline_package_and_explicit_sources(tmp_path: Path) -> None:
    spec = _install_spec(tmp_path)

    commands = install_command_plan(spec, create_user=True)

    flattened = [argument for command in commands for argument in command]
    assert "marvain==1.2.3" in flattened
    assert f"--find-links={spec.wheelhouse}" in flattened
    assert "--no-index" in flattened
    assert ["/usr/bin/grep", "-Fx", 'ID="amzn"', "/etc/os-release"] in commands
    assert ["/usr/bin/grep", "-Fx", 'VERSION_ID="2023"', "/etc/os-release"] in commands
    assert str(spec.environment_source) in flattened
    assert str(spec.model_manifest_source) in flattened
    assert ["/usr/bin/sudo", "/usr/bin/systemctl", "enable", spec.unit_name] in commands
    assert [
        "/usr/bin/sudo",
        "-u",
        "marvain-recognition",
        "/usr/bin/python3.12",
        "-m",
        "venv",
        "/opt/marvain-recognition/venv",
    ] in commands
    assert not any("aws" in argument for argument in flattened)


def test_install_spec_has_no_host_path_or_version_defaults(tmp_path: Path) -> None:
    spec = _install_spec(tmp_path)
    relative = RecognitionInstallSpec(**{**spec.__dict__, "model_manifest_destination": Path("models.json")})

    with pytest.raises(RecognitionServiceCommandError, match="model_manifest_destination must be an absolute path"):
        install_command_plan(relative, create_user=False)

    unpinned = RecognitionInstallSpec(**{**spec.__dict__, "package_version": "latest"})
    with pytest.raises(RecognitionServiceCommandError, match="explicit version"):
        install_command_plan(unpinned, create_user=False)


def test_service_control_status_and_logs_are_explicit() -> None:
    assert control_command(action="start", unit_name="marvain-recognition.service") == [
        "/usr/bin/sudo",
        "/usr/bin/systemctl",
        "start",
        "marvain-recognition.service",
    ]
    assert control_command(action="stop", unit_name="marvain-recognition.service")[-2:] == [
        "stop",
        "marvain-recognition.service",
    ]
    status = status_commands(
        unit_name="marvain-recognition.service",
        health_path=Path("/var/lib/marvain-recognition/health.json"),
    )
    assert status[0][:3] == ["/usr/bin/systemctl", "show", "marvain-recognition.service"]
    assert status[1] == ["/usr/bin/cat", "/var/lib/marvain-recognition/health.json"]
    assert logs_command(unit_name="marvain-recognition.service", lines=200, follow=True)[-1] == "--follow"


def test_service_control_rejects_inferred_or_malformed_inputs() -> None:
    with pytest.raises(RecognitionServiceCommandError, match="action must"):
        control_command(action="status", unit_name="marvain-recognition.service")
    with pytest.raises(RecognitionServiceCommandError, match="explicit systemd"):
        status_commands(unit_name="recognition", health_path=Path("/var/lib/health.json"))
    with pytest.raises(RecognitionServiceCommandError, match="lines must be positive"):
        logs_command(unit_name="marvain-recognition.service", lines=0, follow=False)


def test_systemd_unit_is_outbound_only_and_supervised() -> None:
    unit = Path(__file__).resolve().parents[1] / "deploy" / "recognition" / "marvain-recognition.service"
    text = unit.read_text(encoding="utf-8")

    assert "Restart=on-failure" in text
    assert "EnvironmentFile=/etc/marvain/recognition.env" in text
    assert "ReadWritePaths=/var/lib/marvain-recognition" in text
    assert "ListenStream" not in text
    assert "Environment=" not in text
    assert "HUB_DEVICE_TOKEN" not in text
