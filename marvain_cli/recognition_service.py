"""Explicit Linux service primitives for the recognition worker.

This module has no CLI registration side effects.  The root CLI can bind these
functions after configuration supplies every host path, model manifest, and
secret-bearing environment file.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


class RecognitionServiceCommandError(ValueError):
    pass


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class RecognitionInstallSpec:
    service_user: str
    service_group: str
    unit_name: str
    python_executable: Path
    install_root: Path
    worker_source: Path
    wheelhouse: Path
    package_version: str
    environment_source: Path
    environment_destination: Path
    model_manifest_source: Path
    model_manifest_destination: Path
    unit_source: Path
    unit_destination: Path
    health_path: Path

    def validate(self) -> RecognitionInstallSpec:
        for field in (
            "python_executable",
            "install_root",
            "worker_source",
            "wheelhouse",
            "environment_source",
            "environment_destination",
            "model_manifest_source",
            "model_manifest_destination",
            "unit_source",
            "unit_destination",
            "health_path",
        ):
            path = getattr(self, field)
            if not path.is_absolute():
                raise RecognitionServiceCommandError(f"{field} must be an absolute path")
        for field in ("worker_source", "wheelhouse", "environment_source", "model_manifest_source", "unit_source"):
            if not getattr(self, field).exists():
                raise RecognitionServiceCommandError(f"{field} does not exist: {getattr(self, field)}")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.service_user):
            raise RecognitionServiceCommandError("service_user is invalid")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", self.service_group):
            raise RecognitionServiceCommandError("service_group is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", self.unit_name):
            raise RecognitionServiceCommandError("unit_name must be an explicit systemd .service unit")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?", self.package_version):
            raise RecognitionServiceCommandError("package_version must be an explicit version")
        fixed_contract = {
            "service_user": "marvain-recognition",
            "service_group": "marvain-recognition",
            "unit_name": "marvain-recognition.service",
            "install_root": Path("/opt/marvain-recognition"),
            "environment_destination": Path("/etc/marvain/recognition.env"),
            "model_manifest_destination": Path("/etc/marvain/recognition-models.json"),
            "unit_destination": Path("/etc/systemd/system/marvain-recognition.service"),
            "health_path": Path("/var/lib/marvain-recognition/health.json"),
        }
        for field, expected in fixed_contract.items():
            if getattr(self, field) != expected:
                raise RecognitionServiceCommandError(f"{field} must match the checked-in service unit: {expected}")
        return self


def install_command_plan(
    spec: RecognitionInstallSpec,
    *,
    create_user: bool,
    create_group: bool | None = None,
) -> list[list[str]]:
    spec = spec.validate()
    sudo = "/usr/bin/sudo"
    if create_group is None:
        create_group = create_user
    commands: list[list[str]] = [
        ["/usr/bin/grep", "-Fx", 'ID="amzn"', "/etc/os-release"],
        ["/usr/bin/grep", "-Fx", 'VERSION_ID="2023"', "/etc/os-release"],
        ["/usr/bin/test", "-x", str(spec.python_executable)],
        ["/usr/bin/test", "-d", str(spec.wheelhouse)],
    ]
    if create_group:
        commands.append([sudo, "/usr/sbin/groupadd", "--system", spec.service_group])
    if create_user:
        commands.append(
            [
                sudo,
                "/usr/sbin/useradd",
                "--system",
                "--gid",
                spec.service_group,
                "--home-dir",
                str(spec.install_root),
                "--shell",
                "/sbin/nologin",
                spec.service_user,
            ]
        )
    commands.extend(
        [
            [
                sudo,
                "/usr/bin/install",
                "-d",
                "-m",
                "0750",
                "-o",
                "root",
                "-g",
                spec.service_group,
                str(spec.environment_destination.parent),
            ],
            [
                sudo,
                "/usr/bin/install",
                "-d",
                "-m",
                "0750",
                "-o",
                spec.service_user,
                "-g",
                spec.service_group,
                str(spec.install_root),
                str(spec.install_root / "app"),
                str(spec.health_path.parent),
            ],
            [
                sudo,
                "/usr/bin/install",
                "-m",
                "0750",
                "-o",
                spec.service_user,
                "-g",
                spec.service_group,
                str(spec.worker_source),
                str(spec.install_root / "app" / "worker.py"),
            ],
            [
                sudo,
                "/usr/bin/install",
                "-m",
                "0600",
                "-o",
                spec.service_user,
                "-g",
                spec.service_group,
                str(spec.environment_source),
                str(spec.environment_destination),
            ],
            [
                sudo,
                "/usr/bin/install",
                "-m",
                "0640",
                "-o",
                spec.service_user,
                "-g",
                spec.service_group,
                str(spec.model_manifest_source),
                str(spec.model_manifest_destination),
            ],
            [
                sudo,
                "-u",
                spec.service_user,
                str(spec.python_executable),
                "-m",
                "venv",
                str(spec.install_root / "venv"),
            ],
            [
                sudo,
                "-u",
                spec.service_user,
                str(spec.install_root / "venv" / "bin" / "python"),
                "-m",
                "pip",
                "install",
                "--no-index",
                f"--find-links={spec.wheelhouse}",
                f"marvain=={spec.package_version}",
            ],
            [
                sudo,
                "/usr/bin/install",
                "-m",
                "0644",
                str(spec.unit_source),
                str(spec.unit_destination),
            ],
            [sudo, "/usr/bin/systemctl", "daemon-reload"],
            [sudo, "/usr/bin/systemctl", "enable", spec.unit_name],
        ]
    )
    return commands


def run_install(
    spec: RecognitionInstallSpec,
    *,
    runner: Runner = subprocess.run,
) -> list[subprocess.CompletedProcess[str]]:
    spec = spec.validate()
    identity = runner(["/usr/bin/id", "-u", spec.service_user], capture_output=True, text=True, check=False)
    if identity.returncode not in {0, 1}:
        raise RecognitionServiceCommandError(
            f"service user lookup failed: rc={identity.returncode} stderr={identity.stderr.strip()}"
        )
    group = runner(["/usr/bin/getent", "group", spec.service_group], capture_output=True, text=True, check=False)
    if group.returncode not in {0, 2}:
        raise RecognitionServiceCommandError(
            f"service group lookup failed: rc={group.returncode} stderr={group.stderr.strip()}"
        )
    results: list[subprocess.CompletedProcess[str]] = []
    for command in install_command_plan(
        spec,
        create_user=identity.returncode == 1,
        create_group=group.returncode == 2,
    ):
        results.append(runner(command, capture_output=True, text=True, check=True))
    return results


def control_command(*, action: str, unit_name: str) -> list[str]:
    if action not in {"start", "stop", "restart"}:
        raise RecognitionServiceCommandError("action must be start, stop, or restart")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit_name):
        raise RecognitionServiceCommandError("unit_name must be an explicit systemd .service unit")
    return ["/usr/bin/sudo", "/usr/bin/systemctl", action, unit_name]


def status_commands(*, unit_name: str, health_path: Path) -> list[list[str]]:
    if not health_path.is_absolute():
        raise RecognitionServiceCommandError("health_path must be absolute")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit_name):
        raise RecognitionServiceCommandError("unit_name must be an explicit systemd .service unit")
    return [
        [
            "/usr/bin/systemctl",
            "show",
            unit_name,
            "--property=ActiveState,SubState,MainPID,ExecMainStatus,RestartUSec,FragmentPath",
        ],
        ["/usr/bin/cat", str(health_path)],
    ]


def logs_command(*, unit_name: str, lines: int, follow: bool) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", unit_name):
        raise RecognitionServiceCommandError("unit_name must be an explicit systemd .service unit")
    if lines <= 0:
        raise RecognitionServiceCommandError("lines must be positive")
    command = ["/usr/bin/journalctl", "--unit", unit_name, "--lines", str(lines), "--no-pager"]
    if follow:
        command.append("--follow")
    return command


def run_commands(
    commands: Sequence[Sequence[str]],
    *,
    runner: Runner = subprocess.run,
) -> list[subprocess.CompletedProcess[str]]:
    return [runner(list(command), capture_output=True, text=True, check=True) for command in commands]
