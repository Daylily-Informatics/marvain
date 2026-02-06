#!/usr/bin/env python3
"""Marvain Remote Satellite Daemon.

A lightweight daemon that runs on remote devices (Raspberry Pi, etc.) and connects
to the Marvain Hub via WebSocket. It reports heartbeats, responds to pings, and
can execute device-local tools when commanded by the Hub.

Usage:
    python daemon.py --hub-ws-url wss://example.com/ws --device-token TOKEN

Or via installed CLI:
    marvain-remote-satellite --hub-ws-url wss://example.com/ws --device-token TOKEN
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import time as time_module
from pathlib import Path
from typing import Any

import click
import yaml
from hub_client import HubClient, HubClientConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("marvain-satellite")


# -----------------------------------------------------------------------------
# Device Action Registry
# -----------------------------------------------------------------------------


def _action_ping(payload: dict[str, Any]) -> dict[str, Any]:
    """Respond to ping with basic device info."""
    return {
        "status": "ok",
        "timestamp": time_module.time(),
        "platform": platform.system(),
        "hostname": platform.node(),
    }


def _action_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Return device status information (alias for device_status)."""
    return _action_device_status(payload)


def _action_echo(payload: dict[str, Any]) -> dict[str, Any]:
    """Echo back the payload for testing."""
    return {"echoed": payload, "timestamp": time_module.time()}


# -----------------------------------------------------------------------------
# Shell Command Execution
# -----------------------------------------------------------------------------

# Read-only commands that are safe to execute
SAFE_SHELL_COMMANDS = {
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "wc",
    "du",
    "df",
    "ps",
    "top",
    "uptime",
    "uname",
    "hostname",
    "whoami",
    "id",
    "pwd",
    "echo",
    "date",
    "which",
    "whereis",
    "file",
    "stat",
    "env",
    "printenv",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
    "free",
    "vmstat",
    "iostat",
    "lscpu",
    "lsblk",
    "lsusb",
    "ping",
    "nslookup",
    "dig",
    "host",
    "traceroute",
}


def _action_shell_command(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a shell command with safety restrictions.

    Payload:
        command: str - The shell command to execute
        timeout: int - Maximum execution time in seconds (default: 30)
        working_dir: str - Optional working directory
    """
    command = payload.get("command", "").strip()
    timeout = min(payload.get("timeout", 30), 300)  # Max 5 minutes
    working_dir = payload.get("working_dir")

    if not command:
        return {"status": "error", "error": "No command provided"}

    # Parse first word to check if command is safe
    parts = command.split()
    base_cmd = parts[0].split("/")[-1] if parts else ""

    if base_cmd not in SAFE_SHELL_COMMANDS:
        return {
            "status": "error",
            "error": f"Command '{base_cmd}' not in safe list",
            "safe_commands": sorted(SAFE_SHELL_COMMANDS),
        }

    start_time = time_module.time()
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=working_dir,
        )
        execution_time = time_module.time() - start_time

        return {
            "status": "success",
            "exit_code": result.returncode,
            "stdout": result.stdout[:50000],  # Limit output size
            "stderr": result.stderr[:10000],
            "execution_time_seconds": round(execution_time, 3),
            "truncated": len(result.stdout) > 50000 or len(result.stderr) > 10000,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": f"Command timed out after {timeout} seconds",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# HTTP/HTTPS Requests
# -----------------------------------------------------------------------------


def _action_http_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute an HTTP/HTTPS request.

    Payload:
        url: str - The URL to request
        method: str - HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: dict - Optional headers
        body: str|dict - Optional request body
        timeout: int - Request timeout in seconds (default: 30)
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    url = payload.get("url", "").strip()
    method = payload.get("method", "GET").upper()
    headers = payload.get("headers", {})
    body = payload.get("body")
    timeout = min(payload.get("timeout", 30), 120)  # Max 2 minutes

    if not url:
        return {"status": "error", "error": "No URL provided"}

    if not url.startswith(("http://", "https://")):
        return {"status": "error", "error": "URL must start with http:// or https://"}

    # Prepare body
    data = None
    if body:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        start_time = time_module.time()

        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read()
            execution_time = time_module.time() - start_time

            # Try to decode as text
            try:
                body_text = response_body.decode("utf-8")[:50000]
                is_binary = False
            except UnicodeDecodeError:
                body_text = base64.b64encode(response_body[:10000]).decode("ascii")
                is_binary = True

            return {
                "status": "success",
                "status_code": response.status,
                "headers": dict(response.headers),
                "body": body_text,
                "is_binary": is_binary,
                "body_length": len(response_body),
                "truncated": len(response_body) > 50000,
                "execution_time_seconds": round(execution_time, 3),
            }
    except urllib.error.HTTPError as e:
        return {
            "status": "http_error",
            "status_code": e.code,
            "error": str(e.reason),
            "headers": dict(e.headers) if e.headers else {},
        }
    except urllib.error.URLError as e:
        return {"status": "error", "error": f"URL error: {e.reason}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# -----------------------------------------------------------------------------
# Device Status/Info
# -----------------------------------------------------------------------------


def _get_uptime_seconds() -> float:
    """Get system uptime in seconds."""
    try:
        if platform.system() == "Linux":
            with open("/proc/uptime") as f:
                return float(f.read().split()[0])
        elif platform.system() == "Darwin":  # macOS
            result = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5)
            # Parse "{ sec = 1234567890, usec = 123456 }"
            import re

            match = re.search(r"sec\s*=\s*(\d+)", result.stdout)
            if match:
                boot_time = int(match.group(1))
                return time_module.time() - boot_time
    except Exception:
        pass
    return -1


def _get_cpu_usage() -> float:
    """Get CPU usage percentage."""
    try:
        if platform.system() == "Linux":
            # Read /proc/stat twice with a small delay
            with open("/proc/stat") as f:
                line1 = f.readline()
            time_module.sleep(0.1)
            with open("/proc/stat") as f:
                line2 = f.readline()

            vals1 = [int(x) for x in line1.split()[1:8]]
            vals2 = [int(x) for x in line2.split()[1:8]]

            total1 = sum(vals1)
            total2 = sum(vals2)
            idle1 = vals1[3]
            idle2 = vals2[3]

            total_diff = total2 - total1
            idle_diff = idle2 - idle1

            if total_diff > 0:
                return round((1 - idle_diff / total_diff) * 100, 1)
        elif platform.system() == "Darwin":
            result = subprocess.run(["top", "-l", "1", "-n", "0"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                if "CPU usage" in line:
                    import re

                    match = re.search(r"(\d+\.?\d*)%\s*user.*?(\d+\.?\d*)%\s*sys", line)
                    if match:
                        return round(float(match.group(1)) + float(match.group(2)), 1)
    except Exception:
        pass
    return -1


def _get_memory_info() -> dict[str, Any]:
    """Get memory information."""
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = int(parts[1].strip().split()[0])  # Value in KB
                    info[key] = val

            total = info.get("MemTotal", 0)
            available = info.get("MemAvailable", info.get("MemFree", 0))
            used = total - available

            return {
                "total_gb": round(total / (1024 * 1024), 2),
                "available_gb": round(available / (1024 * 1024), 2),
                "used_gb": round(used / (1024 * 1024), 2),
                "used_percent": round((used / total) * 100, 1) if total > 0 else 0,
            }
        elif platform.system() == "Darwin":
            result = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5)
            page_size = 4096  # Typical macOS page size
            info = {}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    parts = line.split(":")
                    key = parts[0].strip()
                    val = parts[1].strip().rstrip(".")
                    try:
                        info[key] = int(val)
                    except ValueError:
                        pass

            pages_free = info.get("Pages free", 0)
            pages_active = info.get("Pages active", 0)
            pages_inactive = info.get("Pages inactive", 0)
            pages_wired = info.get("Pages wired down", 0)

            total_pages = pages_free + pages_active + pages_inactive + pages_wired
            used_pages = pages_active + pages_wired

            return {
                "total_gb": round((total_pages * page_size) / (1024**3), 2),
                "available_gb": round((pages_free * page_size) / (1024**3), 2),
                "used_gb": round((used_pages * page_size) / (1024**3), 2),
                "used_percent": round((used_pages / total_pages) * 100, 1) if total_pages > 0 else 0,
            }
    except Exception:
        pass
    return {}


def _get_network_interfaces() -> list[dict[str, Any]]:
    """Get network interface information."""
    interfaces = []
    try:
        import socket

        _hostname = socket.gethostname()  # noqa: F841 — kept for future use

        if platform.system() in ("Linux", "Darwin"):
            result = subprocess.run(
                ["ifconfig"] if platform.system() == "Darwin" else ["ip", "-o", "addr"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Simple parsing - just get interface names and IPs
            import re

            if platform.system() == "Darwin":
                current_iface = None
                for line in result.stdout.split("\n"):
                    if not line.startswith("\t") and ":" in line:
                        current_iface = line.split(":")[0]
                    elif "inet " in line and current_iface:
                        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            interfaces.append({"name": current_iface, "ipv4": match.group(1)})
            else:
                for line in result.stdout.split("\n"):
                    match = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        interfaces.append({"name": match.group(1), "ipv4": match.group(2)})
    except Exception:
        pass
    return interfaces


def _action_device_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Return comprehensive device status information."""
    disk = shutil.disk_usage("/")

    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "platform_release": platform.release(),
        "hostname": platform.node(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "uptime_seconds": _get_uptime_seconds(),
        "cpu_usage_percent": _get_cpu_usage(),
        "memory": _get_memory_info(),
        "disk": {
            "total_gb": round(disk.total / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "used_percent": round((disk.used / disk.total) * 100, 1),
        },
        "network_interfaces": _get_network_interfaces(),
        "timestamp": time_module.time(),
    }


# -----------------------------------------------------------------------------
# Camera Capture
# -----------------------------------------------------------------------------


def _detect_cameras() -> list[dict[str, Any]]:
    """Detect available cameras on the system."""
    cameras = []
    try:
        if platform.system() == "Linux":
            # Check /dev/video* devices
            for i in range(10):
                dev = f"/dev/video{i}"
                if os.path.exists(dev):
                    cameras.append({"device": dev, "index": i})
        elif platform.system() == "Darwin":
            # Use system_profiler to list cameras
            result = subprocess.run(
                ["system_profiler", "SPCameraDataType", "-json"], capture_output=True, text=True, timeout=10
            )
            try:
                data = json.loads(result.stdout)
                for cam in data.get("SPCameraDataType", []):
                    cameras.append(
                        {
                            "name": cam.get("_name", "Unknown"),
                            "model": cam.get("spcamera_model-id", ""),
                        }
                    )
            except json.JSONDecodeError:
                pass
    except Exception:
        pass
    return cameras


def _action_capture_photo(payload: dict[str, Any]) -> dict[str, Any]:
    """Capture a photo from the camera.

    Payload:
        device: str - Camera device (e.g., /dev/video0) or index
        resolution: str - Resolution (e.g., "1920x1080")
        output_format: str - Output format: "base64" or "file"
        output_path: str - File path if output_format is "file"
    """
    device = payload.get("device", 0)
    resolution = payload.get("resolution", "640x480")
    output_format = payload.get("output_format", "base64")
    output_path = payload.get("output_path", "/tmp/marvain_capture.jpg")

    cameras = _detect_cameras()
    if not cameras:
        return {"status": "error", "error": "No cameras detected"}

    try:
        # Try using ffmpeg (cross-platform)
        width, height = resolution.split("x")

        if platform.system() == "Darwin":
            # macOS uses avfoundation
            cmd = [
                "ffmpeg",
                "-y",
                "-f",
                "avfoundation",
                "-framerate",
                "30",
                "-video_size",
                resolution,
                "-i",
                str(device) if isinstance(device, int) else device,
                "-frames:v",
                "1",
                output_path,
            ]
        else:
            # Linux uses v4l2
            dev = device if isinstance(device, str) else f"/dev/video{device}"
            cmd = ["ffmpeg", "-y", "-f", "v4l2", "-video_size", resolution, "-i", dev, "-frames:v", "1", output_path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            return {
                "status": "error",
                "error": "ffmpeg capture failed",
                "stderr": result.stderr[:1000],
            }

        if output_format == "base64":
            with open(output_path, "rb") as f:
                image_data = base64.b64encode(f.read()).decode("ascii")
            os.remove(output_path)
            return {
                "status": "success",
                "format": "base64",
                "mime_type": "image/jpeg",
                "data": image_data,
                "resolution": resolution,
            }
        else:
            return {
                "status": "success",
                "format": "file",
                "path": output_path,
                "resolution": resolution,
            }
    except FileNotFoundError:
        return {"status": "error", "error": "ffmpeg not found - install ffmpeg for camera capture"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Capture timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _action_capture_video(payload: dict[str, Any]) -> dict[str, Any]:
    """Capture a video from the camera.

    Payload:
        device: str - Camera device (e.g., /dev/video0) or index
        duration: int - Recording duration in seconds (max 60)
        resolution: str - Resolution (e.g., "1920x1080")
        output_path: str - File path for output
    """
    device = payload.get("device", 0)
    duration = min(payload.get("duration", 5), 60)  # Max 60 seconds
    resolution = payload.get("resolution", "640x480")
    output_path = payload.get("output_path", "/tmp/marvain_video.mp4")

    cameras = _detect_cameras()
    if not cameras:
        return {"status": "error", "error": "No cameras detected"}

    try:
        if platform.system() == "Darwin":
            cmd = [
                "ffmpeg",
                "-y",
                "-f",
                "avfoundation",
                "-framerate",
                "30",
                "-video_size",
                resolution,
                "-i",
                str(device) if isinstance(device, int) else device,
                "-t",
                str(duration),
                "-c:v",
                "libx264",
                "-preset",
                "fast",
                output_path,
            ]
        else:
            dev = device if isinstance(device, str) else f"/dev/video{device}"
            cmd = [
                "ffmpeg",
                "-y",
                "-f",
                "v4l2",
                "-video_size",
                resolution,
                "-i",
                dev,
                "-t",
                str(duration),
                "-c:v",
                "libx264",
                "-preset",
                "fast",
                output_path,
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)

        if result.returncode != 0:
            return {
                "status": "error",
                "error": "ffmpeg capture failed",
                "stderr": result.stderr[:1000],
            }

        file_size = os.path.getsize(output_path)
        return {
            "status": "success",
            "path": output_path,
            "duration_seconds": duration,
            "resolution": resolution,
            "file_size_bytes": file_size,
        }
    except FileNotFoundError:
        return {"status": "error", "error": "ffmpeg not found - install ffmpeg for video capture"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Capture timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _action_list_cameras(payload: dict[str, Any]) -> dict[str, Any]:
    """List available cameras on the device."""
    cameras = _detect_cameras()
    return {
        "status": "success",
        "cameras": cameras,
        "count": len(cameras),
    }


# -----------------------------------------------------------------------------
# File Operations (Read-Only)
# -----------------------------------------------------------------------------


def _action_read_file(payload: dict[str, Any]) -> dict[str, Any]:
    """Read contents of a file.

    Payload:
        path: str - File path to read
        max_size: int - Maximum bytes to read (default: 1MB)
        encoding: str - Text encoding (default: utf-8, use "binary" for base64)
    """
    file_path = payload.get("path", "").strip()
    max_size = min(payload.get("max_size", 1024 * 1024), 10 * 1024 * 1024)  # Max 10MB
    encoding = payload.get("encoding", "utf-8")

    if not file_path:
        return {"status": "error", "error": "No path provided"}

    path = Path(file_path)
    if not path.exists():
        return {"status": "error", "error": f"File not found: {file_path}"}

    if not path.is_file():
        return {"status": "error", "error": f"Not a file: {file_path}"}

    try:
        file_size = path.stat().st_size
        truncated = file_size > max_size

        if encoding == "binary":
            with open(path, "rb") as f:
                data = f.read(max_size)
            content = base64.b64encode(data).decode("ascii")
            return {
                "status": "success",
                "path": str(path.absolute()),
                "content": content,
                "encoding": "base64",
                "size_bytes": file_size,
                "truncated": truncated,
            }
        else:
            with open(path, "r", encoding=encoding) as f:
                content = f.read(max_size)
            return {
                "status": "success",
                "path": str(path.absolute()),
                "content": content,
                "encoding": encoding,
                "size_bytes": file_size,
                "truncated": truncated,
            }
    except UnicodeDecodeError:
        return {"status": "error", "error": f"Cannot decode file as {encoding}. Try encoding='binary'"}
    except PermissionError:
        return {"status": "error", "error": f"Permission denied: {file_path}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _action_list_directory(payload: dict[str, Any]) -> dict[str, Any]:
    """List contents of a directory.

    Payload:
        path: str - Directory path to list
        include_hidden: bool - Include hidden files (default: False)
        max_items: int - Maximum items to return (default: 500)
    """
    dir_path = payload.get("path", ".").strip()
    include_hidden = payload.get("include_hidden", False)
    max_items = min(payload.get("max_items", 500), 1000)

    path = Path(dir_path)
    if not path.exists():
        return {"status": "error", "error": f"Path not found: {dir_path}"}

    if not path.is_dir():
        return {"status": "error", "error": f"Not a directory: {dir_path}"}

    try:
        items = []
        for i, entry in enumerate(sorted(path.iterdir())):
            if i >= max_items:
                break

            name = entry.name
            if not include_hidden and name.startswith("."):
                continue

            try:
                stat = entry.stat()
                items.append(
                    {
                        "name": name,
                        "type": "directory" if entry.is_dir() else "file",
                        "size_bytes": stat.st_size if entry.is_file() else None,
                        "modified": stat.st_mtime,
                    }
                )
            except (PermissionError, OSError):
                items.append(
                    {
                        "name": name,
                        "type": "unknown",
                        "error": "permission_denied",
                    }
                )

        return {
            "status": "success",
            "path": str(path.absolute()),
            "items": items,
            "count": len(items),
            "truncated": len(list(path.iterdir())) > max_items,
        }
    except PermissionError:
        return {"status": "error", "error": f"Permission denied: {dir_path}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _action_file_info(payload: dict[str, Any]) -> dict[str, Any]:
    """Get detailed information about a file or directory.

    Payload:
        path: str - Path to get info for
    """
    file_path = payload.get("path", "").strip()

    if not file_path:
        return {"status": "error", "error": "No path provided"}

    path = Path(file_path)
    if not path.exists():
        return {"status": "error", "error": f"Path not found: {file_path}"}

    try:
        stat = path.stat()

        info = {
            "status": "success",
            "path": str(path.absolute()),
            "name": path.name,
            "type": "directory" if path.is_dir() else "file" if path.is_file() else "other",
            "size_bytes": stat.st_size,
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
            "accessed": stat.st_atime,
            "mode": oct(stat.st_mode),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "is_symlink": path.is_symlink(),
        }

        if path.is_symlink():
            info["symlink_target"] = str(path.resolve())

        if path.is_file():
            # Try to detect MIME type
            import mimetypes

            mime_type, _ = mimetypes.guess_type(str(path))
            info["mime_type"] = mime_type

        return info
    except PermissionError:
        return {"status": "error", "error": f"Permission denied: {file_path}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# Registry of supported device actions
DEVICE_ACTIONS: dict[str, Any] = {
    # Basic actions
    "ping": _action_ping,
    "status": _action_status,
    "echo": _action_echo,
    # Enhanced actions
    "shell_command": _action_shell_command,
    "http_request": _action_http_request,
    "device_status": _action_device_status,
    # Camera actions
    "capture_photo": _action_capture_photo,
    "capture_video": _action_capture_video,
    "list_cameras": _action_list_cameras,
    # File operations
    "read_file": _action_read_file,
    "list_directory": _action_list_directory,
    "file_info": _action_file_info,
}


# -----------------------------------------------------------------------------
# Configuration State
# -----------------------------------------------------------------------------

_device_config: dict[str, Any] = {}


def get_device_config() -> dict[str, Any]:
    """Get the current device configuration."""
    return _device_config.copy()


# -----------------------------------------------------------------------------
# Command Handler
# -----------------------------------------------------------------------------


async def handle_command(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Handle incoming device commands.

    Supports:
    - cmd.run_action: Execute device-local actions (ping, status, echo, etc.)
    - cmd.config: Apply configuration updates

    Add custom device-specific functionality by extending DEVICE_ACTIONS.
    """
    global _device_config
    msg_type = msg.get("type", "")

    if msg_type == "cmd.run_action":
        kind = msg.get("kind", "")
        payload = msg.get("payload", {})
        logger.info("Received run_action command: kind=%s", kind)

        if kind in DEVICE_ACTIONS:
            try:
                handler = DEVICE_ACTIONS[kind]
                result = handler(payload)
                return {
                    "action": "action_result",
                    "kind": kind,
                    "status": "success",
                    "result": result,
                }
            except Exception as e:
                logger.exception("Error executing action %s", kind)
                return {
                    "action": "action_result",
                    "kind": kind,
                    "status": "error",
                    "error": str(e),
                }
        else:
            return {
                "action": "action_result",
                "kind": kind,
                "status": "unsupported",
                "message": f"Action kind '{kind}' not supported. Supported: {list(DEVICE_ACTIONS.keys())}",
            }

    elif msg_type == "cmd.config":
        config_data = msg.get("config", {})
        logger.info("Received config update: %s", config_data)

        # Merge new config with existing config
        _device_config.update(config_data)

        return {
            "action": "config_ack",
            "status": "applied",
            "config_keys": list(config_data.keys()),
        }

    return None


def load_config_file(path: str) -> dict[str, Any]:
    """Load configuration from YAML file."""
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


@click.command()
@click.option(
    "--hub-ws-url",
    envvar="MARVAIN_HUB_WS_URL",
    required=True,
    help="WebSocket URL of the Marvain Hub (e.g., wss://api.example.com/ws)",
)
@click.option(
    "--hub-rest-url",
    envvar="MARVAIN_HUB_REST_URL",
    default=None,
    help="REST API URL of the Marvain Hub (optional, for heartbeat endpoint)",
)
@click.option(
    "--device-token",
    envvar="MARVAIN_DEVICE_TOKEN",
    required=True,
    help="Device authentication token from the Hub",
)
@click.option(
    "--heartbeat-interval",
    envvar="MARVAIN_HEARTBEAT_INTERVAL",
    default=20,
    type=int,
    help="Heartbeat interval in seconds (default: 20)",
)
@click.option(
    "--config-file",
    envvar="MARVAIN_CONFIG_FILE",
    default=None,
    type=click.Path(exists=False),
    help="Path to YAML configuration file",
)
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(
    hub_ws_url: str,
    hub_rest_url: str | None,
    device_token: str,
    heartbeat_interval: int,
    config_file: str | None,
    debug: bool,
) -> None:
    """Marvain Remote Satellite Daemon.

    Connects to a Marvain Hub and acts as a remote device, sending heartbeats
    and responding to commands.
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load config file if provided (overrides CLI args)
    if config_file:
        file_config = load_config_file(config_file)
        hub_ws_url = file_config.get("hub_ws_url", hub_ws_url)
        hub_rest_url = file_config.get("hub_rest_url", hub_rest_url)
        device_token = file_config.get("device_token", device_token)
        heartbeat_interval = file_config.get("heartbeat_interval", heartbeat_interval)

    logger.info("Starting Marvain Remote Satellite Daemon")
    logger.info("Hub WebSocket URL: %s", hub_ws_url)
    logger.info("Heartbeat interval: %d seconds", heartbeat_interval)

    config = HubClientConfig(
        ws_url=hub_ws_url,
        rest_url=hub_rest_url,
        device_token=device_token,
        heartbeat_interval=heartbeat_interval,
    )

    client = HubClient(config, on_command=handle_command)

    # Handle shutdown gracefully
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown_handler(sig: signal.Signals) -> None:
        logger.info("Received signal %s, shutting down...", sig.name)
        loop.create_task(client.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_handler, sig)

    try:
        loop.run_until_complete(client.run())
    finally:
        loop.close()
        logger.info("Satellite daemon stopped")


if __name__ == "__main__":
    main()
