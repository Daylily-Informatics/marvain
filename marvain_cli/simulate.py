from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from cli_core_yo import output
from cli_core_yo.runtime import get_context
from typer import Option


@dataclass(frozen=True)
class SimulatedDevice:
    label: str
    location: str
    space: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class SimulatedCommand:
    label: str
    utterance: str
    required_capability: str
    target_space: str


_DEVICES = (
    SimulatedDevice(
        label="kitchen-display",
        location="home",
        space="kitchen",
        capabilities=("audio.speak", "display.show", "device.notify"),
    ),
    SimulatedDevice(
        label="studio-speaker",
        location="home",
        space="studio",
        capabilities=("audio.speak", "device.notify", "session.listen"),
    ),
)

_COMMANDS = (
    SimulatedCommand(
        label="announce-dinner",
        utterance="Tell the kitchen that dinner is ready.",
        required_capability="audio.speak",
        target_space="kitchen",
    ),
    SimulatedCommand(
        label="show-reminder",
        utterance="Put the reminder on the kitchen display.",
        required_capability="display.show",
        target_space="kitchen",
    ),
    SimulatedCommand(
        label="studio-check-in",
        utterance="Ask the studio whether anyone is still recording.",
        required_capability="audio.speak",
        target_space="studio",
    ),
)


def _id(seed: str, label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"marvain:simulate:{seed}:{label}"))


def _device_dict(seed: str, device: SimulatedDevice) -> dict[str, Any]:
    return {
        "device_id": _id(seed, f"device:{device.label}"),
        "name": device.label,
        "location": {
            "location_id": _id(seed, f"location:{device.location}"),
            "name": device.location,
        },
        "space": {
            "space_id": _id(seed, f"space:{device.space}"),
            "name": device.space,
        },
        "capabilities": list(device.capabilities),
        "connection_state": "online",
    }


def build_two_devices_report(
    seed: str = "marvain-simulate-two-devices-v1",
    *,
    agent_id: str | None = None,
    location_a: str = "home",
    space_a: str = "kitchen",
    location_b: str = "home",
    space_b: str = "studio",
) -> dict[str, Any]:
    device_a = SimulatedDevice(
        label="device-a",
        location=location_a,
        space=space_a,
        capabilities=("audio.speak", "display.show", "device.notify"),
    )
    device_b = SimulatedDevice(
        label="device-b",
        location=location_b,
        space=space_b,
        capabilities=("audio.speak", "device.notify", "session.listen"),
    )
    commands = (
        SimulatedCommand(
            label="announce-primary",
            utterance=f"Tell {space_a} that dinner is ready.",
            required_capability="audio.speak",
            target_space=space_a,
        ),
        SimulatedCommand(
            label="show-primary-reminder",
            utterance=f"Put the reminder on the {space_a} display.",
            required_capability="display.show",
            target_space=space_a,
        ),
        SimulatedCommand(
            label="secondary-check-in",
            utterance=f"Ask {space_b} whether anyone is still recording.",
            required_capability="audio.speak",
            target_space=space_b,
        ),
    )
    devices = [_device_dict(seed, item) for item in (device_a, device_b)]
    routes: list[dict[str, Any]] = []

    for command in commands:
        candidates = [
            device
            for device in devices
            if device["space"]["name"] == command.target_space
            and command.required_capability in set(device["capabilities"])
            and device["connection_state"] == "online"
        ]
        selected = candidates[0] if candidates else None
        routes.append(
            {
                "command_id": _id(seed, f"command:{command.label}"),
                "label": command.label,
                "utterance": command.utterance,
                "target_space": command.target_space,
                "required_capability": command.required_capability,
                "selected_device_id": selected["device_id"] if selected else None,
                "selected_device_name": selected["name"] if selected else None,
                "status": "routed" if selected else "unroutable",
                "reason": "space_and_capability_match" if selected else "no_online_device_matches_space_and_capability",
            }
        )

    location_names = tuple(dict.fromkeys((location_a, location_b)))
    space_specs = ((space_a, location_a), (space_b, location_b))

    return {
        "simulation": "two-devices",
        "seed": seed,
        "deterministic": True,
        "agent_id": agent_id or _id(seed, "agent"),
        "locations": [{"location_id": _id(seed, f"location:{name}"), "name": name} for name in location_names],
        "spaces": [
            {"space_id": _id(seed, f"space:{name}"), "location": location, "name": name}
            for name, location in space_specs
        ],
        "devices": devices,
        "routes": routes,
        "summary": {
            "device_count": len(devices),
            "command_count": len(routes),
            "routed_count": sum(1 for route in routes if route["status"] == "routed"),
            "unroutable_count": sum(1 for route in routes if route["status"] != "routed"),
        },
    }


def two_devices_cmd(
    seed: str = Option("marvain-simulate-two-devices-v1", "--seed", help="Deterministic simulation seed"),
    agent_id: str | None = Option(None, "--agent-id", help="Agent ID to show in the simulation report"),
    location_a: str = Option("home", "--location-a", help="Location name for simulated device A"),
    space_a: str = Option("kitchen", "--space-a", help="Space name for simulated device A"),
    location_b: str = Option("home", "--location-b", help="Location name for simulated device B"),
    space_b: str = Option("studio", "--space-b", help="Space name for simulated device B"),
) -> None:
    """Return a deterministic two-device command-routing simulation."""
    data = build_two_devices_report(
        seed=seed,
        agent_id=agent_id,
        location_a=location_a,
        space_a=space_a,
        location_b=location_b,
        space_b=space_b,
    )
    if get_context().json_mode:
        output.emit_json(data)
        return
    output.print_text(json.dumps(data, indent=2, sort_keys=True))
