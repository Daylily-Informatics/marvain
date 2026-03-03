# Phase 3: Location-Aware Device Provisioning Wizard

> **Parent plan**: [GUI_OVERHAUL_PLAN.md](../GUI_OVERHAUL_PLAN.md)
> **Risk**: Medium — DB migration + new API endpoints
> **Depends on**: Phase 1 (macros), Phase 2 (dashboard shows device health)

## Overview

Add "location" concept to devices. Create a streamlined wizard flow for: (1) name the location, (2) select or create device, (3) configure scopes, (4) generate & copy config, (5) one-click satellite launch. Group devices by location in the devices view.

## Scope

- `sql/011_device_locations.sql` — new migration adding `location` JSONB to devices (label, coordinates, timezone, area)
- `functions/hub_api/app.py` — new endpoint `POST /api/devices/provision-location`, update `gui_devices()` to group by location
- `functions/hub_api/templates/devices.html` — add location grouping, provision wizard modal
- `apps/remote_satellite/daemon.py` — accept `--location-label` CLI flag, include in heartbeat metadata
- `layers/shared/python/agent_hub/tools/device_command.py` — accept optional `location` filter

## Definition of Done

- Devices can have a `location` with label, optional coords, timezone, area
- Provision wizard: 5 steps, generates a one-liner install command for the remote device
- Devices page shows devices grouped by location (with "Unassigned" group for legacy)
- Satellite daemon reports location label in heartbeat metadata
- CLI: `marvain device add-location --name "Kitchen" --agent <id>` works

## Migration SQL

```sql
-- sql/011_device_locations.sql
ALTER TABLE devices ADD COLUMN IF NOT EXISTS location jsonb DEFAULT '{}'::jsonb;
COMMENT ON COLUMN devices.location IS 'Location metadata: {label, coordinates: {lat, lng}, timezone, area}';
CREATE INDEX IF NOT EXISTS devices_location_label_idx ON devices ((location->>'label')) WHERE location->>'label' IS NOT NULL;
```

## Verification

```bash
# Validate migration SQL
python -c "import json; print('SQL valid')"

# Create a device with location via API
curl -X POST http://localhost:8443/api/devices -H 'Content-Type: application/json' \
  -d '{"agent_id":"...","name":"kitchen-pi","scopes":[],"location":{"label":"Kitchen"}}'

# Run satellite daemon with --location-label
python apps/remote_satellite/daemon.py --hub-ws-url wss://... --location-label "Kitchen"

# Verify heartbeat contains location
```

