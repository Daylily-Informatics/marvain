# Marvain Remote Satellite Daemon

A lightweight daemon that runs on remote devices (Raspberry Pi, NUC, etc.) and connects to the Marvain Hub via WebSocket. It reports heartbeats, responds to pings, and can execute device-local tools when commanded by the Hub.

## Features

- **WebSocket Connection**: Maintains persistent connection to Hub
- **Automatic Reconnection**: Exponential backoff on connection failure
- **Heartbeat**: Sends periodic pings to indicate online status
- **Command Response**: Responds to `cmd.ping`, `cmd.run_action`, `cmd.config`
- **Extensible**: Add device-specific tools and sensors

## Installation

### From Source

```bash
cd apps/remote_satellite
pip install -r requirements.txt
```

### As a Systemd Service (Linux)

```bash
sudo cp marvain-satellite.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable marvain-satellite
sudo systemctl start marvain-satellite
```

## Usage

### Command Line

```bash
python daemon.py \
  --hub-ws-url wss://your-hub.example.com/ws \
  --device-token YOUR_DEVICE_TOKEN \
  --heartbeat-interval 20
```

### Environment Variables

```bash
export MARVAIN_HUB_WS_URL="wss://your-hub.example.com/ws"
export MARVAIN_DEVICE_TOKEN="YOUR_DEVICE_TOKEN"
export MARVAIN_HEARTBEAT_INTERVAL=20
python daemon.py
```

### Configuration File

Create `config.yaml`:

```yaml
hub_ws_url: wss://your-hub.example.com/ws
device_token: YOUR_DEVICE_TOKEN
heartbeat_interval: 20
```

Then run:

```bash
python daemon.py --config-file config.yaml
```

## Getting a Device Token

1. Log into the Marvain Hub GUI
2. Navigate to **Devices**
3. Click **Register Device**
4. Copy the generated device token

**Important**: The token is shown only once. Store it securely.

## Adding Device-Local Tools

Edit `daemon.py` and modify the `handle_command()` function:

```python
async def handle_command(msg: dict[str, Any]) -> dict[str, Any] | None:
    msg_type = msg.get("type", "")

    if msg_type == "cmd.run_action":
        kind = msg.get("kind", "")
        payload = msg.get("payload", {})

        if kind == "capture_photo":
            # Your camera capture logic here
            photo_path = await capture_photo()
            return {
                "action": "action_result",
                "kind": kind,
                "status": "success",
                "result": {"path": photo_path},
            }

        # ... handle other action kinds

    return None
```

## Troubleshooting

### Connection Refused

- Verify the WebSocket URL is correct
- Check that the Hub is running and accessible
- Ensure firewalls allow WebSocket connections

### Authentication Failed

- Verify the device token is correct
- Check that the device hasn't been revoked in the Hub
- Ensure the device's scopes include required permissions

### Debug Mode

Run with `--debug` for verbose logging:

```bash
python daemon.py --debug --hub-ws-url ... --device-token ...
```

## License

MIT License - See main repository LICENSE file.

