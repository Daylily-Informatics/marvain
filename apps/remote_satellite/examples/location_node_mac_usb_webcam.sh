#!/usr/bin/env bash
set -euo pipefail

# Example: Run Marvain Remote Satellite in Location Node mode on macOS with a USB webcam.
#
# This joins a *stable* LiveKit room for a space (room == space_id), publishes mic/cam,
# and plays remote audio tracks (agent speech) to the speakers.
#
# Required environment variables:
#   MARVAIN_DEVICE_TOKEN
#   MARVAIN_SPACE_ID
#
# Hub URLs (set explicitly OR auto-resolve via `marvain config show` if available):
#   MARVAIN_HUB_WS_URL
#   MARVAIN_HUB_REST_URL
#
# Optional:
#   MARVAIN_CAMERA_USB_INDEX (default: 0)
#   MARVAIN_ENABLE_VIDEO=1|0 (default: 1)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${SAT_DIR}"

die() {
  echo "error: $*" >&2
  exit 2
}

HUB_WS_URL="${MARVAIN_HUB_WS_URL:-}"
HUB_REST_URL="${MARVAIN_HUB_REST_URL:-}"

# Best-effort hub URL auto-discovery for convenience (requires marvain CLI + config on this machine).
if [[ -z "${HUB_WS_URL}" || -z "${HUB_REST_URL}" ]]; then
  if command -v marvain >/dev/null 2>&1; then
    HUB_WS_URL="${HUB_WS_URL:-$(
      marvain config show 2>/dev/null \
        | python -c 'import json,sys; print(json.load(sys.stdin)["env_config"]["resources"]["HubWebSocketUrl"])' 2>/dev/null \
        || true
    )}"
    HUB_REST_URL="${HUB_REST_URL:-$(
      marvain config show 2>/dev/null \
        | python -c 'import json,sys; print(json.load(sys.stdin)["env_config"]["resources"]["HubRestApiBase"])' 2>/dev/null \
        || true
    )}"
  fi
fi

[[ -n "${HUB_WS_URL}" ]] || die "Set MARVAIN_HUB_WS_URL (or install/configure the marvain CLI on this machine)."
[[ -n "${HUB_REST_URL}" ]] || die "Set MARVAIN_HUB_REST_URL (or install/configure the marvain CLI on this machine)."
[[ -n "${MARVAIN_DEVICE_TOKEN:-}" ]] || die "Set MARVAIN_DEVICE_TOKEN."
[[ -n "${MARVAIN_SPACE_ID:-}" ]] || die "Set MARVAIN_SPACE_ID."

for v in HUB_WS_URL HUB_REST_URL MARVAIN_DEVICE_TOKEN MARVAIN_SPACE_ID; do
  val="${!v}"
  if [[ "${val}" == *"<"* || "${val}" == *">"* ]]; then
    die "$v still contains a placeholder: ${val}"
  fi
done

ENABLE_VIDEO="${MARVAIN_ENABLE_VIDEO:-1}"
CAM_INDEX="${MARVAIN_CAMERA_USB_INDEX:-0}"

echo "Using:"
echo "  hub ws:   ${HUB_WS_URL}"
echo "  hub rest: ${HUB_REST_URL}"
echo "  space:    ${MARVAIN_SPACE_ID}"
echo "  video:    ${ENABLE_VIDEO}"
echo "  cam idx:  ${CAM_INDEX}"
echo

# Optional sanity check (public endpoint).
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsS "${HUB_REST_URL%/}/health" >/dev/null; then
    echo "warning: hub health check failed: ${HUB_REST_URL%/}/health" >&2
  fi
fi

# Install minimal dependencies for daemon + Location Node.
python -m pip install -r requirements.txt
python -m pip install livekit sounddevice numpy

EXTRA_ARGS=()
if [[ "${ENABLE_VIDEO}" == "1" ]]; then
  python -m pip install opencv-python pillow
  EXTRA_ARGS+=(--publish-video --camera-usb-index "${CAM_INDEX}")
fi

exec python daemon.py \
  --hub-ws-url "${HUB_WS_URL}" \
  --hub-rest-url "${HUB_REST_URL}" \
  --device-token "${MARVAIN_DEVICE_TOKEN}" \
  --space-id "${MARVAIN_SPACE_ID}" \
  --publish-audio \
  --subscribe-audio \
  "${EXTRA_ARGS[@]}"

