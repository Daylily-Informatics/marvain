# Observability SLOs

## Metrics

1. `BroadcastDelivered` and `BroadcastDropped` track fanout delivery outcomes.
2. `CommandDispatchLatencyMs` tracks hub-to-device dispatch latency.
3. `CommandResultLatencyMs` tracks device command completion latency.
4. `ActionExecutionCount` tracks action outcomes by kind and status.
5. `DeviceFreshnessLagMs` tracks `now - last_heartbeat_at`.
6. `DeviceTimeout` tracks actions that timed out awaiting device completion.

## SLO Targets

1. Broadcast success rate >= 99.5% over 5 minutes.
2. P95 command result latency <= 15 seconds over 15 minutes.
3. Device timeout rate <= 2% of dispatched device actions over 15 minutes.
4. Device freshness lag P95 <= 60 seconds for online devices.

## Alarm Triage

1. Check `WsMessageFunction`, `ToolRunnerFunction`, and `ActionTimeoutSweeperFunction` CloudWatch logs.
2. Confirm `WS_API_ENDPOINT` and subscription table env vars are present in deployed Lambdas.
3. Validate WebSocket connection table/subscription index health and stale-connection cleanup.
4. Inspect action rows in `awaiting_device_result` and `device_acknowledged` to isolate stuck devices.
