# Marvain plugin connection

The plugin uses an OAuth-linked Marvain account over remote Streamable HTTP. A dot can use enabled plugins within its linked account and workspace permissions. The workspace and personal dot selected during setup are administrative choices. The access token authenticates the linked Marvain principal for this resource and OAuth client. The bridge uses that principal's provisioned software-actor association and returns Marvain-issued run identities. Native dot conversations and notes remain in ChatGPT. [Dot app connections](https://learn.chatgpt.com/docs/dots/computers-and-apps) · [Custom MCP servers](https://developers.openai.com/api/docs/guides/custom-mcp-server)

## Connection inputs

- Select the intended ChatGPT workspace and personal dot and confirm the workspace permits the custom plugin and its tool actions.
- Select the public HTTPS MCP URL and a dedicated Cognito client. Configure authorization-code flow with PKCE `S256`, OAuth discovery, the exact redirect URI shown by ChatGPT and the scopes for run creation, recall and recording updates. The token must carry the exact MCP URL as `aud`. The example manifest uses a registered public client. Choose the actual client's declared token authentication method during connection setup. Keep any client secret in that setup flow. [OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth) · [Plugin packaging](https://developers.openai.com/plugins/build/plugins)
- Bind the signed Cognito issuer and subject to the persisted Marvain software actor, tenant and principal. Provision each authorized scene with its conversation session and explicit immutable update policy, including audience and retention. The canonical backend resolves the actor, principal and scene relationships in TapDB and enforces the governing policies for each operation.
- Start the dedicated ASGI service with `marvain dot serve` and the selected absolute binding file once authorized. Register the actual server URL through **Add custom MCP server** in the selected ChatGPT workspace. For manifest packaging, copy the example manifest to `/Users/jmajor/projects/marvain/plugins/marvain/mcp.json` and supply the actual URL and OAuth client registration. [/Users/jmajor/projects/marvain/plugins/marvain/mcp.json.example](/Users/jmajor/projects/marvain/plugins/marvain/mcp.json.example)

## Tools

| Tool | Input | Result |
| --- | --- | --- |
| `begin_run` | Authorized `scene_euid`, stable `request_key` | Persisted Marvain run EUID and scene |
| `recall` | `run_euid`, `source_scene_euid`, `query` | Selected source scene EUID and current, authorized episode detail from that scene |
| `record_update` | Run EUID, stable `request_key`, update text | Persisted evidence EUID attributed to the linked software actor and run |

Use the same request key and inputs when retrying a write. The update's observation time is when Marvain received the submission. Text that mentions another person, event or time is attributed to the submitting software actor. The tool receives only the model arguments in the table. The service resolves authorization, scene, session and audience.

Recall authorizes the run independently of the selected source scene. Choose a source from the linked account's configured scene and session bindings. A retained closed scene can supply recall when its governing audience, retention and recall permissions still allow it.

## Handoff events

With events enabled, the authenticated MCP endpoint exposes `events/list`, `events/subscribe` and `events/unsubscribe` for `marvain.handoff.ready`. Repeating `events/subscribe` refreshes a subscription. Subscriptions select one authorized scene and store their owner, callback, encrypted signing key and expiry in Marvain's transport tables. The endpoint verifies the HTTPS callback with a signed challenge and supports signing key rotation. [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)

The writer records delivery intent in the same transaction as the canonical handoff. After commit it checks the recipient's current access and sends the handoff and scene EUIDs using Standard Webhooks. The event ID comes from the persisted handoff and stays stable across retries. The webhook uses `cursor: null`. A callback's `2xx` records receipt. Handoff execution, review and acknowledgment remain separate states.

Transient callback failures use the existing TapDB writer SQS retry cadence and bounded redrive to its dead-letter queue. HTTP `410` and `413` end that delivery attempt sequence. A callback failure leaves the canonical handoff's written receipt intact. Per-callback exponential backoff remains an open requirement from the OpenAI delivery guide. [Delivery responses](https://developers.openai.com/plugins/build/mcp-events#handle-delivery-responses)

### Activation inputs

- Set `dot.events_mode` in the binding file and `DotEventsMode` for the writer deployment to `enabled` or `disabled`. With `enabled`, set `dot.events_secret_arn` and `DotEventsSecretArn` to the selected shared secret. The writer receives these as `MARVAIN_DOT_EVENTS_MODE` and `MARVAIN_DOT_EVENTS_SECRET_ARN`. Disabled mode serves the tools and OAuth metadata.
- Provide a secret JSON object with `encryption_key` and a `settings` object. Settings require `event_scope`, `callback_hosts`, `subscription_ttl_ms`, `verification_cache_seconds`, `rotation_seconds` and `callback_timeout_seconds`. Use the event scope granted by the Cognito client and the exact approved callback DNS hosts. Keep the encryption key in Secrets Manager.
- Provision the Marvain subscription and delivery tables through the fresh schema initialization. Provide outbound public HTTPS access from the MCP service for callback verification and from the writer for delivery. The existing private writer placement needs a selected egress path.
- Confirm the intended account, personal dot and workspace policy permit MCP Events. Under separate live authorization, enable the feature and have the subscription owner request the scene-filtered subscription through ChatGPT. [Dot app connections](https://learn.chatgpt.com/docs/dots/computers-and-apps) · [MCP Events availability](https://developers.openai.com/plugins/build/mcp-events#before-you-start)
