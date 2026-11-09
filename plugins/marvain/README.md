# Marvain plugin connection

The plugin uses an OAuth-linked Marvain account over remote Streamable HTTP. A dot can use enabled plugins within its linked account and workspace permissions. The workspace and personal dot selected during setup are administrative choices. The access token authenticates the linked Marvain principal for this resource and OAuth client. The bridge uses that principal's provisioned software-actor association and returns Marvain-issued run identities. Native dot conversations and notes remain in ChatGPT. [Dot app connections](https://learn.chatgpt.com/docs/dots/computers-and-apps) · [Custom MCP servers](https://developers.openai.com/api/docs/guides/custom-mcp-server)

## Connection inputs

- Select the intended ChatGPT workspace and personal dot and confirm the workspace permits the custom plugin and its tool actions.
- Select the public HTTPS MCP URL and a dedicated Cognito client. Configure authorization-code flow with PKCE `S256`, OAuth discovery, the exact redirect URI shown by ChatGPT and the scopes for run creation, recall and recording updates. The token must carry the exact MCP URL as `aud`. The example manifest uses a registered public client. Choose the actual client's declared token authentication method during connection setup. Keep any client secret in that setup flow. [OpenAI plugin authentication](https://developers.openai.com/plugins/build/auth) · [Plugin packaging](https://developers.openai.com/plugins/build/plugins)
- Bind the signed Cognito issuer and subject to the persisted Marvain software actor, tenant and principal. Provision each authorized scene with its conversation session and explicit immutable update policy, including audience and retention. The canonical backend resolves the actor, principal and scene relationships in TapDB and enforces the governing policies for each operation.
- Start the dedicated ASGI service through the configured Marvain entrypoint once authorized. `create_dot_mcp_app(config, bridge)` supplies the MCP path, OAuth protected-resource metadata and SDK lifespan. Register the actual server URL through **Add custom MCP server** in the selected ChatGPT workspace. If using manifest packaging, copy `mcp.json.example` to `mcp.json` with the actual URL and OAuth client registration before packaging.

## Tools

| Tool | Input | Result |
| --- | --- | --- |
| `begin_run` | Authorized `scene_euid`, stable `request_key` | Persisted Marvain run EUID and scene |
| `recall` | Run EUID, query | Current episode detail granted to the linked principal for the run's scene |
| `record_update` | Run EUID, stable `request_key`, update text | Persisted evidence EUID attributed to the linked software actor and run |

Use the same request key and inputs when retrying a write. The update's observation time is when Marvain received the submission. Text that mentions another person, event or time is attributed to the submitting software actor. The tool receives only the model arguments in the table. The service resolves authorization, scene, session and audience.

## Event source and activation prerequisites

The `marvain.handoff.ready` source event carries the persisted handoff and scene EUIDs to the explicitly addressed principal. Its occurrence time and event ID come from the committed handoff transition. The envelope supports a webhook with no replay cursor. A webhook receipt is separate from review, execution or acknowledgment of the handoff. [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)

Before enabling delivery, select the subscription owner and confirm MCP Events eligibility for that account and dot. Integrate the draft event discovery, subscribe and unsubscribe methods into the authenticated MCP endpoint, and grant only the selected scene filter. The delivery service must persist subscription owner, filter, callback, signing secret and expiration. It must implement the documented HTTPS destination validation and signed callback challenge, sign deliveries using Standard Webhooks, and honor refresh, expiry, unsubscribe and revocation. It should preserve the source event ID when the protocol calls for retrying delivery. Subscribe and send only under separate activation authority. The tool service exposes its tool and OAuth routes. The source event catalog and envelope are available for the future delivery service.
