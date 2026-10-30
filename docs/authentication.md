# Authentication and private MCP gateways

Firewalla MCP supports stdio and Streamable HTTP. Local stdio clients launch the process directly; remote clients can connect through a private MCP gateway. The backend implements bearer authentication, not a complete OAuth/OIDC login service.

A private gateway deployment has been validated. The following is a vendor-neutral integration contract, not a promise that every gateway or identity provider supports the same configuration. Verify the installed products' MCP transport, authorization, discovery and client-registration capabilities before applying it.

## Three separate trust boundaries

```text
MCP client ── user authorization ──> MCP gateway
MCP gateway ── dedicated bearer ──> Firewalla MCP /mcp
Firewalla MCP ── dedicated SSH key + verified host key ──> router
```

- **Client to gateway:** the gateway authenticates and authorizes the user/client. An OAuth authorization server can issue audience-restricted access tokens; an OIDC provider may supply the user identity used during login.
- **Gateway to backend:** this server validates a dedicated upstream bearer secret. The gateway must use its stored backend credential, not forward an arbitrary end-user token.
- **Backend to router:** SSH uses dedicated keys and strict host-key verification. Router permissions remain a separate boundary from gateway access and the advertised tool catalog.

Gateway web-console login/SSO is not automatically authorization for MCP API calls. Test both paths. This backend does not validate OAuth JWTs, act as an authorization server, dynamically register clients or store an identity-provider client secret.

## Backend startup and authentication

Default startup is stdio. To serve HTTP privately:

```sh
FIREWALLA_MCP_CONFIG=/absolute/path/config-read.json \
FIREWALLA_MCP_HTTP_TOKEN_FILE=/absolute/path/http-read-token \
firewalla-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

Provision the token file separately with 32–256 random URL-safe characters. Protect its permissions and mount it read-only; never commit it, paste it into chat or put it in a query parameter or tool argument. Missing/weak token configuration prevents startup. Rotate it by replacing the protected file, updating the gateway's stored credential and restarting this MCP process in a coordinated maintenance step.

The MCP endpoint is `/mcp`. `/healthz` checks process health only, not router connectivity. Every HTTP request, including health, requires `Authorization: Bearer <upstream-secret>`. Unknown/duplicate Host headers, all browser Origin headers, duplicate authorization headers and URL query parameters are rejected. Request bodies are limited to 64 KiB and access logging is disabled. The CLI defaults to loopback. Non-loopback binding requires an explicit `FIREWALLA_MCP_HTTP_ALLOWED_HOSTS` list; wildcards are rejected. The backend has no browser-Origin allowlist setting: direct browser requests with an Origin header are rejected. Use the gateway’s supported client flow; do not disable this boundary.

The [HTTP Compose example](../compose.http.yaml) publishes only loopback port 8000; verify availability on your host. On a shared trusted Docker network, the gateway can use `http://firewalla-read:8000/mcp` without publishing a host port. Use isolated same-host networking or authenticated TLS to protect the bearer. Do not send it over an untrusted plaintext LAN/WAN. Keep backend reachability restricted to the gateway/admin network; no Docker socket mount or privileged container is needed.

## Register the gateway upstream

1. Confirm the approved host/network topology, TLS termination, secret storage, container UID, available port and administration permissions.
2. Register the backend's `/mcp` URL using **Streamable HTTP**, with the dedicated bearer stored in the gateway's protected credential store. Do not use query-string authentication.
3. Discover tools and associate them with the intended private server/integration. Start with the read catalog.
4. Restrict discovery and invocation to authorized users/groups and the least privileges they need. If the gateway supports tool-level authorization, verify it on the installed version. Otherwise use separately isolated reader/writer backends and credentials rather than assuming tool-level isolation exists.
5. Test allowed and denied identities through the actual MCP endpoint. An administrator's successful call alone does not validate access control.

Separate reader/admin backends are an optional deliberate design. Backend bearer authentication does not itself provide per-user or per-tool roles.

## Configure OAuth/OIDC at the gateway

Use an existing approved client/application where suitable. Configuration is provider- and gateway-specific; the table describes what must agree, not environment variables accepted by this backend.

| Setting | Required agreement |
|---|---|
| Issuer | The exact trusted authorization-server issuer; validate signatures and metadata through trusted endpoints |
| Audience/resource | Access tokens must target the gateway's intended MCP resource, not an unrelated application |
| Scopes | Request only scopes required by the MCP access policy; identity/login scopes alone are not write authorization |
| Client and redirect URI | Use the registered client and exact verified callback; preserve existing identifiers during tool upgrades |
| Users/groups and roles | Restrict assignment and map claims to least-privilege access; do not make every signed-in user an administrator |
| Token/session policy | Verify expiry, refresh eligibility, rotation and applicable MFA policy; do not confuse browser sessions with MCP access tokens |

Use the gateway's supported OAuth flow for the chosen MCP client. Check whether the client requires authorization discovery, resource metadata, PKCE or a particular registration method; do not assume the backend provides these. Keep client secrets, where required, in the gateway's approved secret store. Do not copy them into router configuration or tool outputs.

Where explicitly requested and supported by the provider, a service can use a **180-day refresh-token absolute lifetime and inactivity window** (259200 minutes). This is an optional policy example, not a default or universal provider capability. Preserve short access-token lifetimes, rotation and MFA. Read back the actual policy and client assignment: a label or global setting does not prove it applies. Do not extend administrator sessions or alter unrelated applications as part of this setup.

## Catalogs and write confirmation

Default stdio/HTTP exposes 36 read/inspection tools. Optional VPN + capture uses `--vpn-write-catalog` and the corresponding configuration for 47 tools; `writes_enabled=false` excludes general writers. See [installation](install.md) for flags/mounts and [support](features.md) for firmware limits. A schema is not proof of a working adapter or an authorized operation.

In [host-confirmed mode](host-confirmed-vpn.md), the trusted authenticated MCP host shows the exact preview and obtains confirmation before apply. SSH stays internal; no external approval issuer is required. The server enforces plan/target/state/expiry/replay checks but does not independently attest a human reply. OAuth login alone does not enforce that conversational workflow. Only enable writes for clients whose confirmation behavior you trust and verify.

Keep one writer process per configured box set. Pending plans are in memory and lost on restart; persistent consumption-ledger and audit storage must survive upgrades. General combined writers require a separate review of permissions and source contracts.

## Validate and upgrade without recreating the integration

Verify through the gateway:

- MCP `initialize`, `tools/list` and a bounded read call using the advertised schema.
- Matching backend and gateway schemas, including new pagination/filter parameters.
- Rejection without authentication, with a wrong audience/unauthorized identity at the gateway, and with missing/bad bearer or invalid Host/Origin at the backend.
- Reader identities cannot discover/invoke privileged paths under your chosen access model.

Retain the established integration/server IDs, endpoint, OAuth client, audience and callback when upgrading tools. Replace the private backend, refresh gateway discovery and tool associations, then refresh/review the existing client's tool catalog. Do not duplicate OAuth setup merely to add a tool. For ChatGPT, the action may appear under **Manage → Manage app → Refresh tools**, depending on the account/UI.

Repository HTTP tests exercise real JSON-RPC initialize/list/call, catalog restrictions and missing/wrong/duplicate credentials, Host/Origin and query-token rejection. `tests/http_container_smoke.py` uses a disposable loopback container and test-only bearer, without router credentials. These tests do not certify a particular gateway/provider integration or live SSH access. Validate your actual deployment separately; see the [validation record](validation.md).
