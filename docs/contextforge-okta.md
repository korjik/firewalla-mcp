# Streamable HTTP, ContextForge and Okta

Both stdio and genuine MCP Streamable HTTP are implemented. No gateway, tenant, credential or deployment has been created. Examples are generic; verify the installed ContextForge version, existing issuer/client, callback URL, host/network and available port before applying anything.

## Backend startup and authentication

Default startup remains stdio. To serve HTTP privately:

```sh
FIREWALLA_MCP_CONFIG=/absolute/path/config-read.json \
FIREWALLA_MCP_HTTP_TOKEN_FILE=/absolute/path/http-read-token \
firewalla-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

The owner provisions the token file separately: 32–256 random URL-safe characters, protected with file permissions and never committed. The server reads it from the mounted file, not from a query parameter or tool argument. Missing/weak token configuration prevents startup. Runtime token rotation requires replacing the file and restarting only this MCP process after approval.

Endpoint: `/mcp`. Authenticated process-health endpoint: `/healthz` (does not test router connectivity). Every HTTP request requires `Authorization: Bearer <upstream-secret>`, including health. Unknown/duplicate Host, browser Origin, duplicate authorization and URL query parameters are rejected. Body size is limited to 64 KiB; access logging is disabled. The CLI defaults to loopback. Non-loopback binding requires an explicit `FIREWALLA_MCP_HTTP_ALLOWED_HOSTS` list; wildcards are rejected.

`compose.http.yaml` is a separate HTTP example, with loopback-only published port 8000. This is an example, not a claim that any production port is free. On a shared trusted Docker network, register `http://firewalla-read:8000/mcp` and avoid publishing a port. A same-host isolated network or authenticated TLS proxy protects the bearer secret; do not send it over an untrusted plaintext LAN/WAN. Keep backend reachability restricted to the gateway/admin network. No Docker socket mount or privileged container is needed.

## Read/write separation

HTTP defaults to a **34-tool read-only catalog**: `apply_change` and the four executable-write preview/rollback tools are removed, and startup rejects `writes_enabled=true`. A caller cannot invoke a removed tool by guessing its name. Non-executable `stage_*` proposals remain read-only and do not grant mutation authority.

A separately deployed administrative backend can use `--allow-write-catalog` only with `writes_enabled=true`, exact per-box allowlists, mounted approval/audit directories and a **different bearer secret**. It exposes the complete 39-tool catalog. Keep one writer process to preserve in-memory plan state; load balancing/restarting invalidates plans. Gateway RBAC authorization is necessary but does not replace the host-side, single-use operator approval required by `apply_change`.

Stdio exposes the full catalog with writes disabled by default. HTTP catalog choice does not widen SSH access or create router credentials. Use distinct dedicated SSH keys for read/admin instances when practical; a `pi` key remains powerful outside this application.

## ContextForge registration

After infrastructure access and deployment are approved, register the read backend as a Streamable HTTP upstream using its `/mcp` URL and the dedicated upstream bearer credential stored securely in the gateway. Discover tools and create a read-only virtual server for the authorized reader group. Do not forward arbitrary end-user authorization headers as the backend credential. Do not enable query-parameter authentication.

Register the administrative backend separately only if required. Restrict its virtual server and tools to the operator group, and verify that reader identities cannot discover/invoke the write path. Test both denied and permitted cases, not just admin success. ContextForge supports tool-level RBAC, but exact configuration must match the installed version: [tool authorization guide](https://ibm.github.io/mcp-context-forge/latest/howto/rbac-tool-authorization/) and [RBAC configuration](https://ibm.github.io/mcp-context-forge/manage/rbac/).

## Okta boundary

Okta authenticates users to ContextForge; this backend validates only its dedicated upstream secret. It does not validate arbitrary Okta tokens, act as an OAuth authorization server, register clients dynamically, or store an Okta client secret. Gateway login/SSO and MCP-client API authorization are distinct paths and both need testing.

Use the existing approved Okta application where suitable. Confirm exact issuer, signed-token verification, audience, redirect URI, permitted users/groups and least-privilege role mapping. Do not grant all signed-in users administrative access. Store any gateway client secret in its approved secret store, never in this repository or MCP tool output. ContextForge's documented Okta settings include `SSO_OKTA_ENABLED`, `SSO_OKTA_CLIENT_ID`, `SSO_OKTA_CLIENT_SECRET`, `SSO_OKTA_ISSUER`, `SSO_OKTA_SCOPE` and group mapping; follow its version-specific [Okta OIDC guide](https://ibm.github.io/mcp-context-forge/manage/sso-okta-tutorial/) and [configuration reference](https://ibm.github.io/mcp-context-forge/manage/configuration/).

No deployment or identity changes should proceed from these examples alone. Required preflight includes authenticated access to the actual gateway/host, existing network/TLS topology, approved storage/UID, port availability, upstream registration privileges and Okta app/role scope. No production host permission bypass is appropriate.

## Validation

Unit tests perform a real HTTP JSON-RPC initialize/list/call roundtrip, verify omitted mutation tools, and reject missing/wrong/duplicate credentials, unwanted Host/Origin and query tokens. `tests/http_container_smoke.py` starts a disposable loopback-only container with a generated test-only bearer secret, performs authenticated MCP operations, verifies unauthenticated rejection, then removes that container. It has no router credentials and is not an end-to-end ContextForge/Okta or live SSH test.
