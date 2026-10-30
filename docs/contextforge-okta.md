# Streamable HTTP, ContextForge and Okta

Both stdio and genuine MCP Streamable HTTP are implemented. Private read-only deployment and gateway integration have been validated; tenant-specific details are intentionally omitted. Examples are generic; verify the installed ContextForge version, existing issuer/client, callback URL, host/network and available port before applying anything.

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

## Catalog and confirmation

Default stdio/HTTP exposes36 read/inspection tools. The reference deployment uses
`--vpn-write-catalog` plus capture for47 tools. `writes_enabled=false` keeps general
writers out. Use [installation](install.md) for exact flags/mounts and [host-confirmed
trust](host-confirmed-vpn.md) for preview → confirmation → MCP apply. SSH is internal;
no external issuer is required. The server enforces plan/state/expiry/replay but does
not independently verify the human reply. Restrict the authenticated host accordingly.

General combined writes are a separate reviewed permission expansion and are not
part of the47-tool deployment. A tool schema is not proof of a working firmware
adapter; consult [support](features.md). Keep one writer process per configured box
set; in-memory pending plans are lost on restart. Persistent ledger/audit storage
must survive upgrades.

## ContextForge registration

After infrastructure access and deployment are approved, register the read backend as a Streamable HTTP upstream using its `/mcp` URL and the dedicated upstream bearer credential stored securely in the gateway. Discover tools and associate its discovered tools with the existing private virtual server for the authorized owner/group. Do not forward arbitrary end-user authorization headers as the backend credential. Do not enable query-parameter authentication.

Keep the same integration for approved VPN/capture upgrades; do not create another OAuth client merely to update tools. Separate reader/admin backends are an optional deliberate RBAC design, not a prerequisite. Restrict its virtual server and tools to the operator group, and verify that reader identities cannot discover/invoke the write path. Test both denied and permitted cases, not just admin success. ContextForge supports tool-level RBAC, but exact configuration must match the installed version: [tool authorization guide](https://ibm.github.io/mcp-context-forge/latest/howto/rbac-tool-authorization/) and [RBAC configuration](https://ibm.github.io/mcp-context-forge/manage/rbac/).

## Okta boundary

Okta authenticates users to ContextForge; this backend validates only its dedicated upstream secret. It does not validate arbitrary Okta tokens, act as an OAuth authorization server, register clients dynamically, or store an Okta client secret. Gateway login/SSO and MCP-client API authorization are distinct paths and both need testing.

Use the existing approved Okta application where suitable. Confirm exact issuer, signed-token verification, audience, redirect URI, permitted users/groups and least-privilege role mapping. Do not grant all signed-in users administrative access. Store any gateway client secret in its approved secret store, never in this repository or MCP tool output. ContextForge's documented Okta settings include `SSO_OKTA_ENABLED`, `SSO_OKTA_CLIENT_ID`, `SSO_OKTA_CLIENT_SECRET`, `SSO_OKTA_ISSUER`, `SSO_OKTA_SCOPE` and group mapping; follow its version-specific [Okta OIDC guide](https://ibm.github.io/mcp-context-forge/manage/sso-okta-tutorial/) and [configuration reference](https://ibm.github.io/mcp-context-forge/manage/configuration/).

No deployment or identity changes should proceed from these examples alone. Required preflight includes authenticated access to the actual gateway/host, existing network/TLS topology, approved storage/UID, port availability, upstream registration privileges and Okta app/role scope. No production host permission bypass is appropriate.

## Validation

Unit tests perform a real HTTP JSON-RPC initialize/list/call roundtrip, verify omitted mutation tools, and reject missing/wrong/duplicate credentials, unwanted Host/Origin and query tokens. `tests/http_container_smoke.py` starts a disposable loopback-only container with a generated test-only bearer secret, performs authenticated MCP operations, verifies unauthenticated rejection, then removes that container. It has no router credentials and is not an end-to-end ContextForge/Okta or live SSH test.


## Preserve an existing integration

For tool upgrades, retain the established gateway/server IDs, endpoint, Okta client,
audience and redirect URI. Update the private backend, refresh the gateway catalog,
and refresh/review the existing ChatGPT app tools; do not repeat OAuth setup or
create a duplicate client. Verify `initialize`, `tools/list` and a bounded read call
through the actual advertised schema, plus rejection without authentication.

Where explicitly requested and permitted by the tenant, configure the new service's
refresh-token absolute lifetime **and inactivity window** to 180 days (259200
minutes), preserving short access-token lifetime, rotation and MFA. Read back the
actual policy rule and its client assignment; a policy label or a global setting
alone does not prove it applies. This is not a request to lengthen administrator
sessions or alter unrelated applications. Store no tenant secrets in examples.
