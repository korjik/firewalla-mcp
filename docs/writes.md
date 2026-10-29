# Opt-in writes: temporary kernel state only

There are three implemented mutation adapters: add an IPv4 route, append an IPv4 filter rule, and append an IPv4 DNAT rule. All are **temporary Linux state**, not persistent Firewalla-managed routes, policies or app port-forward entries. Firewalla may overwrite them. No existing object is replaced. No public tool accepts a shell command.

Persistent Firewalla writes, device blocking/policies, VPN controls and maintenance are unsupported. Inspecting source is not enough to validate their management side effects. In particular, [FireRouter.setConfig](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/FireRouter.js) uses config IDs and can trigger service/system restarts; [PolicyManager2](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/PolicyManager2.js) uses asynchronous enforcement flows. Direct Redis writes, source-method calls and development HTTP routes are not substituted for validated persistent management APIs.

## Enable explicitly on the trusted MCP host

Default `writes_enabled` is false. To opt in, add these top-level settings to the administrator-owned config:

```json
{
  "writes_enabled": true,
  "approval_directory": "/approvals",
  "audit_file": "/audit/events.jsonl"
}
```

This fragment augments `sites`; it is not a complete config. Each selected box must also have exact allowlists such as `allowed_route_tables: [42420]`, `allowed_filter_chains: ["MCP_TEST"]` and `allowed_nat_chains: ["MCP_NAT_TEST"]`. Empty lists deny the respective writes. Chains must already exist; the server never creates/links chains. Tables 253, 254 (main) and 255 are always excluded. A route in an unused table has no effect until some routing rule selects that table; this server does not create such rules.

For Docker, mount dedicated host approval and audit directories read/write at `/approvals` and `/audit`. Keep the root filesystem and config/keys read-only. Both directories must be owned/readable by the nonroot container user; approval directory mode 700 is recommended and group/world writable directories are rejected. Do not mount the Docker socket. No additional Linux capability is needed by the MCP container: mutations are sent to the router through existing `sudo -n` access. The disposable **test** container's NET_ADMIN capability is only for an isolated local test namespace, never a deployment requirement.

## One preview, one human approval, one application

1. Call a typed preview tool. It validates the box allowlist and arguments, reads a bounded snapshot and returns a precise object diff, fingerprint, plan ID, digest, expiration, scope, and approval document. Preview never mutates the router. A conflicting route destination or marked rule returns `no_change`; replacements are unsupported.
2. An operator independently reviews the exact box, diff, connectivity consequences and temporary scope. Outside the MCP/model tool interface, the operator writes the returned `approval_document` as JSON to the exact returned `approval_file`, mode 600. This is the explicit action-time confirmation. **The assistant must not create this approval file on the operator's behalf merely because it can see the preview.** Client confirmation UI alone does not create the required host approval.
3. Call `apply_change(plan_id)`. There is no MCP approval endpoint. The server atomically claims the single-use file, verifies its digest and expiration, requires a successful pre-write audit append, re-reads the remote fingerprint, and only then executes the exact validated argv. Stale snapshots refuse the change. Plans expire in 10 minutes and are lost on server restart.
4. Read the result. `applied` means the after-read found the added object; it does not mean persistent configuration or desired network behavior. `uncertain` means the command or verification failed/timed out. Do not retry blindly. Inspect the actual state through a separate trusted channel. Replaying a completed plan returns the recorded outcome without running it again.
5. For a verified addition, call `preview_rollback` within its 10-minute window. It requires the complete relevant state fingerprint to match the post-apply snapshot and produces a **new** plan needing a **new** operator approval and `apply_change`. Rollback removes only that exact added object. Stale state, failed verification, expired plans and server restarts require manual investigation. There is no automatic cleanup after lost connectivity.

The approval directory is a host trust boundary, not protection against a compromised MCP process or a user with filesystem/shell access to that host. Keep it unavailable to autonomous tools. The directory and config must be controlled by the operator. Audit records contain time, box label, plan ID and outcome, not addresses, keys or raw rules. Retain the reviewed preview privately if the exact change details are required for an audit.

## Boundaries and concurrency

Per-box locks serialize changes from one server instance. `iptables -w 2` waits briefly for the xtables lock. The before-check and change are **not one atomic transaction** against Firewalla's own writers or other administrators. Run one writer instance, use a maintenance window, and do not assume these safeguards prevent all network disruption. Post-verification checks object presence; it is not traffic-policy proof. A DNAT rule alone does not add filter acceptance, SNAT, provider forwarding or VPN routing.

## Smallest proposed appliance write test — not executed

After separate approval, on one selected appliance: confirm table 42420 is absent/empty and not referenced by policy routing or VRF configuration; preview an IPv4 `blackhole 192.0.2.254/32` route in that table. The prefix is documentation-only. Approve, apply, verify presence, immediately preview rollback, separately approve rollback, and verify the table returns to its original state. If any reference/conflict exists, stop and choose a new reviewed table. No rule to select the table is added, and no production route, firewall, VPN or service is touched. Even this isolated test requires exact action-time approval; it has not been run on a real appliance.

## Testing

Mock tests exercise write-disabled behavior, allowlists, argument injection, missing/mismatched/expired/symlink approvals, audit failure, concurrent duplicate calls, stale fingerprints, uncertainty, one-time replay and independent rollback approval. `tests/kernel_smoke.py` exercises actual route/filter/DNAT addition, stale rejection and removal in a disposable Docker network namespace with no network interfaces beyond loopback and no router credentials. Appliance writes remain untested.
