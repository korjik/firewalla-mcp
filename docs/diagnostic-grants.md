# Exact TCP diagnostic grants

This optional capability manages diagnostic permissions through MCP. It does not
change firewall rules, routing, credentials or `probe_networks`. SSH remains the
server's internal transport. This implementation is locally tested, not deployed.

## Workflow

1. Call `preview_diagnostic_grant` with a configured source box, one canonical
   literal IPv4 address, 1–8 distinct TCP ports and a lifetime of 60–3600 seconds.
2. Show the entire scope and expiry to the owner and obtain explicit confirmation.
3. Call `apply_diagnostic_grant_plan` with that exact plan ID. No probe runs yet.
4. Use `tcp_probe` for individual allowed ports. Each grant permits at most 16
   handshake attempts, with no application payload. Failed attempts count too.
5. Inspect `diagnostic_grants` or preview a revoke with
   `preview_diagnostic_revoke`, then confirm and apply it.

Example preview arguments (use your actual authorized destination):

```json
{"box_name":"router-a","address":"10.20.30.40","ports":[80,443],"ttl_seconds":600}
```

No hostnames, CIDRs, port ranges, IPv6, UDP or DNS rebinding are supported. Public
unicast and RFC1918 addresses are eligible; loopback, link-local, multicast,
special-use ranges, known metadata endpoints and configured router SSH host addresses
are denied. Other WAN/VLAN/VPN router addresses are not discovered automatically.
Add infrastructure destinations to `diagnostic_grants_deny_addresses`
when they must never receive these probes. A TCP handshake can still trigger
remote logging or connection limits; this is active network activity.

## Installation and trust

Require the general write catalog, explicit `host_confirmed` configuration,
existing private audit/execution storage and these additional settings:

```json
{
  "diagnostic_grants_enabled": true,
  "diagnostic_grants_directory": "/state/diagnostic-grants",
  "diagnostic_grants_deny_addresses": ["10.20.30.1"]
}
```

Mount a dedicated persistent process-owned `0700` directory. Its append-only
`0600` journal stores private target metadata and usage; it is not an approval
issuer. Preserve it and the execution ledger across upgrades. Plans expire after
two minutes and are discarded on restart; applied grants survive only until
their original expiry and remaining attempt limit. Configuration drift invalidates
use. The bounded journal rejects further work when full or corrupted; never clear
it to bypass limits or replay a plan. Preview/list can initialize the empty local
journal; neither contacts the target.

The trusted authenticated MCP host must enforce owner confirmation and the gateway
must restrict permission-management tools to the intended owner. This backend
cannot independently attest a human reply or distinguish users behind a shared
bearer credential. A model-supplied confirmation boolean is not used. Enabling
this feature is a security-sensitive opt-in, not a guarantee that arbitrary MCP
clients enforce conversation consent.

Legacy `sites.<box>.probe_networks` retains its existing IP-based behavior,
including access to other ports. Exact grants are checked only when that legacy
scope does not already authorize the destination. Revoking a grant cannot revoke
legacy permissions or another overlapping grant. No other diagnostic tool receives
this grant implicitly; the new scope applies only to `tcp_probe`.

Grant/revoke plans bind exact state, source configuration, scope and expiry and
use durable single-use execution claims. A global interprocess lock serializes
changes with granted probes. Concurrent calls may receive a busy error. Expiry or
revocation prevents new dispatches; it does not cancel an SSH probe request already dispatched (its handshake may
finish after expiry). Expiry is checked again after waiting for SSH transport capacity.
A crash after a claim may leave a consumed plan with an uncertain result: inspect
the journal through the inventory tool and obtain a fresh preview, never blindly
retry or edit the journal. Back up audit, journal and consumption storage together.
