# Managing app-created forwarding objects

The optional app-object workflow inspects and explicitly adopts selected native
forwarding objects. It does not infer ownership from a display name, matching port
or MCP label. It is a source capability; tool registration alone does not establish
that an appliance's firmware, restricted SSH gate or enforcement proof supports it.

Enable `forwarding_app_management_enabled` only alongside the existing forwarding
lifecycle configuration, private recovery directory and host-confirmed write mode.
The helper must contain the matching reviewed adapter. Enabling this option expands
which existing objects the writer may manage and requires operator review.

## Workflow

1. Call `inspect_forwarding_app_objects` for the configured box and selected WAN.
   Inspect every mapping and policy candidate, including its scope and identity.
2. Pass exact mapping keys/fingerprints and separately selected policy IDs, birth
   identities and semantic fingerprints to `preview_forwarding_reset`. A matching
   port is a relationship, not authorization to delete a policy.
3. Show the ordered removals, preserved objects, recreations, exposure and outage
   risks to the user. Obtain explicit confirmation of this exact plan before
   `apply_forwarding_lifecycle`.
4. Inspect results. On interruption, obtain a fresh recovery preview and confirmation.
   Do not blindly reapply the original plan or clear recovery storage.

`all_mappings=true` requires the selections to match the entire current inventory;
it does not discover or silently add deletions. Selection is limited to eight NAT
mappings and eight policies on one WAN, with up to four recreated forwards and 32
ordered steps. The plan and maintenance window expire after at most ten minutes.
Different selected devices can be removed; new forwards use the explicitly selected
recreation target. Each recreation includes a meaningful display name.

Policies are disabled and removed before NAT removal, followed by creation of the
replacement configuration. This is not an atomic transaction: failures or expiry can
leave a partial configuration and a prolonged outage. Durable receipts bind exact
objects and verified policy allocations across restarts. Native policy restoration
may allocate a different ID. A crash before that allocation is durably verified
requires inspection; semantic equality alone cannot authorize recovery.

## Protocol and family coverage

| Operation | TCP | UDP | Address-family behavior |
| --- | --- | --- | --- |
| Selected IPv4 NAT removal and recreation | Supported adapter | Supported adapter | IPv4 DNAT only |
| New scoped inbound allow accompanying NAT | Supported adapter | Supported adapter | Explicit IPv4 source CIDR; verified empty IPv6 counterpart |
| Exact selected legacy device allow removal/restoration | Supported adapter | Supported adapter | Preserves its original dual-stack scope; requires IPv4 and IPv6 enforcement proof |
| New IPv6 inbound pinhole/routed policy | Not exposed | Not exposed | Separate native-policy and address/enforcement contract still needs validation |
| NAT66 or mixed-family translation | Unsupported | Unsupported | Rejected before mutation |

Legacy app device allows can permit direct IPv4 **and IPv6** access, not only DNAT
traffic. Their removal withdraws that broader permission; recovery restores it.
A newly created IPv4 allow must not silently replace the scope of a legacy policy.
New allows bind the selected WAN, device, source network, transport and ports, but
are not restricted to one original public destination IP or to DNAT traffic alone.

Global, inherited, scheduled, group-scoped, shared and incompletely understood
policies are not automatically adopted. Ambiguous native selectors, shared hairpin
resources, references, changed identities or unverified enforcement stop execution.
Unrelated policies remain in the snapshot and are preserved. See
[forwarding contracts](persistent-forwarding.md), [approvals](approvals.md) and the
[generated tool schemas](tool-reference.md).

## Validation limits

Synthetic integration tests cover a six-mapping/two-device reset with 24 ordered
steps, maximum-size 32-step reset and conditional rollback, UDP recreation,
expiry, drift, replay and restart recovery. Parser tests cover both-family legacy
rule evidence and rejection of missing or ambiguous evidence. These tests are not
proof of a live app-created reset or live IPv6 pinhole support. No implicit live
network test is part of enabling or inspecting this feature.

## IPv6 native-contract decision

The reviewed native rule builder emits both IPv4 and IPv6 rules and ignores a
caller-supplied family selector. An exact IPv6 `origDst` therefore also reaches
an IPv4 conntrack rule and is rejected by `iptables`. Supplying an empty IPv4
source set does not repair this: the invalid rule still must parse. This prevents
reusing the existing exact-destination forwarding contract for IPv6 pinholes.

A separate, technically plausible native policy omits `origDst`, uses an explicit
IPv6 source CIDR, selected WAN, device scope and TCP/UDP port, with an empty IPv4
source counterpart. Its destination scope is the device's entire IPv6 address set,
including addresses later added by Firewalla. It is not a single-address pinhole,
not port translation, and not proof of routing or reachability. Supporting that
alternative requires an explicit scope decision and a dedicated policy-only
preview/execution/recovery adapter; it is not exposed by this candidate.

The reproducible source-contract probe is
`scripts/check_forward_policy_contract.cjs`, run against the reviewed `control/Block.js`
without importing appliance modules. `tests/ipv6_contract_smoke.py` runs in a
disposable network-none container with `NET_ADMIN`: it verifies the invalid
cross-family destination, TCP/UDP rule parsing and positive/negative IPv6 source
set membership with an empty IPv4 set. It sends no traffic and does not establish
packet-path or live-appliance enforcement. Never run this smoke script on a router.
