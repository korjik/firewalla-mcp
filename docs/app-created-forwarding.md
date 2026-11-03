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
| New device-wide IPv6 inbound policy | Separate opt-in | Separate opt-in | See [IPv6 policies](ipv6-policies.md); not a NAT reset action |
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
not port translation, and not proof of routing or reachability. The separate opt-in [IPv6 policy workflow](ipv6-policies.md) implements that
explicitly disclosed scope. It is not part of the IPv4 reset plan or enabled by
the app-management flag.

The reproducible source-contract probe is
`scripts/check_forward_policy_contract.cjs`, run against the reviewed `control/Block.js`
without importing appliance modules. `tests/ipv6_contract_smoke.py` runs in a
disposable network-none container with `NET_ADMIN`: it verifies the invalid
cross-family destination, TCP/UDP rule parsing and positive/negative IPv6 source
set membership with an empty IPv4 set. It sends no traffic and does not establish
packet-path or live-appliance enforcement. Never run this smoke script on a router.

## Default-WAN to selected-WAN migration

An app-created mapping that **omits** `wanUUID` can now be explicitly selected by
its digest key and full object fingerprint in `preview_forwarding_reset`. The
supported migration selects one active IPv4 TCP/UDP mapping, no policy removals,
`all_mappings=false`, and one named replacement on the supplied WAN UUID. The
replacement retains the device, destination IP, protocol and external port and
uses a different internal port. For example, all-WAN TCP 80 → device:80 becomes
selected-WAN TCP 80 → the same device:8080. Resolve the WAN UUID from current
inventory; a provider name alone is not a selector.

The preview discloses the scope narrowing and the new IPv4 inbound allow with
its source CIDR, WAN, device and ports. All existing policies and unselected
mappings remain intact, including HTTPS. `autoFirewall` is preserved metadata;
it neither proves ownership of an allow policy nor authorizes deleting one.
The original allow for port 80 may therefore remain effective independently.
The new allow has the existing forwarding policy semantics, including direct
routed/non-DNAT scope; it is not a guarantee of external reachability.

The adapter sends the original mapping with only `state=false` for removal; it
never fills in an omitted WAN UUID. Native matching treats missing and null WAN
values alike, so a null-scope peer, duplicate selector, unknown fields, shared
hairpin resources or potentially overlapping mappings on any WAN block the
operation. An explicitly null/empty/false/wildcard WAN on the selected record is
unsupported. DMZ, `applyToAll` and `extIP` are unsupported even when false/null.
One exact default-chain DNAT and ingress evidence for every observed WAN are
required. Inactive/unknown WAN environments fail closed. No output bounds or
firmware guards are relaxed.

A confirmed plan removes the original NAT, creates a disabled scoped IPv4 allow,
creates the selected-WAN NAT, then enables the new allow. This has an outage
window and is not atomic. A lost reply is uncertain, not a reason to retry.
Fresh recovery inspects exact stored and kernel state; rollback explicitly
restores the original omitted-WAN scope and metadata and removes only the new
objects. It requires a new confirmation and maintenance window. Same-internal-
port narrowing is intentionally unsupported until shared/recreated hairpin
proofs cover it.

The reproducible pinned-source probe is
`node scripts/check_default_wan_contract.cjs /path/to/reviewed/portforward.js`.
It extracts only the reviewed selector/removal/rule-builder methods into an
isolated recorder; it never imports appliance modules. Synthetic tests cover
complete snapshot transitions, preserved policies/443, expiry, drift, ambiguous
selectors, uncertain replies, orphan rules and restart recovery. These are not
live-appliance or external-reachability tests. The network-none
`tests/forwarding_default_wan_smoke.py` check uses real legacy iptables/ipset
with only NET_ADMIN and NET_RAW, sends no traffic, and verifies independent
old/new NAT and hairpin tuples. Updating source does not deploy a
helper, change its gate pin, merge a PR or authorize a live migration.

PR #5 is guidance-only and retains the old default-WAN limitation; its guidance
must be reconciled if combined with this executor. The compact atomic policy
projection reduces wire size without relaxing bounds; this migration uses that
existing inventory contract and does not lift its limits.


## Bounded enforcement projection

Enforcement verification scans every IPv4/IPv6 filter chain on the router and
projects only exact `rule_<policy ID>` comments before the response crosses the
existing 131,072-byte subprocess boundary. This preserves detection of duplicate
rules and rules in unexpected chains. It does not read just the expected allow
chain, truncate a full dump, increase the response cap or treat a read failure as
absence. The scanner accepts at most 64 exact IDs, 4,096 lines, 16,384 bytes per
line and 4 MiB of input per family. It requires complete UTF-8 lines, successful
native command completion and a bounded complete response; timeout, malformed
output and any bound failure yield no proof. Each verification pass reads fresh
evidence. The strict existing rule and ipset verifiers remain unchanged.

If native disabled-policy creation completed but verification failed, the original
transaction remains uncertain. A fresh recovery preview must bind the observed
policy ID/birth and exact state and verify enforcement before proposing the
remaining mapping creation and policy enable. Recovery requires new confirmation;
installing this fix never resumes, enables or deletes anything automatically.
