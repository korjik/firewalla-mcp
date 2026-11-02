# Device-wide IPv6 inbound policies

This optional workflow creates native persistent inbound **firewall policies**, not
NAT mappings. It uses the same preview → explicit host confirmation → apply trust
model and internal SSH transport. It is separate from IPv4 forwarding/reset tools.

## Exact scope

Each action selects one configured box, current WAN UUID, device MAC, explicit IPv6
source CIDR, TCP or UDP, and one destination port. It permits traffic to **all IPv6
addresses in that device's native address set, including future addresses**.
It does not promise a single-address pinhole, translate addresses/ports, create
NAT66, change routing or permit IPv4. The corresponding IPv4 source set must be
verified empty. Multiple source ranges or ports require explicitly enumerated
separate actions, not an unbounded port range.

Current device addresses and WAN bindings are included in the snapshot. A change
between preview and execution stops the plan, even though the resulting policy
would intentionally cover future device addresses after successful creation.
No observed IPv6 address does not prove IPv6 is disabled; the future-address scope
still applies. Rule verification is not proof of WAN traversal, priority over
other policies, return routing, a listening service or external reachability.

## Enablement

Set `ipv6_policy_enabled: true` together with general host-confirmed writes,
`vpn_target_policy: approval_bound`, private audit/consumption storage and a private
`forwarding_recovery_directory`. The NAT lifecycle/app-management flags are not
required. Install the matching reviewed pinned lifecycle helper and refresh the
existing gateway/client tool catalog. The helper now accepts the separate IPv6
policy-only template through its restricted lifecycle command; approving this
permission change is required before upgrading an existing restricted deployment.
No credential, SSH host-key or OAuth registration change is required.

The default remains disabled. The native policy, network and enforcement source
contracts must pass their guards on the configured revision. Unsupported or changed
firmware stops execution; do not remove the guards to enable the feature.

## Tools and example

1. `inspect_ipv6_policies` lists policies owned through verified private transaction
   receipts and current device/WAN metadata. Matching names do not establish ownership.
2. `preview_ipv6_policy_plan` accepts up to four creations and four exact owned
   removals, within 16 ordered steps and a five-minute maintenance window.
3. Show the complete plan and scope, obtain explicit user confirmation, then call
   `apply_ipv6_policy_plan` with the exact plan ID.
4. After interruption or restart, use `preview_ipv6_policy_recovery` and obtain fresh
   confirmation. Never blindly retry or erase the consumption/recovery records.

Example action for a synthetic source network:

```json
{"source_network":"2001:db8:100::/48","protocol":"tcp","port":443}
```

A request such as “Allow this IPv6 source range to reach the selected device's TCP
443 through router-a's WAN” should preview the all-device-address scope explicitly.
Use a real source range chosen by the owner; documentation addresses are examples.

New policies are created disabled, their allocated identity is verified, and expiry
is rechecked before enabling. Removal binds the exact owned native ID/birth and
state. Unknown/shared references fail closed. Unrelated, app-created or merely
semantically equal policies remain opaque and preserved; this workflow does not
adopt existing IPv6 policies. A same-scope existing policy, including disabled ones,
blocks creation rather than being silently enabled.

## Failure and recovery limits

Plans are not atomic transactions. A partial failure may leave a disabled policy
or an interrupted sequence. Recovery only acts on verified transaction-owned state;
a crash before a returned policy allocation is durably verified requires inspection.
Restoration may allocate a different native policy ID. Concurrent changes, altered
configuration, expired plans and replay stop execution. The trusted MCP host enforces
human confirmation; an authenticated backend request does not attest a human reply.

## Evidence

Source probes show that the native builder emits both families and cannot safely
use an exact IPv6 `origDst` in its IPv4 rule. The separate adapter omits that selector
and proves positive IPv6 source membership with an empty IPv4 counterpart.
Synthetic tests cover native request contracts, transport, identities, expiry,
partial outcomes and restart recovery. Disposable network-none kernel tests exercise
TCP/UDP source-family isolation. These are not live-appliance policy mutation,
reboot persistence or external reachability tests. See [approval semantics](approvals.md)
and [the generated schemas](tool-reference.md).
