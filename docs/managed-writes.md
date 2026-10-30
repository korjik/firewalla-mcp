# Persistent device, app and DNS controls

These typed adapters use existing Firewalla management requests over internal SSH.
They never enable an API, write raw Redis policy state or install temporary kernel
rules while claiming app persistence. They are source/contract tested, not deployed
or live-enforcement tested by this release.

## Reviewed installed contracts

The two revisions and shared tree in [firmware review](firmware-compatibility.md)
now support the following additional kinds through `policy_source_guard`:

- `managed_feature`: device Ad Block, Safe Search or Unbound.
- `managed_scoped`: the same three features for a numeric group or network UUID.
- `managed_rule`: new device Internet/category/app/IP/domain blocks, recurring
  category/app blocks and literal-IP DNS-answer rules.

Both appliance copies of Policy.js, PolicyManager2.js, SafeSearchPlugin.js,
UnboundPlugin.js and AdblockPlugin.js matched by SHA256. Their five digests are
pinned in `remote.POLICY_SOURCE_HASHES` in addition to the existing eleven-file
management/VPN contract and exact Git revision/tree guard. Only a validated
translation dictionary edit is tolerated; relevant code drift fails closed.
No Firewalla AGPL implementation is copied into this repository; tests are
independent synthetic contract fixtures.

Source review verified netbot's device/group/network target dispatch and native
policy set/create/enable/delete requests; Policy's domain/MAC canonicalization;
disabled-duplicate handling; native scheduled policy fields; and PolicyManager2's
DNS `address` action forwarding of resolver, scope, exact-match and IP-only flags.
The three service plugins explicitly distinguish true, false and null for Host,
Tag and NetworkProfile. Runtime-source alignment and asynchronous enforcement
still need operational verification before deployment or a live write.

DoH and NTP implementations were not included in this review and remain blocked
on these installed revisions. Their older-revision adapters are not certification
of current support. RADIUS/global changes and arbitrary existing-rule CRUD are
unsupported.

## Exact behavior and limits

Feature previews require an existing recognized explicit value so rollback can
restore it exactly. Ad Block is a scalar; Safe Search and Unbound use `{state:...}`.
Enable=true, inherit=false, explicit disable=null. Removing a local override does
not bypass an inherited/global rule. Unknown extra policy fields fail closed.

Rules use `action=block`, `direction=outbound`; Internet targets the exact MAC,
other rules use a single-device scope. Apps resolve dynamically only when the
catalog declares ACL support. Video category is `av`. DNS answer rules include
subdomains and only accept canonical unscoped literal IP answers. Schedules use
typed weekly fields and verified router timezone, not raw cron input.

At most 512 policy IDs are inspected, with bounded total Redis data/output.
Oversized configurations fail closed, not partially. Selected public fields and
opaque hashes bind the complete observed set; possible duplicate type/target
pairs are rejected even across scopes. Creation first saves a new disabled rule,
verifies its ID/fields, then enables it. This prevents upstream duplicate-create
behavior from reactivating an existing disabled rule under create-new approval.
Rollback deletes only the verified created ID when its expected state still matches.

Native acknowledgments and stored readback are not proof of packet filtering,
DNS answers or schedule execution. Normal Firewalla processing may reload DNS and
schedule background persistence. Concurrent writers are not atomically excluded;
uncertain outcomes stop without blind retry or cleanup.

## Enablement

Use [host-confirmed writes](writes.md) with the general catalog and persistent
ledger/audit. `scripts/managed_ssh_gate.py` is a separately reviewed installation
template for the supported kinds/features plus VPN/forwarding/capture. It rejects
DoH/NTP, temporary kernel writes and arbitrary commands. Its helper pins must match
the exact release; publishing this template does not install or authorize it.
Existing VPN/capture deployments retain their narrower gates until a separate
permission/deployment review. Kernel tools need their own explicitly scoped gate.

A plan binds exact targets/settings/prior state and expires. The host obtains
explicit confirmation, then calls MCP apply directly. No external SSH approval
file is required in host-confirmed mode. See [tool schemas](tool-reference.md).
