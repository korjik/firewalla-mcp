# Persistent VPN forwarding and shared confirmation

Local candidate only. No live mapping has been installed by this work. The deployed
catalog remains VPN-only until explicit approval expands its command boundary.

## Installed contract and limits

Both reviewed firmware trees contain the same port-forward implementation
(SHA256 `0db0a855be5d04a5110b949342d26b5f62db6d48b9b249110321f0c410958158`).
`set policy` with `portforward` publishes to FireMain's existing MessageBus handler.
FireMain updates `extension.portforward.config` and restores maps during startup.
The adapter sends the native management request; it does not SET Redis, install
startup scripts, call side-effecting Node modules or write temporary iptables rules.
The port-forward module and three supporting files are additionally pinned.

`wanUUID=VC:<profile>` selects the VPN NAT chain and the profile's tunnel-address
ipset. VPNClient supplies the interface-specific ingress jump. An ordinary inbound
allow rule is separate from NAT; neither creates a provider-side forwarded port.
The new adapter verifies the stored owned mapping plus observed DNAT and VPN ingress
rules. Missing kernel evidence yields `uncertain`, not success. Firewall acceptance,
provider forwarding and independent external reachability remain untested. A local
hairpin timeout is not proof of a globally closed port. Existing conntrack entries
are not flushed: test a new connection from an independent external vantage.

The selected device must have an explicit VPN policy matching the requested profile
and its recorded IPv4 address must match. Those facts and VPN settings are bound to
the plan; they are not proof of effective return routing. Inherited device/group
routing, IPv6 forwarding, DMZ, range creation and provider port discovery are outside
this initial writer. Existing ranges/disabled mappings/catch-alls are conservatively
checked for conflicts. No automatic replacement, enablement of a pre-existing entry,
firewall allow or routing change is intended.

The API acknowledgment is asynchronous. The native queue has no atomic compare-and-
set and can modify a duplicate submitted concurrently. The adapter therefore requires
an explicit no-concurrent-mapping-edit maintenance window, checks before dispatch,
submits once, polls bounded readback, and detects unexpected after-state. **It cannot
prevent a competing writer in the queue interval.** Do not claim transaction isolation.
Configuration retention across FireMain restart is supported by source review; no
restart/reboot or Redis durable-storage recovery has been live-tested.

## Tools and one confirmation

In the general write catalog:

- `preview_persistent_vpn_forward`: box, device MAC, expected destination IPv4,
  profile ID, TCP/UDP, external/destination ports, maintenance deadline.
- `preview_forward_plan`: the same scope plus 2–4 ordered protocol/port actions.
  All actions are displayed in one immutable plan and share one confirmation.
- `apply_change`: exact plan ID after the authenticated MCP host obtains confirmation.
- `preview_rollback`: single-mapping rollback only while the verified complete state
  and ownership marker match. Removal is sent through the native management path.

Example: preview TCP41000→device41000 and UDP41000→device41000 on `router-a`, then
confirm that exact two-step plan once. SSH runs internally. No operator file is used
when `write_confirmation_mode=host_confirmed` is selected. Kernel table/chain restrictions
remain for the separately named temporary adapters.

A compound mapping plan strips only its exact previously verified additions when
comparing the baseline for the next action. Other mappings, device/IP/VPN settings,
changed or missing earlier results cause a stop. Results identify each attempted
step; failure is partial/uncertain, not an atomic rollback. Replaying the plan does
not dispatch again. Inspect an uncertain step before any retry. This version requires
a fresh plan/confirmation for remaining steps rather than claiming safe automatic
resume or undoing a concurrent owner's change.

**Mixed plan candidate:** `preview_network_plan` accepts one device, expected/current
profile, destination profile and protocol, and 1–2 forwarding actions. It declares
start → switch → forwards and dependencies; `apply_network_plan` consumes one exact
host-confirmed plan. A read-only workflow snapshot binds unrelated mappings, device
IP, both profiles' safety settings and source-file identity/change metadata. It never
reads credential files. File metadata detects ordinary in-place edits/replacement;
it is not protection against a privileged actor able to falsify kernel metadata.

Execution permits only the projected transitions: observed destination connection,
explicit profile-policy replacement preserving the supported policy shape, and exact
owned forwarding entries. It revalidates before and after each step. A native start
acknowledgment without connected observations stops before changing the device.
Changed safety/DNS settings, unrelated mappings, unexpected policy, modified/missing
owned entries and expiry stop execution. Already-connected start is a declared no-op.
Fresh step fingerprints alone are insufficient: stable/transition checks must also
match the original plan. Runtime observations still do not prove peer/provider
reachability or effective return routing. The native APIs have no cross-step CAS.

Completed/partial plans cannot be replayed. A partial result identifies completed
steps and the stopped index, preserves uncertain state and requires inspection plus
a fresh exact remaining plan/confirmation. No automatic cross-step compensation is
claimed. Workflow-created forwards do not yet have an exposed inverse-plan tool;
removal requires separately reviewed native management action, not a fabricated
rollback token. Single-forward plans retain their conditional rollback tool. Cross-plugin qBittorrent or external-probe operations may be included in a
host-coordinated user preview, but Firewalla does not execute those other tools.
Material changes or new steps require new confirmation. No live mixed plan tested.

## Audit of existing writers

| Family | Host-confirmed flow | Installed-firmware status |
|---|---|---|
| VPN lifecycle/device switch/import | Existing supported catalog | Reviewed contracts; live mutations not tested here |
| Persistent VPN NAT mapping / start-switch-forward plan | New local single/bounded compound adapters | Exact installed source pins; realistic mocks only; deployment pending |
| Kernel route/filter/DNAT | Shared general confirmation supported | Temporary kernel state only; restricted tables/chains; not app-persistent |
| Device Safe Search/Ad Block/Unbound/DoH | Shared general confirmation supported | Current source pins for Ad Block/Safe Search/Unbound; DoH remains rejected |
| Persistent app/category/scheduled rules and DNS overrides | Shared general confirmation supported | Current policy dependencies reviewed and pinned; mocks only, no live enforcement test |
| Scoped group/network DNS/NTP | Shared general confirmation supported | Current group/network Ad Block/Safe Search/Unbound source contracts; NTP/DoH remain blocked |
| General permanent routes, RADIUS enrollment, arbitrary services | Unsupported | No validated management adapter |

Confirmation does not make an unsupported contract valid. General firmware guards
remain fail-closed; only persistent-forward kinds receive the additional reviewed
current-revision permission. The default confirmation mode remains compatible.

## Deployment review still required

This expands persistent network control beyond VPN lifecycle. Review the code,
new remote helper hash, and a narrowly expanded SSH gate permitting only
`managed_forward`/`managed_forward_batch` alongside previously approved kinds, plus
the fixed read-only `managed_workflow_state` projection. Mixed plans invoke only
those individual approved mutations through internal SSH.
Select the general host-confirmed catalog/configuration and refresh the same CF
identity; do not broadly allow all `managed_*` operations. Rebuild the pinned import
bundle if its embedded remote code changes, retaining its existing import scope.
No live forwarding, firewall, route or VPN test is authorized by implementation.

Native VPN ingress isolation caveat: the shared NAT chain selects the destination
IP set, not a second ingress-interface match. Two profiles with overlapping tunnel
addresses can therefore make profile isolation ambiguous. The candidate reads only
bounded VPN self-address sets on-box, rejects overlap or an empty selected set, and
binds that inventory into the plan. It does not return all set members. A disconnected
profile with no observed tunnel address cannot pass this forwarding preview.

Combined catalog rollout: enable both general and VPN write catalogs with
`writes_enabled=true`, `write_confirmation_mode=host_confirmed`,
`vpn_writes_enabled=true`, `vpn_confirmation_mode=host_confirmed`, and
`vpn_target_policy=approval_bound`. The 57-tool combined catalog preserves the
existing 43 VPN-catalog tools; exact operation guards still determine availability.
The proposed narrow network SSH gate does not enable legacy device/app/DNS or kernel
writers merely because their MCP tools exist. Their permissions/contracts need their
own review. Five policy/control dependencies were subsequently reviewed with explicit approval; the separate managed gate template covers only those reviewed additions. No production gate was expanded.
