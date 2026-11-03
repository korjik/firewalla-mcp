# Persistent forwarding and shared confirmation

These source-supported adapters require the combined write catalog, compatible firmware and restricted router permissions. Live forwarding enforcement and restart persistence are not certified; see the [support matrix](features.md).

## Installed contract and limits

Both reviewed firmware trees contain the same port-forward implementation
(SHA256 `0db0a855be5d04a5110b949342d26b5f62db6d48b9b249110321f0c410958158`).
`set policy` with `portforward` publishes to FireMain's existing MessageBus handler.
FireMain updates `extension.portforward.config` and restores maps during startup.
The adapter sends the native management request; it does not SET Redis, install
startup scripts, call side-effecting Node modules or write temporary iptables rules.
The port-forward module and five supporting files are additionally pinned.

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

## WAN/interface forwarding

Use `forwarding_interfaces` to select an exact **current WAN network UUID**. Do not pass an interface name, guess a UUID, use `*`, or substitute a VPN profile ID. The adapter validates the UUID/name relationship against current network metadata, an observed LAN subnet for the destination, and the device's recorded IPv4. Stale UUIDs, empty self-address sets, colliding native set prefixes and overlapping network self-addresses fail closed. The metadata inventory is bounded to 64 entries in each hash; unusually large configurations are unsupported.

Native `wanUUID=<network UUID>` selects `FW_PRERT_PORT_FORWARD` with the network's self-address set. This includes hairpin access to that WAN address. It does **not** implement physical ingress-only filtering. DNAT and the WAN address jump are checked separately after submission; missing evidence is uncertain. Unlike VPN forwarding, a matching device VPN assignment is not required. The device's stored VPN policy, current network/address sets and observed routing tables/rules are bound to the plan; inherited policies and effective return routing remain unverified. A destination using VPN or policy routing may need separate troubleshooting. This operation never changes routing to make forwarding work.

Default/all-WAN, explicit matching-WAN, apply-to-all, DMZ and disabled/range mappings are checked conservatively for conflicts. Observed competing IPv4 DNAT (including UPnP) also blocks the plan; unknown multiport DNAT requires manual review. Dynamic mappings can still appear between checks. New wildcard/all-WAN maps, LAN-ingress maps, IPv6, DMZ and range creation are unsupported. Existing maps are preserved. Firewall acceptance, upstream NAT/CGNAT and provider restrictions may still prevent access.

## Tools and one confirmation

`forwarding_interfaces` is available in the inspection catalog. In the general write catalog:

- `preview_persistent_forward`: box, device MAC, expected destination IPv4, WAN network UUID, TCP/UDP, external/destination ports and maintenance deadline.
- `preview_interface_forward_plan`: same WAN/device scope, with 2–4 ordered protocol/port actions.

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
rollback token. Single-forward plans retain their conditional rollback tool. External application configuration can be included in a host-coordinated user preview, but Firewalla does not execute those other tools.
Material changes or new steps require new confirmation. No live mixed plan tested.

## Audit of existing writers

| Family | Host-confirmed flow | Installed-firmware status |
|---|---|---|
| VPN lifecycle/device switch/import | Existing supported catalog | Reviewed contracts; live mutations not tested here |
| Persistent WAN/interface and VPN NAT / VPN start-switch-forward plan | Source-supported single/bounded compound adapters | Exact installed source pins; realistic mocks only; deployment pending |
| Kernel route/filter/DNAT | Shared general confirmation supported | Temporary kernel state only; restricted tables/chains; not app-persistent |
| Device Safe Search/Ad Block/Unbound/DoH | Shared general confirmation supported | Current source pins for Ad Block/Safe Search/Unbound; DoH remains rejected |
| Persistent app/category/scheduled rules and DNS overrides | Shared general confirmation supported | Current policy dependencies reviewed and pinned; mocks only, no live enforcement test |
| Scoped group/network DNS/NTP | Shared general confirmation supported | Current group/network Ad Block/Safe Search/Unbound source contracts; NTP/DoH remain blocked |
| General permanent routes, RADIUS enrollment, arbitrary services | Unsupported | No validated management adapter |

Confirmation does not make an unsupported firmware contract valid. Each operation requires its reviewed source guards and restricted SSH permissions. Existing file-based approval configurations must follow the explicit [host-confirmed migration](approvals.md#migrating-from-file-based-approval) before enabling writes.

## Deployment review still required

This expands persistent network control beyond VPN lifecycle. Review the code,
new remote helper hash, and a narrowly expanded SSH gate permitting only
`managed_forward`/`managed_forward_batch` alongside previously approved kinds, plus
the fixed read-only `managed_workflow_state` projection. Mixed plans invoke only
those individual approved mutations through internal SSH.
Select the general host-confirmed catalog/configuration and refresh the existing gateway integration; do not broadly allow all `managed_*` operations. Rebuild the pinned import
bundle if its embedded remote code changes, retaining its existing import scope.
No live forwarding, firewall, route or VPN test is authorized by implementation.

Native VPN ingress isolation caveat: the shared NAT chain selects the destination
IP set, not a second ingress-interface match. Two profiles with overlapping tunnel
addresses can therefore make profile isolation ambiguous. The candidate reads only
bounded VPN self-address sets on-box, rejects overlap or an empty selected set, and
binds that inventory into the plan. It does not return all set members. A disconnected
profile with no observed tunnel address cannot pass this forwarding preview.

Combined catalog rollout: select `--allow-write-catalog` and enable the required general/VPN configuration fields with
`writes_enabled=true`, `write_confirmation_mode=host_confirmed`,
`vpn_writes_enabled=true`, `vpn_confirmation_mode=host_confirmed`, and
`vpn_target_policy=approval_bound`. The 57-tool combined catalog preserves the
existing 43 VPN-catalog tools; exact operation guards still determine availability.
The network gate permits the documented VPN/forwarding operations. Device/app/DNS operations require the separate managed gate and compatible firmware contracts; kernel writers require their own restricted permissions. Tool registration alone grants none of these permissions.

## Example: ordinary WAN port forwarding

1. Call `forwarding_interfaces(box_name="router-a")` and select the intended WAN UUID. Resolve the intended device MAC and current LAN address using the device inventory.
2. Call `preview_persistent_forward` with the resolved values, `protocol="tcp"`, `external_port=41000`, `destination_port=8080`, and an actual Unix `maintenance_until` deadline within the next ten minutes. Do not reuse a stale example timestamp.
3. Show the complete preview and obtain explicit confirmation of both the mapping and no concurrent forwarding edits during the window. Call `apply_change(plan_id=...)` once.
4. Inspect stored and kernel evidence. A verified mapping is not an external service test. Any active external probe requires its own authorized scope.

For TCP+UDP, use `preview_interface_forward_plan` with two actions on the same UUID/device. Batches have a 110-second SSH deadline with a smaller internal subprocess budget so an interrupted step can return partial/uncertain results. The batch is not atomic. Stop and inspect partial results; never blindly replay or delete a mapping after an uncertain outcome. For a successful single mapping, `preview_rollback` creates a separate removal preview only while ownership and complete expected state still match.

## Upgrade and rollback

Build and test the new image without router credentials first. Preserve the prior image, configuration, helper/gate files and integration identity. The combined catalog requires explicitly enabled host-confirmed general writes, protected audit/consumption storage and an installed restricted network gate with the reviewed helper hash. Gate changes grant network-control access and require separate deployment authorization. Preserve existing VPN/import/capture permissions only when intended; do not use the broader managed-control gate merely to enable forwarding.

After an authorized upgrade, refresh the existing gateway/client catalog, verify tool schemas, health and harmless previews. Do not apply a real forwarding plan as a deployment smoke test. Roll back the image, configuration and matching gate pins together if verification fails; keep the persistent consumption ledger and audit history. No OAuth recreation or SSH key rotation is necessary.

Forwarding previews distinguish an exact enabled stored mapping (`no_change`)
from a possible overlap (`conflict`, with bounded source/count evidence). Neither
result proves effective enforcement or external reachability. Kernel overlap
checks inspect actual DNAT jump targets and protocol/port selectors; conntrack
state labels and unrelated DNS redirects are not forwarding duplicates.

### Completion means several independent checks

A firewall allow policy permits matching traffic; it does not translate an inbound
port to a LAN destination. A NAT mapping performs translation; it does not prove
that policy permits the packet, the service listens, replies use the correct path,
or an external client can connect. Do not recreate a mapping because a probe fails.

Forwarding previews, apply results and mapping inventory include
`forwarding_guidance` with distinct verification levels. `service_ready: unknown`
is intentional even after `applied` or `no_change`. A batch needs per-step inspection.
Use the observed evidence to say “mapping saved and NAT observed” rather than
“port opened.” Inspect applicable policy and precedence, the listener/host firewall,
and reply routing; then use an authorized independent probe with a new connection.
An external timeout alone cannot establish which layer failed.

If a separate inbound allow is needed, preview its exact target, direction,
protocol, ports and source scope and obtain confirmation. A forwarding plan does
not include that policy or authorize broader permissions. When a suitable policy
writer is unavailable, report that limitation instead of silently using another
write path. Inventory pages and direct device rules do not prove the absence of
inherited group/network/global policy.

### Durable recovery for new single-mapping operations

An optional `forwarding_recovery_directory` stores private operation receipts for
new single WAN/VPN mapping operations. Provision a persistent, process-owned `0700`
directory; receipts are `0600` and contain private target metadata, expected state
and ownership context, but no SSH keys or VPN credentials. Back it up securely
alongside the execution ledger. Do not clear either store to retry an operation.

The server writes a started receipt before dispatch. After a response it
records the terminal result, including uncertain outcomes. A completed receipt is
not proof of success: only a verified `applied` result qualifies for rollback. Following a restart, `preview_rollback` can use a completed
receipt to check the current firmware/configuration and exact after-state, then
produce a **new** expiring rollback plan requiring confirmation. It never restores
an expired approval. A started-only receipt is an uncertain operation and cannot
be automatically retried or rolled back. If storage fails after submission, inspect
current state before further action.

This does not recover provenance for mappings created before receipts were enabled.
An old `mcp:` label or lost plan ID alone does not establish safe deletion ownership.
Batch and combined policy/NAT recovery are not yet supported by this receipt path.

### Combined forwarding lifecycle

The separately opt-in [complete WAN lifecycle](forwarding-lifecycle.md) implements
exact selection, dependency checks, disabled policy creation, NAT creation and
allow activation with durable step recovery. It uses the explicitly disclosed
IPv4 source-network scope below, not the unsupported exact-original-IP variant.
It is locally tested, not deployed or live-write-tested. A separate permission
review is required before installing its pinned helper and enabling the catalog.

The reviewed native ordinary-allow path currently generates both address families.
An IPv4 `origDst` is copied into the IPv6 conntrack matcher, which the isolated
kernel contract test rejects. Therefore the combined writer is **not enabled**
with this requested original-destination restriction. The implementation does not
silently omit the restriction, set UPnP bypass flags, edit firmware, or treat an
IPv6 restore error as successful enforcement. The exact-original-address variant requires a validated native family-specific
path before it can ship.

Firewalla’s [manual forwarding guide](https://help.firewalla.com/hc/en-us/articles/1500009502622-Create-Port-Forwarding-on-Gold-Purple-Orange-Series)
describes a separate ingress permission on the internal port, optionally restricted
to selected sources. Source-contract tests also show a native candidate using an
IPv4 source network, device scope, internal port, protocol and WAN binding, without
the original destination IP. Its IPv6 source set is empty under the reviewed policy
contract. That is a different permission scope: it does not restrict the original
public destination address. It must not silently replace an exact-address plan.
The private app’s precise request payload has not been verified.

Native policy batches execute sequentially, and kernel enforcement failures may
be logged without undoing already saved configuration or other successful rules.
Neither a successful management response nor a saved policy proves complete
enforcement. A future combined executor must journal each step, inspect uncertain
outcomes, and verify the effective rules before reporting success.

Legacy adoption is separately validated as a fresh exact-object operation: the
selected mapping must match its complete fingerprint and explicit target/scope,
have an eligible MCP tag and a strict supported shape, and have a complete,
unshared dependency report. This is not historical ownership proof and does not
revive an old approval. The lifecycle planner consumes the validated selection and bounded policy
projection. Incomplete inheritance or indirect dependencies block removal rather
than being treated as absence.


#### Exposure of the candidate source-scoped alternative

The opt-in lifecycle uses an explicit IPv4 source-network match with a
positive IPv4 set and an empty IPv6 set; it must not be replaced with the general
Internet target, which can match both families. The empty-set and rendered-rule
conditions require verification before reporting enforcement.

Without `origDst`, the allowance is not limited to one public destination address.
It can match traffic through another address on the selected WAN if routing or
another NAT mapping delivers it to the same device and approved internal port.
It does not itself create that other mapping. Ordinary native allow rules also
lack a DNAT-state requirement: otherwise matching, directly routed IPv4 traffic
can qualify. Retaining `origDport` restricts the original port, not whether NAT
occurred. These differences must appear in the preview and confirmation.

For a TCP-only plan, UDP and other ports are outside the candidate. Device scope
follows the device's native address set rather than pinning the allow to just one
internal IPv4 address; the NAT destination remains explicitly pinned. Existing
policy precedence and network reachability still affect the outcome. No assertion
about a particular device's IPv6 configuration follows from these source tests.

## Explicit app-created object management

The separately enabled [app-created forwarding workflow](app-created-forwarding.md)
adds exact-object adoption, TCP/UDP reset plans and restart-safe conditional recovery.
It does not add NAT66 or new IPv6 pinhole creation. Review its scope and validation
limits before enabling it.
