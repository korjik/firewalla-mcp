# Feature support and evidence

The [generated tool reference](tool-reference.md) is the complete schema catalog. Default read catalog37, VPN44, VPN+capture48, combined+capture64. Counts describe registration, not execution authorization or firmware compatibility.

| Family | Implemented behavior | Evidence and limits |
|---|---|---|
| System/network/services | Uptime/load/memory, fixed unit status, bounded interface/VLAN/address/route/rule/neighbor reads | Actual MCP/internal SSH reads on Gold Plus and Gold SE; not complete topology |
| Devices/People | Inventory, lookup, explicit People/group membership, names and empty groups | Bounded live projection and mocks; stored offline records and app counts can differ; never infer ownership from a name |
| VPN inventory | Saved OpenVPN/WireGuard labels, types, endpoints, observed link state | Bounded live projection; other protocols unsupported; connectivity is not administrative intent or routing proof |
| Rules/controls/apps | Paginated configured rules, scoped feature state, dynamic app IDs, schedules | Read tests and mocks; inheritance/effective enforcement may remain unknown; stage tools never apply |
| Flows/alarms/usage | Bounded per-device flows, page summaries, active alarm samples/counts, interface counters | Retention, mutable paging and domain attribution incomplete; no full archival analytics or sensitive behavior inference |
| DNS/TCP/NAT diagnosis | Resolver lookup, allowlisted TCP probe, configured mappings, counters, scoped conntrack | Each observation has its own vantage/time; local timeout does not prove global closure; UDP/provider assignment not inferred |
| Capture | Preview/start/status/cancel; scoped metadata; 15seconds/100packets maximum | Deployed permission/schema, fake-process cleanup and parser tests; no real capture yet |
| VPN lifecycle/switch | Native existing-profile start/stop and explicit device-profile switch; exact plan/state binding | Current installed source contracts reviewed; deployed methods and read/negative checks; no live mutation in deployment tests |
| VPN import | Registered router-local archive, router-local credential clone, fresh IDs, inactive/unassigned publication | Transaction mocks and one bounded one-off import; reusable MCP mutation not live-tested; maintenance window required, no atomic FireMain stop guarantee |
| Persistent WAN/interface and VPN NAT | Single mapping, bounded TCP/UDP plan; owned conditional single-map rollback | Current source pins and realistic mocks; local candidate, not deployed or live-enforcement/restart tested |
| Mixed VPN plan | Start → device switch → 1–2 forwards, expected own-state transitions | Local mocks cover drift/replay/partial outcomes; not atomic; no automatic resume/compensation or exposed mixed-plan inverse |
| Temporary kernel route/filter/DNAT | Scoped additions and conditional removal | Mock and disposable isolated-kernel tests; not Firewalla-managed persistence; not enabled by current VPN/capture gate |
| Device/app/DNS/scoped service writes | Tri-state overrides, new/scheduled block rules, DNS answer rules, scoped DNS/NTP | Five installed policy/control dependencies reviewed and pinned on both revisions; Ad Block/Safe Search/Unbound and rules/DNS supported in source. DoH/NTP remain blocked on these revisions. Not deployed or live-enforcement tested |
| Permanent routes, arbitrary rule CRUD | No validated adapter | Unsupported; temporary route tools are not a substitute |
| RADIUS, users/time quotas, arbitrary maintenance | No safe complete management contract | Unsupported; no enrollment, restart/reboot, arbitrary shell or credential-export tool |

`write_capabilities.configured_contracts` reports revision eligibility per configured box. It explicitly does not certify installed source, gate permissions or live behavior. Preview performs those checks. Failure/unknown is never an empty configuration or proof of enforcement.

## Approval migration

File-based/operator execution and the external issuer have been removed. Existing configurations fail closed until explicitly migrated to host-confirmed mode. New managed-rule activation rechecks expiry after disabled creation and reports `partial_expired` without enabling or cleaning up after the deadline. See [migration and trust boundaries](approvals.md#migrating-from-file-based-approval). These are source changes, not a claim of live deployment.

### WAN/interface forwarding

`forwarding_interfaces` projects current network UUIDs, names, types and IPv4 subnets. `preview_persistent_forward` and `preview_interface_forward_plan` add persistent WAN mappings for an existing device MAC and expected LAN IPv4, using the same confirmed `apply_change` as VPN mappings. Single additions have conditional exact-state rollback; batches stop on partial/uncertain outcomes and do not automatically compensate.

Source contract hashes were checked on Gold Plus and Gold SE; synthetic tests cover native request shape, conflicts, routing/interface drift and rollback. No live mapping, reboot, external reachability or persistence test is claimed. WAN scope matches destination addresses, including hairpin traffic, not an ingress-only ACL. See [forwarding](persistent-forwarding.md) for setup and limits.


## Opt-in complete WAN forwarding lifecycle

See [WAN lifecycle](forwarding-lifecycle.md) for the opt-in lifecycle catalog,
explicit IPv4 source scope, persistent NAT plus inbound policy, exact removals and
durable restart recovery. This is locally tested, not live-write-tested or enabled
by default. Unknown policy semantics, inherited/indirect dependencies and ambiguous
objects fail closed. It does not expand other managed or kernel write permissions.

## Optional exact diagnostic grants

The local opt-in [diagnostic grant workflow](diagnostic-grants.md) adds owner-confirmed
exact source-box/IPv4/TCP-port grants and revocation with bounded expiry/attempts.
It preserves legacy `probe_networks`, does not alter router policies, and is not
live-deployed or live-grant-tested. See the generated reference for all four tools.

### Forwarding display names

`preview_forwarding_metadata` previews a guarded rename of one or two TCP 80/443 mappings through the same lifecycle apply/recovery tools. Durable receipts preserve management identity independently of the label. Removing the optional default type field requires a separate explicit field choice; it is not implied by a rename. Native metadata replacement briefly interrupts each selected forward. This integrated workflow is locally tested and is not yet deployed. See [metadata and recovery](development/forwarding-display-names.md).
