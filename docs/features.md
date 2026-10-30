# Feature support and evidence

The [generated tool reference](tool-reference.md) is the complete schema catalog. Default read catalog36, VPN43, VPN+capture47, combined+capture61. Counts describe registration, not execution authorization or firmware compatibility.

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
| Persistent VPN NAT | Single mapping, bounded TCP/UDP plan; owned conditional single-map rollback | Current source pins and realistic mocks; local candidate, not deployed or live-enforcement/restart tested |
| Mixed VPN plan | Start → device switch → 1–2 forwards, expected own-state transitions | Local mocks cover drift/replay/partial outcomes; not atomic; no automatic resume/compensation or exposed mixed-plan inverse |
| Temporary kernel route/filter/DNAT | Scoped additions and conditional removal | Mock and disposable isolated-kernel tests; not Firewalla-managed persistence; not enabled by current VPN/capture gate |
| Device/app/DNS/scoped service writes | Tri-state overrides, new/scheduled block rules, DNS answer rules, scoped DNS/NTP | Five installed policy/control dependencies reviewed and pinned on both revisions; Ad Block/Safe Search/Unbound and rules/DNS supported in source. DoH/NTP remain blocked on these revisions. Not deployed or live-enforcement tested |
| Permanent routes, arbitrary rule CRUD | No validated adapter | Unsupported; temporary route tools are not a substitute |
| RADIUS, users/time quotas, arbitrary maintenance | No safe complete management contract | Unsupported; no enrollment, restart/reboot, arbitrary shell or credential-export tool |

`write_capabilities.configured_contracts` reports revision eligibility per configured box. It explicitly does not certify installed source, gate permissions or live behavior. Preview performs those checks. Failure/unknown is never an empty configuration or proof of enforcement.

## Approval migration

File-based/operator execution and the external issuer have been removed. Existing configurations fail closed until explicitly migrated to host-confirmed mode. New managed-rule activation rechecks expiry after disabled creation and reports `partial_expired` without enabling or cleaning up after the deadline. See [migration and trust boundaries](approvals.md#migrating-from-file-based-approval). These are source changes, not a claim of live deployment.
