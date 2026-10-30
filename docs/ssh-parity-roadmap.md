# SSH feature parity roadmap

Reference: [amittell/firewalla-mcp-server](https://github.com/amittell/firewalla-mcp-server),
review target `46a15cb6e82f391b44608120b5f37ba84771a33f`. It is an independent
MIT-licensed MSP-backed project. This repository remains SSH-only and requires no
MSP subscription or cloud credentials. No source code was copied for this update.
A feature name in the reference does not establish a supported local adapter.
The pinned reference exposes **28 read tools and 11 opt-in write tools**. Counts
are not a parity metric: this project's diagnostic tools cover different scopes.
The comparison below tracks functional gaps rather than matching tool totals.
Official Firewalla master reference `8b099b21f07da6096b2bc4ec3b61b3678a68f5a5`
is a research reference, not a claim about the installed firmware revision.

Priorities after the current read-result fixes:

1. Explicit People/group/device relationships, readable device labels, complete
   versus partial counts, offline records and unambiguous search. Collector and
   joins are implemented locally; deployment awaits the new helper trust gate.
2. Named saved VPN profiles and configured endpoint metadata. OpenVPN/WireGuard
   projection is implemented and mock tested. Explicitly approved live on-box projection passed on both appliances; service
   replacement approval remains pending. No profile changes or credential exports occurred.
3. Active and archived alarm details/search through validated selected-field
   schemas; do not describe the existing active summaries as complete coverage.
4. General bounded flow search and retained/sample analytics with explicit time,
   pagination, byte and attribution limits. Never promise MSP-style 30-day raw
   history when the appliance has already expired it.
5. Target-list inventory/detail where local schemas and provenance are verified.
   MSP-owned target-list management and cloud fleet statistics are not assumed
   to have local equivalents.
6. Investigate each reference write operation individually. Existing preview,
   approval and rollback infrastructure does not establish adapter parity.
   Persistent managed state, transient kernel state and staged proposals remain
   distinct; no live mutation is authorized by the parity roadmap.

See the [current coverage](requested-coverage.md), [feature catalog](features.md),
[read audit](read-audit.md), [examples](examples.md), [SSH setup](ssh-setup.md),
and [HTTP/ContextForge/Okta guide](contextforge-okta.md). Gold Plus/x86_64 and
Gold SE/aarch64 have bounded read checks; this is not full-model or full-feature
certification. Docker host architecture is separate from SSH target architecture.


## Read coverage and priorities

| Priority / family | Implemented or partial SSH coverage | Remaining work / limits |
|---|---|---|
| P1 device status, offline devices, search | Known-device lookup, paged inventory; new People/name join locally implemented | Rich device search and app-equivalent visibility/status need validation; stored records are not all online devices |
| P1 active/specific/search alarms | Bounded active summaries and counts | Detail projection, archive pagination/search, severity interpretation; expired/deleted history is unavailable, not zero |
| P1 general/recent/search flows | Bounded device flows and sampled analysis | Cross-device search and retained-history analytics; show per-source limits and last observed verdict, not current enforcement |
| P1 rules/search/summary | Paginated rich configured rules, selected filters, schedule explanations | Additional action/scope/category resolution; configured intent is not effective enforcement |
| P1 target lists/detail/search | Not implemented | Validate local customized-category metadata and ownership; do not assume MSP-owned lists have a writable local equivalent |
| P2 box/local statistics | Health, interfaces, counters, routes and services | No cloud fleet/account analytics; counters and samples are not billing totals |
| P2 regions, bandwidth, insights/trends | Limited flow-page summaries | Provenance, geographic attribution uncertainty and retention must be explicit; no invented 30-day history |
| P3 AP, channel, SSID, settings | Basic interface/VLAN observations | Hardware/controller-gated adapters, no unsupported AP functionality promised |

## Eleven reference write actions — individual adapter review

| Action | Current local state | Required contract before claiming parity |
|---|---|---|
| Create rule | Selected persistent rule previews/apply exist in source; mock-tested, disabled in reader | Supported target/scope/schedule identity, stale-state protection, management-path enforcement verification |
| Delete rule | No general delete adapter; conditional rollback only for owned additions | Existing-rule identity, scope-specific approval and before/after verification |
| Pause rule | Not implemented as general operation | Existing management update semantics and restoration of prior state |
| Resume rule | Not implemented as general operation | Same identity/approval protection; must not accidentally reactivate another rule |
| Rename device | Not implemented | Validated persistent name-management contract; preserve device identity |
| Archive alarm | Not implemented | Exact alarm identity, archive semantics and recoverability |
| Delete alarm | Not implemented | Explicit destructive scope and truthful irrecoverability |
| Mute alarm | Not implemented | Exception creation plus archive behavior; **not** a firewall allow rule |
| Create target list | Not implemented | Local ownership/schema and supported management path |
| Update target list | Not implemented | Version/stale-state checks and policy-impact preview |
| Delete target list | Not implemented | Reference checks, deletion scope and rollback limitations |

Use existing enabled local management logic for persistent writes. Never substitute
direct Redis mutation or enable development endpoints merely to fill the matrix.
The read-only deployment exposes no executable mutation tools.

## Investigation guides and resources

The reference's five prompt themes—security report, threat analysis, bandwidth
analysis, device investigation and network health—are useful guide categories.
Its summary/device/security-metric/topology/recent-threat resource themes are
likewise candidates, not newly registered resources in this server. Use observed
interfaces/routes for topology; never insert an example CIDR as measured topology.
Historical flow verdicts are *last observed*, never proof of current policy.

No reference code or prose was imported. Any later adaptation must retain the
full MIT notice, including Copyright 2024 Alex Mittell. Firewalla appliance source
has separate AGPL-3.0 obligations; schema research does not authorize wholesale
copying into this MIT project.
