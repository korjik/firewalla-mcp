# Related projects, licenses and feature parity

Reviewed primary source on 2026-10-29. These are unofficial community projects; source inspection is not vendor certification or live validation. **This server remains SSH-only: no MSP backend, subscription requirement, node-firewalla pairing, cloud authentication or local development HTTP enablement is added.**

| Project / examined commit | License verified | Transport / useful patterns | Reuse decision |
| --- | --- | --- | --- |
| [amittell/firewalla-mcp-server](https://github.com/amittell/firewalla-mcp-server/tree/46a15cb6e82f391b44608120b5f37ba84771a33f) | [MIT](https://github.com/amittell/firewalla-mcp-server/blob/46a15cb6e82f391b44608120b5f37ba84771a33f/LICENSE), Alex Mittell | MSP API; rich read/write catalog, explicit write opt-in and box targeting | Feature/safety comparison only. MSP adapters not imported |
| [scott-pallas/firewalla-mcp](https://github.com/scott-pallas/firewalla-mcp/tree/0482f9183768d1b076644b8fd5fbc4c033cd3b4d) | [MIT](https://github.com/scott-pallas/firewalla-mcp/blob/0482f9183768d1b076644b8fd5fbc4c033cd3b4d/LICENSE), Scott Pallas | node-firewalla local box data path with login/pairing; examined client picks first group | Useful feature taxonomy; authentication/client code not imported. Our labels select explicit boxes |
| [brombomb/firewalla-bridge](https://github.com/brombomb/firewalla-bridge/tree/1e5f32a6302dbcb646eda52c1f9280e59aef6325) | [MIT](https://github.com/brombomb/firewalla-bridge/blob/1e5f32a6302dbcb646eda52c1f9280e59aef6325/LICENSE), brombomb | Docker REST bridge; explicit mutation gate; policy:update pause/resume through paired client | Gate and rule-state design reference only. Its paired-client write path is not an SSH API |
| [grapeot/firewalla-local-skill](https://github.com/grapeot/firewalla-local-skill/tree/fedc5f3c7b81b41fd6f2507a8dfdb6fc68685c71) | [MIT](https://github.com/grapeot/firewalla-local-skill/blob/fedc5f3c7b81b41fd6f2507a8dfdb6fc68685c71/LICENSE), Firewalla Local Skill Contributors | Local SSH/Redis CLI skill, allowlisted reads, dry-run design, bounded samples | Data-key patterns cross-checked with official source; independently implemented stricter projections. No full hashes, raw archives or raw-flow outputs imported |

No code, fixtures or license text from these projects has been copied into the implementation. Their authors retain their original copyrights. If future work imports/adapts copyrightable source, preserve that project's MIT copyright/permission notice alongside it and test the imported path. Do not import GPL-3.0-or-later code from `unknown-sh/firewalla-msp-mcp-server` into this MIT implementation without a deliberate license review; no source from that project was used.

## Feature parity decisions

| Feature family in related projects | Current local SSH support | Adaptable / unsupported gap |
| --- | --- | --- |
| Devices and box health | Paged MAC inventory, known-device details, health/services/network/VLANs | People/name joins implemented locally pending deployment; richer search and visibility semantics remain partial |
| Rules | Managed type/action/state summaries, kernel counters, opt-in temporary filter append/rollback | Selected persistent create adapters exist in source, disabled in the reader; general pause/resume/delete remain gaps. Paired-client/MSP calls cannot be translated to Redis writes |
| Port forwarding and routes | Configured mappings, conservative diagnosis, approved temporary DNAT and nonreserved-table routes | Persistent managed config and effective-policy proof unsupported |
| Alarms | Active-index count and up to 10 type/timestamp summaries | Description/details, archive paging and triage mutation unsupported |
| Flows and usage | Up to 100 recent system-flow records aggregated on-router into byte/protocol sample totals, plus interface counters | Bounded per-device selected flow fields are also available; not complete retained history or billing totals |
| DNS, VPN and connection diagnosis | Resolver state/lookup, interface observations, explicit device VPN policy, scoped conntrack metadata, TCP tests | Effective inherited VPN path and cloud/paired-client control unsupported |
| Maintenance, target lists, enrichment, scheduled controls | No mutations | Unsupported without individually validated local adapters; no fake success or hidden cloud dependency |
| Write safety | Off by default, exact box allowlists, preview/digest, operator approval, audit, verification and conditional rollback | Not atomic against external writers; no claim of full app parity |

The new alarm/flow/policy adapters were checked against official [AlarmManager2](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/AlarmManager2.js), [PolicyManager2](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/PolicyManager2.js), [FlowTool](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/FlowTool.js) and [BroDetect](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/BroDetect.js), then tested using mocked schemas and read-only helper calls on two authorized appliances. Active/archive index ordering is not assumed to be event time. Flow aggregation respects local/source direction when mapping original/responder byte counts to sampled upload/download; sampled records may overlap and are not a complete usage total.

See the [pinned functional parity matrix](ssh-parity-roadmap.md) for current priorities and all eleven reference write actions.
