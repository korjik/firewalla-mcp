# Read-result audit

This audit distinguishes source/contract tests from live observations. It does
not claim complete firmware compatibility or exercise production writes.

| Tool group | Contract reviewed | Evidence / limits |
|---|---|---|
| list_boxes, capabilities, system_health | aliases, units, capability versus health | Both platforms read-tested; utility presence is not adapter support |
| service_status, service_feature_status | missing units/flags versus false, cached observations | Selected fields only; no logs, secret settings or enforcement claim |
| network_state, vpn_interfaces, vpn_interface_status | bounded projection, interface versus VPN health | Source/tests; derived VPN-interface result currently loses parent truncation flag, queued helper fix |
| interface_traffic, connection_summary, connection_metadata | cumulative counters, local versus forwarded sockets, bounded tuples | Units/limitations reviewed; no traffic history gathered for audit |
| device_inventory, device_lookup, device_vpn_policy | SCAN termination/duplicates, absent device, explicit versus inherited policy | Contract tests; no assertion that absent explicit policy means no VPN |
| alarm_summaries, active_alarm_count | active index versus archive, count windows | Bounded schema tests; zero applies only to the queried index/window |
| port_forward_mappings, firewall_counters, ipset_names | intent versus enforcement, incomplete match details, truncation | Projection tests; no rule changes or external reachability claims |
| dns_lookup, dns_configuration, tcp_probe, diagnose_port_forward | resolver/probe scope and inconclusive failures | Alias type fixed for external box; no active network probes required by audit |
| managed_rule_summaries | cursor/filter binding, empty filtered pages, traversal cap, partial failures, metadata | Both platforms and CF pagination verified; invalid inputs now rejected before SSH; partial rows retained |
| control_rule_page, device_controls, app_catalog | tri-state/inheritance, declared schedules, ACL versus usage support | Synthetic contract tests; incomplete inheritance remains explicit |
| list_device_flows, analyze_device_flows, flow_sample_summary | source limits, time bounds, direction/byte units, retention and unknown values | Synthetic fixtures, not private flow history; analyzer now retains coverage and unknown-byte distinctions |
| stage_device_control, stage_service_change, stage_vpn_switch, write_capabilities | source implementation versus deployed permission and non-executable proposals | Catalog tests: 34 read tools; no apply/preview write tools exposed in HTTP deployment |

## Fixed in container-side audit update

- Typed dictionary returns generate MCP outputSchema and structuredContent.
  These are object schemas, not a claim that every result field has a closed schema.
- Invalid rule cursors/filter combinations fail before SSH as tool errors.
  Action choices are advertised, rather than accepting arbitrary strings.
- Partial rule traversal preserves collected rows and a continuation cursor.
- A completed traversal beginning at cursor zero reports its matched count;
  unfiltered index totals remain separately identified.
- Global-looking scopes are described as candidates from selected fields, not
  universal/effective applicability. Unknown dynamic category IDs remain unknown.
- Known static category labels and conservative daily/weekday cron descriptions
  are added without inventing timezone, duration or effective schedule state.
- Flow analysis retains source coverage/limitations and uses null for wholly
  unknown byte totals, including destination aggregates.
- Write capability metadata reports deployed exposure and enablement separately
  from source implementations and live validation.

## Remaining specific helper issues

The router helper remains pinned to its reviewed digest. Changing it needs a new
specific trust-gate approval. Remaining candidates are: DNS-address rule action
filter support (`address` is not currently accepted), inherited/other scope-type
projection completeness, propagation of truncation in derived VPN-interface and
DNS results, and unknown blocked-flow direction when fd metadata is missing.
Do not deploy those changes by weakening the gate. Raw cron/category IDs remain
available alongside explanatory presentation; unresolved dynamic labels are not
fabricated.

ChatGPT keeps an approved tool-definition snapshot. After schema refresh in
ContextForge, the owner/admin must refresh/review the existing app actions in
ChatGPT; this does not require recreating OAuth or the integration.
