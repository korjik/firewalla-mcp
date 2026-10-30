# Practical prompts and tool calls

Examples use fictional box labels and documentation-safe addresses. Check the
server's advertised schema: the running deployment may lag local source. The
People and saved-profile tools below are deployed in inventory-v1.

## Rules

Prompt: “Show configured enabled block rules on router-a, including targets,
scopes and schedules. Continue through bounded pages and say what remains.”

```json
{"box_name":"router-a","limit":50,"enabled":true,"action":"block","cursor":"0"}
```

Call `managed_rule_summaries`; pass the exact returned cursor for the next call
with unchanged filters. Empty filtered pages can still have more data. `total`
is the unfiltered index count, not the number matching your filter. A configured
rule and its schedule are not proof of current effective enforcement.

## People and devices

Prompt: “Show devices explicitly assigned to Alex on router-a. Keep name matches
separate and tell me whether the membership inventory is complete.”

```json
{"box_name":"router-a","person":"Alex"}
```

Call `people_and_devices`. Omit `person` for the bounded directory. If duplicate
names exist, use the returned stable person ID. People can be linked through
explicit device-tag relationships. Counts are distinct stored MAC records,
including retained offline devices, and can differ from the app display.

For a known device, call `device_lookup` with:

```json
{"box_name":"router-a","mac":"02:00:00:00:00:01"}
```

## Flows

Prompt: “Inspect a bounded recent flow window for this device. Separate observed
connections from inferred patterns, disclose retention and pagination limits,
and do not infer intentional browsing from background connections.”

Call `list_device_flows` or `analyze_device_flows` with `box_name`, `mac`, and
explicit Unix-second `start`/`end`. Use the currently advertised filters and page
limits. Record timezone when translating a human time range. Unknown byte totals
are not zero, and a sampled page is not a complete traffic history.

## Saved VPN profiles

Prompt: “List saved VPN names and types on router-b, including profiles without
interfaces. Show configured server hostname/IP, port and UDP/TCP separately;
do not claim which failover endpoint is active.”

```json
{"box_name":"router-b"}
```

Call `saved_vpn_profiles`. This inventory currently covers OpenVPN/WireGuard only.
No credential/config content is returned. `vpn_interfaces` remains a separate
interface observation, not a saved-profile inventory or health test.

## Read versus write

The default HTTP catalog exposes no executable write tools. `stage_*` results
are non-executable proposals. Never treat their output as an applied change.
An independently enabled writer still needs a supported adapter, explicit scope,
preview, bound approval and verification; see the managed-write documentation.

## Refresh an existing ChatGPT app

After an approved backend upgrade and ContextForge catalog refresh, open the
existing app's **Manage → Manage app → Refresh tools** action (wording/availability
can vary by account). Review the updated tools. Do not recreate the Okta client,
change its identity or duplicate the integration just to refresh schemas.

## Confirmed VPN change

Prompt: “Preview switching this exact device from profile_a to profile_b on
router-a. Preserve strict VPN and DNS settings. Show the impact; wait for my
confirmation before applying.” Call `preview_managed_vpn_switch` with the resolved
MAC, `expected_profile` and `destination_profile`. After explicit confirmation,
call `apply_vpn_change` with only the returned plan ID. If state changed, obtain a
fresh preview. Do not use a separate SSH approval step in host-confirmed mode.

## Bounded capture

Call `preview_capture` with:

```json
{"box_name":"router-a","interface":"eth0","address":"192.0.2.10","protocol":"tcp","port":41000,"duration":10,"packets":50}
```

Show the exact privacy scope and obtain confirmation, then `start_capture(plan_id)`.
Wait for `ready` before an independently authorized external probe. Poll
`capture_status(plan_id)`; use `cancel_capture(plan_id)` to stop early. Report drops,
unparsed/truncated/incomplete observations. Zero records does not prove global
closure. Compare separate WAN and VPN captures without assuming a WAN mapping is
also a VPN mapping. No PCAP or payload export is supported.

## Candidate compound writes

When the separately reviewed combined catalog is actually enabled,
`preview_network_plan` can enumerate start → device switch → TCP/UDP forwards.
One confirmation binds that exact ordered plan. Stop on partial/uncertain failure;
do not claim atomic rollback or automatically execute external app operations.
The reference47-tool deployment does not expose this candidate.
