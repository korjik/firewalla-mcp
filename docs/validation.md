# Validation record and safe live procedure

## Completed

- Local Python tests: argument injection and invalid ports, allowlisted targets, strict SSH options, byte caps, subprocess/transport timeout cleanup, unsupported schemas, secret-field projection, independent-vantage regression, MCP catalog and actual stdio initialize/list/call roundtrip.
- Actual helper executed in memory over an existing trusted SSH connector on two authorized appliances. Health, all network modes, configured forwarding mappings, ipset names, router socket count and NAT counters returned `ok`. Filter counters returned `ok` on one and `unsupported` on the other. No raw outputs were published.
- No keys generated or installed. No firewall/VPN settings, services, packages, automations or NAS deployment changed.

## Not established

The cloud workspace has no authorized direct LAN TCP route or dedicated mounted router key. Therefore the new server's own OpenSSH transport has not authenticated to a real appliance end to end. The existing connector supplied the live helper channel. DNS/TCP target probes, a known-MAC device lookup, a selected VPN interface, full live diagnosis, UDP, packet capture, ARM container execution and persistent access are not live-validated. No application/provider assignment or effective kernel mapping is claimed verified.

## Owner-run end-to-end checks

On the intended trusted LAN host, configure a dedicated key and verified host fingerprints per `ssh-setup.md`; no need to change the router firewall or restart anything. Start the server or container from an MCP client. Call `list_boxes`, then `capabilities`, `system_health` and `network_state` for each configured label. Compare the values privately with local administrative observations. Only query a known device MAC or VPN interface you have selected. To exercise TCP diagnosis, explicitly allow the chosen target IPs in each box's `probe_networks` and choose an independently routed box. Do not perform general scans.

For helper-only read-only validation through an existing SSH connector, `python scripts/live_probe.py` emits a shell-quoted command that sends the exact helper in memory and prints statuses only. Review the command, then execute it with a 55-second connector timeout. It does not need a new key, installation or writable remote directory. This checks helper operations only, not MCP/OpenSSH transport.

Additional helper checks passed on both appliances: fixed service states, VPN interface candidates, interface traffic counters, active alarm count, system resolver configuration and a source-scoped loopback conntrack query (empty result, not populated production-flow validation). The Docker image built successfully and the MCP protocol smoke test passed; the final expanded catalog of 21 tools passed the container MCP initialize/list/call smoke test. All 45 local tests passed. Device inventory first-page reads also passed on both appliances after adding support for empty nonterminal SCAN pages.

Write extension: 71 automated tests passed including host-side approvals and state checks. No write operation has run on any appliance. The previous live helper evidence remains read-only. The catalog has expanded to 27 tools; final Docker/CI checks are performed on the write-extension commit.

Final write-extension local verification: 27-tool Docker MCP smoke passed; a disposable network-none container successfully added and removed a blackhole route, filter rule and DNAT rule, and rejected stale rollbacks. No router credentials or LAN access were supplied to that sandbox.

Reference-informed read extension: 78 local tests pass. Alarm summaries, managed-rule summaries and aggregate flow samples returned `ok` on both appliances using the actual selected read functions through the existing SSH connector. Only status summaries were retained. The full command was rejected by the connector as invalid before execution; a shorter read-only harness containing just those same functions succeeded. No write was attempted. Final catalog: 30 tools.

Device-control/flow extension: dynamic app catalogs, explicit/global feature-state projection and bounded control-rule pages returned `ok` on both appliances. One-row device-flow pages returned `ok` with one projected record on each appliance; probes printed only status/count, never identities or flow content. Populated blocked-record formats, category attribution completeness, group inheritance, all pagination/retention cases and pattern behavior are not comprehensively live-certified. Unit tests cover tri-state, Video→av, direction, category filtering, equal timestamps and descriptive pattern logic.

A live loopback VPN-profile query was rejected by automatic approval review because the response may include configuration/credentials. It did not execute and was not retried. Source review confirmed `VPNClient.getAttributes` includes config/settings. The code does not use that endpoint, fetch a full init response, or expose raw VPN configuration. Profile import, connect/disconnect and executable device/group VPN switching remain unsupported pending safe management and secret-scoped verification.

Final consolidated local suite: 100 tests pass, including service-field redaction and RADIUS flag-only reads. Current catalog: 39 tools (only apply_change mutates; three stage tools are explicitly non-executable). The Services adapter is source/mocked only. The public draft will retain a clear list of unsupported persistent controls/VPN/services rather than claiming feature parity.

HTTP extension: 113 tests pass, including real ASGI Streamable HTTP initialize/list/call and auth/Host/Origin/query-token rejection. Full catalog remains 39; HTTP read-only catalog contains 34. Live ContextForge/Okta registration, production TLS/network policy and end-to-end real-router transport are still not verified.

Final container verification: stdio initialize/list/call passed with 39 tools; authenticated Streamable HTTP initialize/list/call and health passed with 34 read-only tools, and unauthenticated requests were rejected. The isolated network-none kernel route/filter/DNAT apply/stale-check/rollback test passed again. No actual gateway registration, Okta configuration, router credential provisioning or live appliance mutation occurred.
