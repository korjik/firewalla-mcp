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
