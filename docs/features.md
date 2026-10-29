# Feature catalog and evidence

Status as of 2026-10-29. Two owner-authorized appliances were probed through an existing SSH connector with the actual dependency-free helper. Only status summaries were retained; no private output is included here. This verifies helper behavior, not this server's local OpenSSH transport to those appliances. No full firmware compatibility range is claimed.

| Area | Implemented | Validation / limits | Future or unsupported |
| --- | --- | --- | --- |
| System health | Uptime, load, selected memory counters | Mock and two-appliance helper tests passed | Disk/temperature/service health |
| Interfaces and VLANs | `ip -j -d link`, VLAN ID projection | Two appliances passed | Detailed bridge/switch topology |
| Addresses/routes/neighbors/rules | Bounded `ip -j` selected fields | All five network modes passed on both appliances | Full mark/source-aware route simulation |
| Devices | Bounded MAC scan and known MAC → IPv4 lookup | Scan schema validated separately; specific-device details mocked | Device names and richer safe projections |
| VPN client status | Selected interface status and addresses | Network adapter live-tested; selected VPN tool not live-tested | Provider health, profile inventory, secrets-free profile adapter |
| Device VPN routing | Explicit per-device policy field reader; unsupported effective result in diagnosis | Policy parser mocked; no inheritance/mark resolution asserted | Device/group/network/global policy precedence |
| Firewall | IPv4 filter/nat/mangle counters and basic matches | nat passed on both; filter passed on one and unsupported on one; mangle not live-tested | Full match semantics, IPv6, nftables |
| Ipsets | Names only | Passed on both | Member queries with explicit bounds |
| Port forwarding | Configured sanitized mappings | Parsed successfully on both; range and redaction mocks passed | Effective kernel NAT translations, schedule evaluation, VPN provider assignments |
| DNS | Validated name, bounded resolver lookup | Injection mocks; not live-tested | Per-server DNS tests |
| TCP | One allowlisted connect, no application payload | Success/failure mocked; no new live network probe performed | UDP, application handshake identity |
| Live connections/NAT | Socket count and source-scoped conntrack tuples | Count and empty loopback query passed on both; populated tuple parser mocked | Full NAT semantic evaluation |
| Central diagnosis | Separate evidence and conservative verdict | Mock independent success despite local failure | Exact mapping/policy proof and provider adapter |
| Traffic and alarms | Cumulative interface counters and active alarm count in a bounded score window | Both helper adapters passed on both appliances | Per-device history, descriptions, alarm record fields |
| Packet metadata | Not implemented | No capture performed | Explicit opt-in, packet/time cap, zero payload exposure |
| Persistent mutations | Disabled / absent | No setting changes performed | Individually reviewed and mocked adapters only |

The helper requires Python 3 and `timeout`; adapters probe utility availability and validate schemas on each call. Missing tools or unfamiliar/oversized output remain unsupported. Utility presence alone is not evidence of adapter support. There is no version string allowlist that pretends to validate unknown releases.

## Source research

Reviewed official [Firewalla source](https://github.com/firewalla/firewalla/tree/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396) (snapshot examined 2026-10-29):

- [`extension/portforward/portforward.js`](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/portforward/portforward.js) stores JSON in `extension.portforward.config` with a `maps` array, protocol, dport, toIP, toPort and enabled fields. It also contains scheduling and application logic. Reading a stored entry alone cannot prove its effective kernel behavior.
- [`net2/Host.js`](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/Host.js) uses `host:mac:` records and VPN policy/profile references. This server reads only the known IPv4 field, not entire device or VPN hashes.
- [`api/routes/me.js`](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/api/routes/me.js) has development-gated behavior. Source routes do not establish production/beta runtime support. This server never enables or relies on internal HTTP routes.

The MCP integration uses the [official Python SDK](https://github.com/modelcontextprotocol/python-sdk), pinned to the compatible 1.x API through the dependency lock. Upgrading to 2.x requires an explicit migration and protocol tests.

Additional source review: [`alarm/AlarmManager2.js`](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/AlarmManager2.js) uses the `alarm_active` sorted set for score-window counts. Only TYPE and ZCOUNT are used; no alarm record content is read. [`vpn/VpnManager.js`](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/vpn/VpnManager.js) refers to OpenVPN systemd instances; a fixed unit status is only an observation, not comprehensive server support.
