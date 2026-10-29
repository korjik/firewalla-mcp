# Unofficial Firewalla MCP over SSH

Read-only diagnostics for any number of named Firewalla boxes. Uses verified SSH and the official Python MCP SDK over **stdio**. Not affiliated with or supported by Firewalla. No internal HTTP API is enabled, and nothing is installed on the router. Python 3 and standard diagnostic utilities must already be present there.

## Quick start

1. Follow [SSH setup](docs/ssh-setup.md). Verify each host fingerprint independently and install a dedicated owner-managed public key.
2. Copy `examples/config.json` to `config.json`. Replace documentation addresses, define your own box labels, and supply absolute key/known-hosts paths. `sites` accepts any number of boxes. `box_name` selects one. TCP targets must fall within that box's `probe_networks`; empty means TCP probes are denied. Set narrow ranges. Different `vantage_group` values assert independent network paths; they do not discover them.
3. Use Python 3.11+ and OpenSSH client:

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps .
FIREWALLA_MCP_CONFIG=/absolute/path/config.json .venv/bin/firewalla-mcp
```

The process waits for MCP JSON-RPC on stdin. A silent terminal is expected. There is no HTTP listener or web health endpoint.

Typical MCP client configuration:

```json
{
  "mcpServers": {
    "firewalla": {
      "command": "/absolute/path/.venv/bin/firewalla-mcp",
      "env": {"FIREWALLA_MCP_CONFIG": "/absolute/path/config.json"}
    }
  }
}
```

## Docker and NAS hosting

```sh
cp examples/config.json config.json
mkdir -p secrets
# Place owner-managed keys and verified known_hosts in secrets; never commit them.
docker compose build
docker compose run --rm -T firewalla-mcp
```

Configure the client with `command: "docker"` and `args: ["compose", "-f", "/absolute/path/compose.yaml", "run", "--rm", "-T", "firewalla-mcp"]`. Keep config and keys on persistent NAS storage mounted read-only. Set `MCP_UID`/`MCP_GID` to a NAS service user that can read the files; private keys must be owned by that user with mode 600. The default container UID is 10001. The container runs without capabilities, with a read-only root filesystem and resource limits. It needs outbound LAN TCP access to each SSH port, not host networking or a privileged container.

Run one stdio container per client session; do not use `compose up -d` as an HTTP service. For a client on another trusted LAN machine, run Docker through an owner-administered SSH session on the NAS (`ssh -T nas-host docker ... run --rm -i ...`). Protect that NAS access separately. No inbound container ports are required or published. HTTP transport and authentication are deliberately not implemented.

Startup health: an MCP client must successfully initialize, list tools, and call `list_boxes`; then call `capabilities` for each box. `python tests/container_smoke.py firewalla-mcp:local` verifies the image's MCP protocol with an empty configuration and **does not contact a router**. A healthy process is not evidence of SSH connectivity.

## Tools

| Tool | Scope |
| --- | --- |
| `list_boxes` | Labels only |
| `capabilities` | Utility availability; adapters validate shapes on each call |
| `system_health` | Uptime, load, memory |
| `network_state` | Interfaces, VLAN IDs, addresses, routes, rules, neighbors |
| `device_lookup` | IPv4 address for one known MAC; no names or full Redis hashes |
| `vpn_interface_status` | Selected interface state/addresses, not provider health |
| `port_forward_mappings` | Sanitized configured intent from Redis |
| `firewall_counters` | Bounded IPv4 table counters; incomplete match/translation view |
| `ipset_names` | Names only, no members |
| `connection_summary` | Router-local socket count; not forwarded NAT flows |
| `dns_lookup` | System resolver addresses; generates DNS traffic |
| `tcp_probe` | One allowlisted TCP handshake without application payload |
| `diagnose_port_forward` | Separates service, VPN, provider claim, mapping and external evidence |

See [feature support and validation](docs/features.md) for implemented, live-tested, unsupported, and future capabilities. Results can be `ok`, `unsupported`, or `unavailable`; an unsupported query is never interpreted as an empty ruleset. Collection sizes are capped and report truncation where applicable.

## Port forwarding diagnosis

Call `diagnose_port_forward` with a box label, device IP, listening port, selected VPN interface, current provider-assigned port, public endpoint IP, and optionally another box on an independent path. All values are runtime inputs. No provider, interface or port assignment is hardcoded.

The workflow tests device TCP reachability from the router (not the application's actual local bind settings), reports interface state, labels the provider assignment as user-supplied, returns configured mappings, and probes the public endpoint from the selected sites. **Device VPN policy resolution and effective kernel NAT mapping are explicitly unsupported** in this first version. Use the application settings, Firewalla app and provider dashboard to verify those separately. Configured ranges can cover a port without an exact single-port rule. Do not change rules merely because a same-network probe times out: routing, hairpin NAT, provider behavior or a blocked return path can explain it. An independent successful handshake establishes reachability from that vantage at that moment, not application identity or UDP reachability.

[PrivateVPN's official Linux guide](https://help.privatevpn.com/en/articles/438960-how-to-verify-vpn-port-forwarding-on-linux-os) explains locating the tunnel address and using its provider port lookup. This server does not call that endpoint or send tunnel details to it. Obtain the current assignment yourself and pass it as a claim. No automated rule changes or scheduled tasks are created.

## Development

```sh
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
docker build -t firewalla-mcp:test .
.venv/bin/python tests/container_smoke.py firewalla-mcp:test
```

CI runs tests, builds the image, and performs the container MCP smoke test. [Security](SECURITY.md), [troubleshooting](docs/troubleshooting.md), and [live verification](docs/validation.md) describe limits. No router credentials belong in CI.

## Complete tool contract

All tools are read-only, but SSH connections can create normal login logs; DNS/TCP tools also generate traffic. All router tools require `box_name`. No tool changes settings. Unless stated otherwise, privilege is `pi` without sudo. Remote subprocesses are capped at 5 seconds/128 KiB; the helper is capped at 20 seconds and transport at 25 seconds. Larger results become unsupported. `H` below means the actual helper was tested through an existing SSH connector on two appliances; it does **not** mean the new server's OpenSSH path was live-tested. `M` means mock/protocol coverage only; these adapters are experimental pending an owner-run end-to-end check.

| Tool | Additional arguments | Output and bounds | Privilege | Evidence / side effects |
| --- | --- | --- | --- | --- |
| `list_boxes` | None; no box required | Configured labels, no host/key paths | Local only | Protocol tested; none |
| `capabilities` | None | Utility availability, not firmware certification | pi | H; read |
| `system_health` | None | Uptime/load/selected memory numbers | pi | H; read |
| `service_status` | None | Fixed systemd units: firemain, firemon, firerouter, redis-server, openvpn@server; load/active/substate only | pi | H; read; missing units explicit |
| `network_state` | `kind`: interfaces/addresses/routes/rules/neighbors | Up to 256 rows; VLAN ID and selected fields | pi | H all kinds; read |
| `device_inventory` | `cursor` decimal string, default `0` | One Redis SCAN page of MACs, COUNT hint 32, hard cap 256; follow returned cursor | pi + local Redis | H first page; bounded scan, no writes |
| `device_lookup` | `mac` | Known device IPv4 only | pi + local Redis | M; field read |
| `device_vpn_policy` | `mac` | Explicit state/profile identifier only; effective/inherited path unknown | pi + local Redis | M; field read |
| `vpn_interfaces` | None | Up to 256 network rows filtered by vpn_/tun/tap/wg naming heuristic; not profile inventory | pi | H; read |
| `vpn_interface_status` | `interface` | Selected interface state/addresses | pi | M selection; underlying network read H |
| `port_forward_mappings` | None | Up to 128 configured mappings, port ranges, destination, enabled flag; not effective NAT | pi + local Redis | H; read |
| `firewall_counters` | `table`: filter/nat/mangle | Up to 256 IPv4 counter rows; extensions/translation omitted | Existing sudo -n | H nat both; filter one supported/one unsupported; mangle M |
| `ipset_names` | None | Up to 256 names, no members | Existing sudo -n | H; read |
| `interface_traffic` | None | Up to 256 cumulative interface RX/TX bytes/packets/errors/drops | pi | H; read; not per-device usage |
| `connection_summary` | None | Router-local socket count | pi | H; read |
| `connection_metadata` | `source_address`, allowed by probe_networks | Up to 128 original/reply address/port tuples for one source; no payload | Existing sudo -n | H loopback empty query only; populated parsing M |
| `active_alarm_count` | `seconds`: 60–604800, default 3600 | Count over active-alarm sorted-set score window; no descriptions/device data | pi + local Redis | H; read; archives excluded |
| `dns_configuration` | None | Up to 16 system resolver IPs; no search domains | pi | H; read; split/encrypted DNS unsupported |
| `dns_lookup` | `name`: validated DNS name | Up to 32 resolved IPs | pi | M; DNS traffic |
| `tcp_probe` | `address` literal allowed IP, `port` 1–65535 | One TCP connect result; failure inconclusive | pi | M; one TCP handshake, no application payload |
| `diagnose_port_forward` | `device_address`, `service_port`, `vpn_interface`, `provider_port`, `public_address`, optional `external_box` | Separate service/VPN/provider-claim/mapping/probe evidence; effective mapping and inherited path explicitly unsupported | pi + local Redis | M workflow; up to three TCP connects; different vantage groups required for external box |

Unsupported/planned: complete Firewalla app parity, inherited effective device VPN routing, provider APIs, VPN profile credentials/configuration, complete VPN server/client health, exact kernel firewall/NAT policy evaluation, IPv6/nft firewall interpretation, ipset members, per-device historical traffic, alarm descriptions, packet capture, all persistent mutations and HTTP transport. Source-visible internal routes are not considered supported runtime APIs.

## Hardware compatibility

| SSH target | Architecture | Evidence |
| --- | --- | --- |
| Firewalla Gold Plus | x86_64 | Owner identified model; capability preflight and read-only helper checks performed |
| Firewalla Gold SE | aarch64 | Owner identified model; capability preflight and read-only helper checks performed |
| Other Firewalla models/releases | Varies | Not tested; capability/schema detection may allow individual adapters |

Both checked targets have Python 3, ip, ss, Redis CLI, iptables and timeout; nft is absent and no nft adapter is assumed. Full MCP-to-router authentication with this project's SSH transport is still an owner-run validation step. Container **host** architecture is separate from the SSH **target** architecture: an amd64 NAS/client can query an arm64 router over SSH. The Docker image uses a multi-architecture Python base, but only the local amd64 image build/runtime is tested here; ARM image execution is unverified. The container belongs on the chosen LAN host, not necessarily on a router.
