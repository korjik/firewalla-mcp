# Unofficial Firewalla MCP over SSH

Read-only-by-default diagnostics with optional approved temporary kernel changes for any number of named Firewalla boxes. Uses verified SSH and the official Python MCP SDK over **stdio or authenticated Streamable HTTP**. Not affiliated with or supported by Firewalla. No internal HTTP API is enabled, and nothing is installed on the router. Python 3 and standard diagnostic utilities must already be present there.

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

The process waits for MCP JSON-RPC on stdin. A silent terminal is expected. In this default stdio mode there is no HTTP listener; optional authenticated HTTP is documented below.

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

Run one stdio container per client session; do not use `compose up -d` as an HTTP service. For a client on another trusted LAN machine, run Docker through an owner-administered SSH session on the NAS (`ssh -T nas-host docker ... run --rm -i ...`). Protect that NAS access separately. No inbound container ports are required or published. For an authenticated HTTP gateway backend, use the separate `compose.http.yaml` example and integration guide below.

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

The diagnostic tools below are read-only, but SSH connections can create normal login logs; DNS/TCP tools also generate traffic. All router tools require `box_name`. Write tools are separately cataloged below and disabled by default. Unless stated otherwise, privilege is `pi` without sudo. Remote subprocesses are capped at 5 seconds/128 KiB; the helper is capped at 20 seconds and transport at 25 seconds. Larger results become unsupported. `H` below means the actual helper was tested through an existing SSH connector on two appliances; it does **not** mean the new server's OpenSSH path was live-tested. `M` means mock/protocol coverage only; these adapters are experimental pending an owner-run end-to-end check.

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

Unsupported/planned: complete Firewalla app parity, inherited effective device VPN routing, provider APIs, VPN profile credentials/configuration, complete VPN server/client health, exact kernel firewall/NAT policy evaluation, IPv6/nft firewall interpretation, ipset members, per-device historical traffic, alarm descriptions, packet capture, persistent routes/port forwards, profile provisioning and group/global mutations. Source-visible internal routes are not considered supported runtime APIs.

## Hardware compatibility

| SSH target | Architecture | Evidence |
| --- | --- | --- |
| Firewalla Gold Plus | x86_64 | Owner identified model; capability preflight and read-only helper checks performed |
| Firewalla Gold SE | aarch64 | Owner identified model; capability preflight and read-only helper checks performed |
| Other Firewalla models/releases | Varies | Not tested; capability/schema detection may allow individual adapters |

Both checked targets have Python 3, ip, ss, Redis CLI, iptables and timeout; nft is absent and no nft adapter is assumed. Full MCP-to-router authentication with this project's SSH transport is still an owner-run validation step. Container **host** architecture is separate from the SSH **target** architecture: an amd64 NAS/client can query an arm64 router over SSH. The Docker image uses a multi-architecture Python base, but only the local amd64 image build/runtime is tested here; ARM image execution is unverified. The container belongs on the chosen LAN host, not necessarily on a router.


## Write tool catalog (disabled by default)

All mutation execution requires an administrator-enabled gate, per-box table/chain allowlist, preview, exact one-time **operator-created approval file**, stale-state check and verification. See [write enablement, approvals, audit and rollback](docs/writes.md). No real appliance write has been tested. Mock tests cover approval behavior; disposable-container kernel tests cover actual Linux commands. These are not persistent Firewalla app changes.

| Tool | Arguments | Output / limits | Privilege and side effects |
| --- | --- | --- | --- |
| `write_capabilities` | None | Configured gate and supported/unsupported write paths | Local, no mutation |
| `preview_route_change` | `box_name`, IPv4 `destination` CIDR, numeric allowed `table`, `route_type` blackhole/unicast, optional `gateway` and `interface` (required for unicast) | Exact add diff and snapshot-bound 10-minute plan; refuses replacements and reserved tables 253/254/255 | Read only; planned apply uses sudo to add one temporary kernel route |
| `preview_firewall_rule` | `box_name`, allowed existing `chain`, IPv4 source/destination CIDRs, TCP/UDP `protocol`, `destination_port`, ACCEPT/DROP/REJECT `action` | One marked rule append plan; no arbitrary flags or chain creation | sudo for snapshot; planned apply appends one temporary filter rule |
| `preview_port_forward` | `box_name`, allowed existing NAT `chain`, `public_address`, input `interface`, TCP/UDP `protocol`, `external_port`, `destination_address`, `destination_port` | One marked DNAT append plan; no companion routing/filter rules or provider changes | sudo for snapshot; planned apply adds temporary IPv4 DNAT only |
| `apply_change` | `plan_id` | Single approved application or rollback, verified outcome, or stale/uncertain result; repeat calls do not repeat mutation | sudo; can alter connectivity. Requires separate host approval. Remote byte/time limits still apply |
| `preview_rollback` | Previously applied `plan_id` | New removal plan only if complete post-state still matches within the plan lifetime; requires new approval | Read only until applied; removes only the exact verified addition |

The base catalog described above has 30 tools: 24 diagnostic tools plus these six write-management tools; seven further inspection/staging tools below bring the current total to 37. Five write-management tools only describe or preview; `apply_change` is the sole mutation boundary. Plan memory is bounded to 128 live entries. Rollback is not automatic, and cannot be promised after a disconnect or unrelated configuration change.

Persistent routes/port-forward configuration, general rule editing, VPN connect/disconnect/profile provisioning, service restarts/reboots/upgrades and arbitrary shell execution remain **unsupported**. Selected persistent device settings, new block rules and existing-profile device VPN switches are implemented separately below. The source management paths are described in `docs/writes.md`; no development endpoint is enabled. This project does not claim the full Firewalla app suite is safely available over SSH.

## Related project

[amittell/firewalla-mcp-server](https://github.com/amittell/firewalla-mcp-server) is another unofficial MIT-licensed project. Its README describes an MSP API integration with read tools and opt-in write tools. This repository implements local SSH transport instead and does not require an MSP account. Neither project is represented here as official or vendor-tested. No code was copied from that project.


## Additional local read adapters

These adapters were independently implemented after the [related-project and license review](docs/related-projects.md), cross-checked against official source, mock-tested and read-tested on both appliances. All use the existing SSH transport and selected `box_name`; no MSP account or cloud login is used.

| Tool | Additional arguments | Output / limits | Privilege and effects |
| --- | --- | --- | --- |
| `alarm_summaries` | `limit` 1–10, default 5 | Active-index sample of numeric ID, alarm type and payload timestamp; no description, endpoint/device identity or detail hash | pi + Redis; selected-field reads only; index order is not an event-time guarantee |
| `managed_rule_summaries` | `limit` 1–10, default 5 | Managed rule ID/type/action/disabled/direction; no targets, names or enforcement claim | pi + Redis; selected-field reads only |
| `flow_sample_summary` | `limit` 1–100, default 20 | Recent system-flow sample aggregated on router into upload/download byte and protocol counts; no raw records/endpoints/payload | pi + Redis; bounded read; overlapping samples are not historical usage or billing totals |

[Feature parity and provenance](docs/related-projects.md) explains which ideas are implemented, adaptable or unsupported and records the reviewed MIT licenses. No third-party source was vendored or copied.

## Device controls, apps and flow investigation

The following section adds seven tools to the base catalog; the current total including service inspection below is **42 tools**. The following seven extend the catalog above; all seven are read-only, and staged control/VPN proposals are explicitly **not executable write plans**. See [semantics, filters, retention and VPN limitations](docs/device-controls-and-flows.md).

| Tool | Arguments beyond `box_name` | Output / limits | Privilege, effects and evidence |
| --- | --- | --- | --- |
| `device_controls` | `target_kind`: device/group; `target`: exact MAC/numeric group ID | Selected explicit/global Ad Block, Safe Search, Unbound and raw DoH state; effective inheritance unknown | pi + Redis; selected reads. Device observations passed on both; group semantics source/mocks |
| `app_catalog` | None | Up to 256 locally cached IDs/features; ACL targets only for `features.acl=true` | pi + Redis; no cloud request. Read-tested both; no guaranteed screenshot app list |
| `control_rule_page` | target kind/target, `offset` 0–10000, `limit` 1–20 | Filtered page of explicit/global-candidate Internet/category/app rule metadata and declared timers/schedules | pi + Redis; bounded reads. Read-tested both; no effective-policy or schedule execution claim |
| `list_device_flows` | `mac`, UTC epoch `start`/`end` (max 7 days), connections/blocked/all `verdict`, all/inbound/outbound `direction`, offset, limit 1–25, include/exclude category ID lists (16 total) | Up to 75 projected records/page; known bytes, metadata and next offset; retention/attribution/mutable-pagination limits explicit | pi + Redis; private flow metadata reaches client, no payloads. One populated connection page read-tested on each; comprehensive blocked/version coverage unverified |
| `analyze_device_flows` | MAC/time range, verdict, offset, limit | Page-only byte totals, top destinations, UTC hourly counts/repeats; no anomaly assessment without baseline | Same bounded reads; descriptive analysis mocked; no sensitive behavioral inference |
| `stage_device_control` | target kind/target, control, enable/disable/inherit, optional dynamic `app_id` | Non-executable proposal/current observations; no apply token | Read only; persistent management not validated. Category enable means enable blocking; app control is network access, not OS app management |
| `stage_vpn_switch` | exact MAC, `expected_profile` M, `destination_profile` N | Explicit-current-profile check and non-executable proposal; required validation gaps | Read only. Destination existence, strict/DNS preservation, effective routing and rollback still unverified; no secret config retrieval or real switch |

Scoped feature `false` means inherit and `null` explicit disable in reviewed Safe Search/Unbound/Ad Block semantics; global settings differ. Category/Internet buttons are Rules. Local Video ID is `av`. Usage tracking is not the same as app blocking, and user Time Limits are not device quotas. Removing a device override does not prove a global block is bypassed.

## Service inspection and proposals

**Current total: 42 tools.** Only `apply_change` can execute a mutation; it remains disabled by default and requires host-side approval. The three `stage_*` tools return non-executable proposals, not supported persistent writes. These two service inspection/proposal tools are complemented by the persistent tools below:

| Tool | Arguments beyond `box_name` | Output / limits | Privilege, effects and evidence |
| --- | --- | --- | --- |
| `service_feature_status` | `feature`: all/doh/unbound/ntp/radius/custom_dns | Selected DoH provider IDs, Unbound DNSSEC/killSwitch/DNS-over-VPN reference, cached NTP status, RADIUS dynamic flag; custom DNS explicitly unsupported | pi + Redis; mock-tested, no live service-specific verification. No provider URLs/stamps, VPN profiles, RADIUS users/secrets or full configs |
| `stage_service_change` | feature, enable/disable/inherit, device/group/network/global target kind and exact target | Non-executable scope proposal and observations; no apply token | Read only. Service management and effective scope unverified; no DNS/NTP/RADIUS change or enrollment |

[Service support matrix](docs/services.md) covers DoH, Unbound/DNS-over-VPN, Custom DNS Rules, NTP Intercept and RADIUS. [Validation record](docs/validation.md) distinguishes mocked, isolated-kernel and live helper evidence. Persistent DNS overrides, RADIUS management, device/app policy writes and VPN provisioning/switching are not falsely presented as implemented.


## ContextForge / Okta integration

[Secure HTTP and gateway guide](docs/contextforge-okta.md) covers genuine Streamable HTTP at `/mcp`, mandatory file-backed bearer authentication, private bind defaults, Host/Origin checks, TLS/network isolation and ContextForge registration. `compose.http.yaml` is a separate loopback-only example. HTTP defaults to 34 read-only tools; a separate explicitly enabled writer can expose the complete 42-tool catalog. Okta belongs at the gateway authentication/authorization boundary; no MSP integration is added. No live gateway, Okta or NAS deployment is claimed completed.


## Persistent Firewalla-managed writes (experimental)

Three additional preview tools produce executable `apply_change` plans. They use Firewalla's **existing** loopback management logic over SSH; they never enable an endpoint or write Redis policy fields directly. They require explicit write enablement, a per-device allowlist, exact reviewed source revision and a clean tracked source tree. All are **contract/mock tested only; no live management write or enforcement test has run**. HTTP read-only mode omits these three tools, retaining 34 tools; full mode exposes 42.

| Tool | Arguments (plus `box_name`) | Purpose, scope and limits | Privilege / side effects / verification |
|---|---|---|---|
| `preview_managed_device_control` | `device` MAC, `feature`: adblock/safeSearch/unbound/doh, `desired`: enable/disable/inherit | Persistent device override; requires an existing explicit, recognized value. Exact previous value is available for approved rollback. No group/global/provider changes | pi + local Redis + already-running loopback API. Preview reads only; approved apply can change filtering/DNS and trigger normal Firewalla enforcement. Stored state verified, enforcement unverified |
| `preview_managed_block_rule` | `device` MAC, `rule_type`: internet/category/app/ip/dns, `target` | New persistent outbound block. Category IDs games/social/av/porn/vpn; app IDs require dynamic ACL support. Maximum 128 active policies; possible duplicates rejected. Rollback removes only returned rule ID | Same privileges. Preview includes bounded rule fingerprint; approved apply uses policy:create/delete. Full rule content stays on appliance; selected fields and opaque hashes only. No schedules or arbitrary existing rule editing |
| `preview_managed_vpn_switch` | `device` MAC, `expected_profile`, `destination_profile` | Switch explicit enabled device policy between existing allowlisted OpenVPN/WireGuard profiles. Safety/DNS flags must match; settings never modified. Exact prior policy rollback | Same privileges plus selected local profile settings inspection. No VPN config/key files opened, profile API queried, or credentials returned. Stored policy verified; effective route, DNS and kill-switch behavior remain unverified |

See [persistent adapter enablement, compatibility, evidence and remaining gaps](docs/managed-writes.md). A stored-state acknowledgment is not evidence that network enforcement has completed. Existing inherited/global blocks continue to apply. The `stage_*` tools remain non-executable exploration tools and are not substitutes for these previews.
