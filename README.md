# Unofficial Firewalla MCP over SSH

Typed diagnostics, bounded traffic capture and optional confirmed writes for any number of named Firewalla boxes. Uses internal SSH with strict host-key verification; no MSP subscription or cloud API integration. Not affiliated with Firewalla. No arbitrary shell tool, credential export or development endpoint enablement.

## Status and catalogs

The private reference deployment exposes **47 tools**: 36 read/inspection tools, seven VPN methods and four capture methods. Its NAS image, HTTP authentication, both router read paths and ContextForge schemas were verified. Actual packet capture and general network-write deployment have not been tested live. Source contains additional guarded write adapters; their presence is not proof of installed-firmware compatibility.

| Catalog | Count | Enablement |
|---|---:|---|
| Default read/inspection | 36 | Default stdio or HTTP |
| VPN | 43 | `--vpn-write-catalog`, `vpn_writes_enabled=true` |
| VPN + capture | 47 | VPN mode plus `capture_enabled=true` |
| Combined writes + capture | 61 | `--allow-write-catalog`, both write flags and capture enabled; separate security review required |

See the [complete generated tool reference](docs/tool-reference.md) for every tool, exact arguments, schemas, annotations and behavior. The [support/evidence matrix](docs/features.md) separates implemented, deployed, contract-tested, blocked and unsupported capabilities. [Write safety](docs/writes.md) describes the confirmation and failure contract. This is not full Firewalla app parity.

## Installation

1. Follow [Firewalla SSH and dedicated-key setup](docs/ssh-setup.md), including independent host fingerprint verification.
2. Follow the [Docker/NAS installation and operations guide](docs/install.md). Copy `examples/config.json` and substitute your boxes, key paths and explicit probe ranges. Addresses and labels in examples are fictional.
3. Start stdio for a local MCP client or authenticated Streamable HTTP behind a private gateway. Initialize MCP, list tools and test `system_health` on each box.
4. For ContextForge/Okta, follow [gateway authentication](docs/contextforge-okta.md). Keep the same integration when upgrading; refresh its tool catalog and then the ChatGPT app tools.

For Python-only stdio:

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps .
FIREWALLA_MCP_CONFIG=/absolute/path/config.json .venv/bin/firewalla-mcp
```

The process waits for MCP JSON-RPC on stdin. Configure a client to launch that executable with the environment variable above; do not send terminal prose to stdin.

## Features and examples

- System/service health; interfaces, VLANs, addresses, routes, neighbors; bounded firewall/ipset/connection observations.
- Named People/group/device membership, saved OpenVPN/WireGuard profiles and configured endpoints. Names and cached link state do not establish ownership or VPN health.
- Paginated configured rules, scoped controls, app catalog, bounded device flows and descriptive summaries. Historical connections do not prove deliberate browsing or current enforcement.
- DNS/TCP diagnostics and conservative port-forward diagnosis separating local service, provider assignment, configured NAT and independent reachability.
- [Capture](docs/traffic-capture.md): explicit interface and one IP/MAC, protocol/optional port, maximum 15 seconds/100 packets. Metadata only; no payload or PCAP export.
- [VPN writes](docs/vpn-mcp-writes.md): existing-profile start/stop, explicit device switch and registered inactive profile import, with guarded previews and verification.
- Source-pinned Ad Block, Safe Search, Unbound and new/scheduled device block/DNS-answer rules; see [managed writes](docs/managed-writes.md). These candidate operations are not deployed. DoH/NTP remain blocked on current revisions.
- [Persistent VPN forwarding and compound plans](docs/persistent-forwarding.md): local candidate for start → switch → TCP/UDP mappings; not deployed. No automatic cross-step rollback or atomicity claim.

[Practical prompts and tool calls](docs/examples.md) cover rules, People, flows, VPN changes and capture. [SSH parity roadmap](docs/ssh-parity-roadmap.md) compares useful local features with other projects without promising cloud-only capabilities.

## Confirmation and security

Normal operation is **Firewalla preview → explicit user confirmation → Firewalla apply**. SSH remains internal. Select `host_confirmed` mode as documented; the authenticated MCP host must enforce confirmation. The server does not independently attest a human reply. It enforces exact plan/target/settings, expiry, expected state, replay protection, supported operation and firmware checks. No separate SSH connector or operator approval file is needed in this mode.

Read-only remains the default. Restricted router forced-command helpers are installed separately when approved; generic `pi` access is powerful and application flags alone do not restrict a stolen key. Router helper hashes, supported operations, key/known-hosts mounts and persistent private audit/consumption storage form separate boundaries. Never disable host-key checks or grant broad sudo just to resolve an error. See [security policy](SECURITY.md), [host-confirmed trust model](docs/host-confirmed-vpn.md), and [troubleshooting](docs/troubleshooting.md).

The legacy operator-file mode remains for compatibility and is documented only as an alternative. It is not the recommended reference-deployment workflow.

## Hardware and verification

| Target | Architecture | Evidence |
|---|---|---|
| Gold Plus | x86_64 | Utility/source checks and actual MCP → internal SSH bounded reads |
| Gold SE | aarch64 | Utility/source checks and actual MCP → internal SSH bounded reads |
| Other models/firmware | Unverified | Capability checks and exact management contracts must pass |

Both tested boxes have iptables; nft is absent. Docker host architecture is independent of router architecture: an amd64 NAS can query either target. The container's amd64 build/runtime was tested; ARM container execution is unverified. No router reboot/persistent-enforcement or real capture validation is claimed. See [validation](docs/validation.md).

## Development and publication

```sh
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python scripts/generate_catalog.py --check
python -m compileall -q src scripts
```

CI builds and tests stdio/HTTP containers and isolated kernel changes without router credentials. Published GitHub code, local candidate code and deployed images can differ; use the release evidence and exact commit/image digest, not a tool count alone. No keys, real VPN profiles, traffic or deployment-specific names belong in the repository.
