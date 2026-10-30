# Firewalla MCP over SSH

Ask your AI assistant about your network, investigate connection problems, and preview supported changes to your Firewalla—all through MCP, with SSH handled inside the server.

**Local SSH access · Multiple boxes · Read-only by default · Docker or Python · Optional confirmed writes**

This unofficial community project connects directly to your Firewalla appliances. It does not require a Firewalla MSP subscription or MSP API credentials and is not affiliated with Firewalla.

[Quick start](#quick-start) · [Features](#what-you-can-do) · [Client setup](#connect-your-client) · [Write approvals](#making-changes-safely) · [Documentation](#documentation)

## Why use it?

- **Understand your network in context.** Ask about named devices, People, configured rules, VPN profiles and recent traffic without assembling separate command outputs.
- **Investigate the whole connection path.** Compare service availability, VPN routing, forwarding configuration and independent reachability. Optional short captures return packet metadata for closer inspection.
- **Manage several boxes from one server.** Configure any number of named appliances, then select the intended box in each request.
- **Start with inspection.** Writes and capture are opt-in. Supported changes use an exact preview → confirmation → apply workflow, including bounded plans with multiple actions.
- **Keep access under your control.** Run on a workstation, server or NAS with verified SSH host keys and dedicated credentials. No unrestricted shell tool is exposed.

## What you can do

| Area | Available capabilities |
|---|---|
| System and network | System/service health, interfaces, VLANs, addresses, routes, neighbors, firewall counters and bounded connection inspection |
| Devices and People | Device lookup, readable names, explicit People/group membership, empty groups and ungrouped devices |
| Rules and controls | Paginated configured rules with targets, scopes, ports and schedules; filters; scoped control settings and discovered app identifiers |
| VPNs | Saved OpenVPN/WireGuard names, types and configured server endpoints, including profiles without an interface; separate link observations |
| Traffic and alarms | Bounded per-device flow queries, page summaries, active alarm samples/counts and interface counters |
| Connection diagnosis | DNS lookups, allowlisted TCP tests and port-forward diagnosis that distinguishes configured mappings from external reachability |
| Optional capture | Preview, start, status and cancel; explicit scope; at most **15 seconds / 100 packets**, metadata only |
| Optional writes | VPN lifecycle, device VPN switching and registered inactive profile imports; source-supported rules, controls, DNS answers, VPN forwarding and compound plans |

**Availability depends on configuration and firmware.** Default startup exposes inspection tools, not executable writes. DNS/TCP diagnostics still generate network traffic; read-only does not mean passive. Some write adapters are source-supported candidates rather than deployed or live-enforcement-tested features. The [support matrix](docs/features.md) records that distinction; the [complete tool reference](docs/tool-reference.md) lists every tool, argument and limit.

This is not full Firewalla app parity. Permanent route management, arbitrary existing-rule editing, RADIUS enrollment and complete historical analytics are not supported. Temporary kernel routes/rules are explicitly separate from persistent Firewalla-managed configuration.

## How it works

```text
MCP client / AI assistant
        │
        ├── stdio ──────────────────────┐
        │                               │
        └── authenticated MCP gateway ──┤ Streamable HTTP
                                        ▼
                              Firewalla MCP server
                                        │
                              verified internal SSH
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                      router-a                      router-b
```

The server validates typed requests, selects a configured box, runs bounded SSH operations and returns structured observations. Read adapters project selected fields rather than exporting raw configuration. Managed writes use reviewed Firewalla management contracts and fail closed on meaningful firmware drift; the server does not enable disabled development endpoints.

The MCP server runs on your Docker host or workstation, **not on the router**. Routine tool use does not require a separate SSH plugin.

## Quick start

### 1. Prepare SSH access

You need:

- A Firewalla reachable from the server over a trusted LAN or VPN, with SSH enabled.
- A dedicated SSH key installed for `pi`, plus independently verified host keys in `known_hosts`.
- Docker with Compose, or Python **3.11+** and the OpenSSH client for a native installation.
- An MCP client supporting stdio or authenticated Streamable HTTP.

Start with Firewalla’s official [how to enable and access SSH](https://help.firewalla.com/hc/en-us/articles/115004397274-How-to-access-Firewalla-using-SSH), then follow our [SSH setup guide](docs/ssh-setup.md) for the Firewalla app steps, initial password login, key installation without overwriting existing keys, fingerprint verification and revocation. Do not expose router SSH to the public internet. Some diagnostics require existing noninteractive sudo; missing utilities or permissions are reported rather than silently granted.

### 2. Get the source and configure your boxes

The current implementation is on the review branch linked in [PR #1](https://github.com/korjik/firewalla-mcp/pull/1):

```sh
git clone --branch codex/ssh-diagnostics https://github.com/korjik/firewalla-mcp.git
cd firewalla-mcp
cp examples/config.json config.json
```

Edit `config.json`. Keep only the boxes you need, replace the example addresses with actual literal IPs, and set narrow `probe_networks` for any active TCP diagnostics. Each request selects a configured name through `box_name`.

For a single box, the basic shape is:

```json
{
  "sites": {
    "router-a": {
      "host": "192.0.2.1",
      "user": "pi",
      "identity_file": "/secrets/router-a_ed25519",
      "known_hosts_file": "/secrets/known_hosts",
      "vantage_group": "network-a"
    }
  }
}
```

The address is fictional. The paths above are **inside the container**: place the dedicated key and verified `known_hosts` in the host's `secrets` directory. Keep keys mode `0600` and readable by container UID/GID `10001`, with appropriate parent-directory access. Do not commit credentials. For persistent NAS hosting, keep runtime configuration and secrets outside the checkout and follow the [installation guide](docs/install.md).

### 3. Build and start read-only

```sh
docker compose build
docker compose run --rm -T firewalla-mcp
```

This starts a stdio MCP process with no published network port. It waits for MCP messages on stdin; it is not an interactive command prompt. Configure your client to launch it as shown below, then ask it to call `list_boxes` and `system_health` for your box.

For Synology/older Docker, persistent HTTP, file ownership and startup troubleshooting, use the [Docker/NAS guide](docs/install.md).

## Connect your client

| Setup | Transport | Starting point |
|---|---|---|
| Local MCP client that launches a process | stdio | Docker launch configuration below, or native Python |
| Persistent Docker/NAS service | Streamable HTTP | [Installation guide](docs/install.md), [HTTP Compose example](compose.http.yaml), [NAS example](compose.nas.readonly.yaml) |
| ChatGPT through an MCP gateway and OAuth provider | Authenticated gateway → Streamable HTTP | [Gateway and OAuth guide](docs/authentication.md) |

For clients using an `mcpServers` configuration, adapt this example to the client's schema and replace the absolute path:

```json
{
  "mcpServers": {
    "firewalla": {
      "command": "docker",
      "args": [
        "compose", "--project-directory", "/absolute/path/firewalla-mcp",
        "run", "--rm", "-T", "firewalla-mcp"
      ]
    }
  }
}
```

Prefer native Python? From the checkout:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps .
FIREWALLA_MCP_CONFIG=/absolute/path/config.json .venv/bin/firewalla-mcp
```

Use host paths for keys and `known_hosts` in the native configuration. Configure the client to launch the absolute executable path with `FIREWALLA_MCP_CONFIG` set.

HTTP serves MCP at `/mcp` and requires a protected bearer-token file plus allowed Host configuration; browser Origin headers are rejected. Keep the listener private. With a gateway, user OAuth and the gateway's backend bearer are separate authentication hops; router SSH is a third. Upgrades retain the existing integration and OAuth identities. Refresh gateway tool associations and, if needed, the ChatGPT app's **Manage → Manage app → Refresh tools** action after schema changes.

## Try asking

- “Show enabled block rules on router-a, including destinations, device scopes and schedules. Continue through bounded pages and tell me what remains.”
- “Which devices are explicitly assigned to Alex? Keep possible device-name matches separate.”
- “List saved VPN profiles on router-b with their names, types and configured server endpoints. Distinguish observed connectivity from unknown health.”
- “Summarize this device's recent flows in a bounded time window. Show top destinations and explain any missing history.”
- “Diagnose why this forwarded TCP port is unreachable. Separate the listening service, VPN path, mapping and independent external test.”
- With writes enabled: “Preview switching this device from profile_a to profile_b, preserving strict VPN and DNS settings. Wait for my confirmation.”
- With capture enabled: “Preview a ten-second capture for this device and TCP port on the selected VPN interface. Show the scope before starting.”

See [worked prompts and tool calls](docs/examples.md) for exact JSON examples, pagination and compound plans. A historical flow is an observation, not proof of current enforcement or deliberate browsing. A local timeout does not establish that a port is globally closed.

## Making changes safely

Writes remain disabled until you deliberately enable an appropriate catalog, configure its safety settings and install reviewed restricted router helpers. See [approval workflow](docs/approvals.md) and [write setup](docs/writes.md); enabling tools alone does not grant router permissions or establish firmware compatibility.

In opt-in **host-confirmed** mode:

1. **Preview:** resolve exact targets and show the proposed settings, prior state, risks and any ordered steps.
2. **Confirm:** the MCP host asks you to approve that specific plan.
3. **Apply:** the Firewalla MCP server checks the plan and executes through its internal SSH transport.
4. **Verify:** inspect per-step results and any unresolved outcome before taking further action.

Host-confirmed execution enforces target/settings binding, apply-time expiry, one-time use, expected-state checks and supported-operation/firmware boundaries. Existing file-based approval configurations require an explicit [migration](docs/approvals.md#migrating-from-file-based-approval). **The host enforces human confirmation; the server does not independently attest your reply.** Only use this mode with a trusted authenticated client. No external approval-file or SSH-plugin step is required. See the [trust model](docs/approvals.md).

A multi-action plan can bind supported VPN start → device switch → forwarding steps to one approval. It is not an atomic transaction: execution stops on unexpected failure and reports partial results. Material changes require a fresh preview; rollback is conditional where supported, not a promise to undo concurrent edits or external application actions.

Capture has its own scope confirmation and strict limits. It returns timestamps, tuples, flags and lengths, not packet payloads or PCAP files. See [capture behavior and privacy](docs/traffic-capture.md).

## Compatibility and limits

| SSH target | Architecture | Verified evidence |
|---|---|---|
| Firewalla Gold Plus | x86_64 | Utility/source checks and bounded reads through actual MCP → internal SSH |
| Firewalla Gold SE | aarch64 | Utility/source checks and bounded reads through actual MCP → internal SSH |
| Other models/firmware | Unverified | Require capability checks and compatible management contracts |

The Docker host and router architectures are independent. The amd64 container build/runtime was tested; ARM container execution is unverified. Both checked routers provide iptables and lack nft. No blanket compatibility, real capture acceptance test or reboot-persistence/enforcement certification is claimed.

The default catalog has 36 inspection tools; opt-in VPN, VPN + capture and combined write + capture configurations expose 43, 47 and 61 respectively. These counts describe registration, not authorization or live validation. A running server may expose a smaller catalog than the source; general managed-write adapters still require live enforcement validation. Consult the [support matrix](docs/features.md) and [validation record](docs/development/validation.md) before enabling a feature.

## Documentation

| Guide | What it covers |
|---|---|
| [SSH setup](docs/ssh-setup.md) | Firewalla app settings, keys, fingerprints, permissions and revocation |
| [Install and operate](docs/install.md) | Docker/NAS, native setup, persistent configuration, upgrades and rollback |
| [Authentication and gateways](docs/authentication.md) | Private gateway, OAuth, backend authentication and catalog refresh |
| [Complete tool reference](docs/tool-reference.md) | Every tool's purpose, schema, arguments and limits |
| [Feature support](docs/features.md) | Implemented, tested, candidate and unsupported capabilities |
| [Examples](docs/examples.md) | Natural-language prompts and concrete tool calls |
| [Approvals across tools](docs/approvals.md) | Common workflow, per-operation semantics and exceptions |
| [Write setup](docs/writes.md) | Enablement, drift/replay checks and partial failures |
| [Managed controls](docs/managed-writes.md) | Device/app/DNS operations and firmware restrictions |
| [VPN operations](docs/vpn-mcp-writes.md) | Lifecycle, device switching and router-local inactive import |
| [VPN forwarding and plans](docs/persistent-forwarding.md) | Persistent mappings, compound plans and verification limits |
| [Traffic capture](docs/traffic-capture.md) | Scope, metadata, limits and cleanup |
| [Troubleshooting](docs/troubleshooting.md) | Startup, access and diagnostic issues |
| [Security](SECURITY.md) | Trust boundaries and vulnerability reporting |

## Development

See [contributor guidance](CONTRIBUTING.md) for validation, firmware contracts and import internals.

```sh
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python scripts/generate_catalog.py --check
python3 -m compileall -q src scripts
```

CI tests mocked SSH/contracts, input validation and stdio/HTTP containers, plus isolated kernel changes without router credentials. Local tests do not prove live firmware behavior. Keep private keys, real VPN profiles, traffic and deployment-specific identifiers out of contributions.

For related projects and the feature comparison, see the [SSH parity roadmap](docs/development/ssh-parity-roadmap.md). This project's backend remains SSH-only.

[MIT license](LICENSE) · [Report an issue](https://github.com/korjik/firewalla-mcp/issues)
