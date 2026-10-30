# Bounded packet-header capture

Deployed in the reference47-tool service; no live capture performed. Optional
`capture_enabled=true` adds `preview_capture`, `start_capture`, `capture_status`
and `cancel_capture`. Disabled by default; existing catalogs do not gain capture
permissions implicitly. SSH is internal to the MCP server.

The host previews an exact configured box, existing interface, one IP **or** device
MAC, TCP/UDP/ICMP and optional TCP/UDP port. It obtains explicit scope confirmation
before calling `start_capture(plan_id)`. There are no user-supplied tcpdump flags,
BPF expressions, shell commands, filenames or PCAP exports. `any`, scoped IPv6,
multicast/unspecified targets, malformed interfaces and broad unscoped capture are
rejected. Device MAC filters are meaningful only where the link type exposes the
MAC; use the observed target/tunnel IP on a routed VPN interface.

Defaults:10seconds/50packets. Hard limits:15seconds/100packets,96captured bytes per
packet,64KiB helper output, one active capture per box/two total,16retained jobs,
two-minute start-plan expiry and ten-minute in-memory result expiry. No packet
files are written. A privileged fixed helper runs tcpdump with a snapshot limit,
then parses PCAP **inside router memory**. Snapshot bytes may include a short payload
prefix after headers; those bytes are discarded and never returned or logged.
Output is allowlisted timestamps, IP tuples, TCP flags, wire/captured lengths,
fragment/parser completeness and capture counters. DNS/application text, raw
stderr, payload, hex/base64 data and credentials are not output.

Ethernet/VLAN, Linux cooked v1/v2 and raw-IP framing are supported for IPv4/IPv6.
Bounded IPv6 extension parsing and fragments can produce missing ports or skipped
records. Unsupported/malformed/truncated input is reported as incomplete, not zero
traffic. Received-by-filter counters may have platform-specific semantics. Missing
statistics are `null`; packet loss, truncation or unknown counts prevent an absence
conclusion. A zero-packet capture says only that this scope saw none during its window.

## Coordinating an external probe

1. Preview `router-a`, interface `vpn_example`, address `192.0.2.10`, TCP41000,
   duration15 and packets50. Explain that the filter exposes connection metadata.
2. Confirm and call `start_capture`. Wait for **ready** before probing. A startup
   failure or completed capture is not a ready listener.
3. Independently authorize an external TCP probe using its own tool/host scope.
   Capture itself sends no probe. Account for tool latency: confirm the probe's
   timestamp overlaps `started_at`/`ended_at`.
4. Poll `capture_status`. Inspect `capture_status`, `stop_reason`, dropped counts,
   unparsed/truncated flags and SYN/SYN-ACK/RST tuples. Stop early with
   `cancel_capture`; poll completion rather than assuming cancellation finished.

For WAN-versus-VPN forwarding, use separate narrowly scoped captures and probes on
WAN and VPN ingress. A WAN success does not establish VPN forwarding. An observed
VPN SYN/RST shows packets reached that observation point; it does not alone identify
which host/service emitted the reset or prove a missing NAT rule. Correlate with
mapping/kernel/return-path diagnostics. A home-path timeout is not global closure.
No packet trace from another chat is treated as verified evidence by this candidate.

## Cleanup and permissions

The reviewed helper invokes fixed `/usr/bin/tcpdump`; deployment must verify that
binary. Root privilege is needed for packet capture. The new forced-command branch
accepts **only** the SHA256-pinned helper source with fixed
`sudo -n timeout --signal=TERM --kill-after=3 22 python3 -I -c <pinned source>`.
The JSON request goes over stdin and is independently validated on-box. No arbitrary
root Python or shell is exposed. Existing SSH authentication/host verification stay.
A cancel/EOF/HUP/TERM triggers process-group SIGINT and a bounded SIGKILL fallback.
The outer root timeout remains a cleanup backstop if SSH disconnects or the host
process fails. The host also closes stdin and bounds the SSH process lifetime.
Network failure cannot promise immediate remote cleanup; the hard deadline still
applies. Capture jobs/results are transient and are lost on backend restart.

## Installation boundary

Approve backend capture opt-in, existing private ledger/audit mounts, the reviewed
capture-helper pin and narrowly scoped root-capture gate branch, plus refresh of
these four tools in the same MCP gateway integration. Do not enable the pending
network-write gate or any unrelated operation as a side effect. The candidate
capture gate starts from the existing VPN gate; it does not allow persistent-forward
or generic writes. No new keys/credentials, sudo grants or OAuth provider identities are part
of this proposal. If existing sudo cannot run the exact helper, report that blocker;
do not broaden it automatically. A real capture needs a separate exact-scope host
confirmation; implementation/deployment approval is not capture authorization.

Tests use synthetic frames and a fake tcpdump executable: parsing, payload redaction,
invalid/injected arguments, real subprocess cancellation/timeout cleanup, permission
failure, empty/drop/truncated results, transport timeout and concurrency. They do
not establish actual router capture availability or observed network behavior.
