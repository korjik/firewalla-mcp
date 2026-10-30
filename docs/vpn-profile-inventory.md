# Saved VPN profile inventory

`saved_vpn_profiles` implements a bounded local projection of OpenVPN and
WireGuard saved profiles, independent of interface existence. Installed source
on both tested platforms confirms OpenVPN `.ovpn` discovery, WireGuard `.settings`
discovery via the base client, `.settings` displayName/serverBoxName, `.json`
WireGuard peers, `vpn_` interfaces, and `VC:<id>:connState` cached observations.
No `getAttributes`, init, or credential-bearing management response is used.

Results retain duplicate or missing labels and stable profile IDs. OpenVPN remote
host/port/proto and WireGuard peer endpoint fields are projected separately from
VPN type. Multiple endpoints remain multiple configured candidates; none is
selected as active. Endpoint hostname is not resolver DNS. Missing directives
remain unknown; OpenVPN connection blocks are flagged incomplete. Other VPN
protocols are explicitly outside this inventory. Interface presence and cached
connected values do not prove health, administrative stopped intent or routing.

Current implementation reads bounded local files into memory and returns only
allowlisted fields. It never reads `.userpass`/`.password`, executes configuration,
returns inline TLS/private keys, or logs raw files. Symlinks and nonregular files
are rejected. Limits: 128 profiles, 1024 directory entries, 32 endpoints/profile,
32 KB settings and 256 KB profile/config files. Malformed endpoint metadata is
reported unavailable without raw errors.

The presentation separates `enabled` (unknown administrative intent), `connected` (cached value with unknown freshness), and `health` (passive assessment with timestamp/reason). Absent interface plus cached false is disconnected; other observations remain unknown, never automatically healthy. No handshake or provider probe is performed. Bounded read projections have been checked on Gold Plus and Gold SE; see [support](features.md).
