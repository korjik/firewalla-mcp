# Consolidated requested-feature checklist

The current server exposes **46 tools** in full mode and **34** in read-only HTTP mode. `apply_change` is the sole mutation boundary. Every write needs disabled-by-default enablement, explicit scope allowlists, preview, independent host approval, stale-state protection and audit. Managed adapters require the exact reviewed source revision; other firmware versions fail closed. No live managed mutation or effective-enforcement test has run.

| Requested category | Implemented | Partial, blocked or not verified |
|---|---|---|
| Generic multi-box SSH | Arbitrary named boxes, strict host keys, bounded typed commands, no MSP | Actual server OpenSSH-to-appliance end-to-end test awaits LAN host/key setup; existing connector helper tests are separate |
| Docker/MCP | Dockerfile/Compose, stdio and authenticated Streamable HTTP, read/write catalog separation | ARM container execution and actual NAS deployment unverified |
| Gold Plus/Gold SE variety | Architecture/preflight documentation and selected helper reads on both | No blanket all-model or live managed-write compatibility claim |
| SSH setup | Official-source app instructions, dedicated key generation, safe public-key append, permissions, fingerprint verification and revocation | No credentials generated or installed by this task |
| Health/network | System/services, interfaces/addresses/VLANs/routes/neighbors, traffic counters | Full platform-specific diagnostics and exact policy-routing evaluation incomplete |
| Devices/controls | Inventory, explicit policy reads; persistent device/group/network Ad Block/Safe Search/DoH/Unbound overrides | Existing explicit recognized values required; global mutations, complete inheritance/effective behavior and first-time absent-field restoration not supported |
| App/category/Internet control | Dynamic app ACL catalog, device block rules, recurring category/app schedules | Arbitrary existing rule edits, group/global block creation and User time quotas not implemented; app control affects network access, not app installation |
| Device flows/patterns | Bounded time-filtered/paginated regular/blocked flow projections and descriptive aggregates | Retention, domain/category gaps and mutable-pagination limitations remain; no intent/sensitive-behavior inference or complete anomaly detection |
| VPN device switching | Approved existing-profile M-to-N switch with expected-M and matching safety/DNS flags; prior policy rollback | Group switching and effective route/DNS/kill-switch validation incomplete; no provider port-assignment API |
| VPN connect/disconnect | Existing-profile lifecycle with consistent cached/interface observations; OpenVPN units must already be disabled | No exact rollback or boot-persistence guarantee; no live connectivity proof; inverse is a separate approved action |
| VPN profile import | Not enabled | Credential ingress, upstream logging review and partial-file/setup recovery are required; exact provisioning approval pending |
| Firewall/rules | Selected counters/policies, persistent new device block rules and scheduled app/category rules; exact created-ID rollback | General existing-rule CRUD, full kernel evaluation, IPv6/nft interpretation incomplete |
| Routes/port forwarding | Approved temporary IPv4 route/filter/DNAT operations; configured mapping reads and bounded diagnosis | Persistent FireRouter route/forward configuration requires transaction/restart/rollback contracts; UDP and exact effective NAT evaluation incomplete |
| Port-forward diagnosis | Separates service probe, selected VPN observation, provider claim, configured mapping and independent TCP vantage | A local timeout is never proof of global closure; no full application handshake identity claim |
| DoH/Unbound | Selected status plus device/group/network overrides | Provider selection, global config and DNS-over-VPN config changes remain unsupported |
| Custom DNS | New device-scoped domain-and-subdomain address rules with exact-ID deletion rollback | Arbitrary existing override listing/update/delete, global rules and exact-host-only matching not exposed; live DNS answer unverified |
| NTP Intercept | Network override on already-enabled service, selected prior-value restore | No feature/daemon activation, device/group scope, clock changes or fresh health guarantee |
| RADIUS | Feature flag only | Enrollment/users/shared secrets/config changes blocked pending secret-ingress and recovery design plus exact approval |
| Alarms/usage | Bounded selected alarm summaries/counts, interface counters and flow aggregates | Full descriptions, long-term per-device/app usage accounting and complete historical analytics incomplete |
| Connections/NAT | Selected bounded conntrack/socket metadata and counters | Full NAT translation reconstruction, payload capture and unrestricted packet capture absent |
| Context Forge/Okta | Secure backend HTTP and gateway/Okta integration documentation | Actual registration, credentials, TLS/network policy and deployment pending infrastructure access and exact approvals |
| Testing/publication | Automated contracts, injection/limits/redaction/approval tests, Docker protocol tests and isolated kernel tests; draft PR | No router security changes, live service/VPN mutations, deployment or merge performed |

Exact adapter semantics, source links and proposed approval scopes are in [managed-writes.md](managed-writes.md). Historical read-helper evidence and current test results are in [validation.md](validation.md). No unsupported feature returns fabricated success.
