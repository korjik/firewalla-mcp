# DNS, NTP and RADIUS service coverage

`service_feature_status` projects selected read-only metadata; `stage_service_change` is a non-executable proposal. Source-supported Unbound overrides and new device DNS-answer rules use the separate [managed-write adapters](managed-writes.md). DoH/NTP writes remain blocked on the currently reviewed revisions. Provider/global configuration, arbitrary existing DNS-rule updates and RADIUS management are unsupported. See the authoritative [support matrix](features.md).

| Service | Implemented read | Unsupported / not inferred |
| --- | --- | --- |
| DNS over HTTPS | Dynamic feature override and selected provider IDs from `ext.dnscrypt.servers`; scoped raw DoH policy through `device_controls` | Provider stamps, URLs, custom-server credentials, provider CRUD, effective inheritance and executable scoped changes |
| Unbound | Selected `ext.unbound` fields: upstream transport, DNSSEC, killSwitch, and DNS-over-VPN state/profile reference; scoped/global tri-state observations | No VPN profile/config read; missing fields do not imply defaults. Effective DNS routing and provider changes unverified/unsupported; device override writes separately implemented |
| Custom DNS Rules | Explicit unsupported result | Service-level listing and arbitrary existing-rule CRUD unsupported; `preview_dns_override` separately creates a new device DNS-answer rule through native management, subject to firmware guards |
| NTP Intercept | Dynamic `ntp_redirect` override and cached `sys:ntp:status` | Cache can be stale; network scope/interception effectiveness unresolved. No system clock or NTP service changes |
| RADIUS | Dynamic `freeradius_server` flag only | Runtime/config management, users, enrollment, shared secrets, certificates/private keys and access expansion unsupported; no policy/config read |

Dynamic flags in `sys:features` are overrides, not full effective feature state. An absent override does not mean a service is disabled. A provider name does not prove its endpoint is currently healthy or in use. Service reads have mock coverage; this service-specific adapter has not been live-tested. The existing device/global feature observations are separately documented.

RADIUS source has status handlers that also load policy data; this project does not call them merely to obtain a status flag. DNS provider definitions may include sensitive stamps or account-specific URLs; only selected IDs are read. No credential value is accepted by the staging tool. RADIUS enrollment/access expansion would require its own exact approval and a secret-safe provisioning design.

NTP interception means directing applicable NTP requests to a service; it is not authorization to forge time, change clocks or modify device security. Unbound DNS-over-VPN settings must remain separate from a device's VPN data routing and strict-VPN behavior. No setting is changed implicitly as part of diagnosis.

Source review: [DNSCryptPlugin](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/DNSCryptPlugin.js), [dnscrypt configuration](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/dnscrypt/dnscrypt.js), [Unbound configuration](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/unbound/unbound.js), [NTPRedirectPlugin](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/NTPRedirectPlugin.js), [FreeRadiusSensor](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/FreeRadiusSensor.js).
