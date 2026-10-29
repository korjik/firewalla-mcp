# Device controls, apps and flow investigation

## Control semantics

`device_controls` accepts a selected box and either an exact MAC (`target_kind=device`) or a numeric group ID (`target_kind=group`). It reads only selected feature fields from that target and the global policy. It does not resolve group/network inheritance or claim effective packet behavior.

For scoped Ad Block, Safe Search and Unbound in the reviewed source:

| Stored value | Meaning |
| --- | --- |
| Missing field | No explicit observed setting |
| `true` (or `{state:true}`) | Explicit enable |
| `false` (or `{state:false}`) | Unset/inherit |
| `null` (or `{state:null}`) | Explicit disable |

Global feature settings use different semantics; the result labels them separately. DoH raw state is exposed without an unverified semantic interpretation. VPN policy is a separate read. Never interpret removing a device override as bypassing a global block. This source-based mapping is covered by tests and observed reads, not a promise for every firmware version.

Internet/Gaming/Social/Video/Porn controls are ordinary Firewalla Rules, not host boolean fields. `control_rule_page` returns a bounded page of explicit device/group and global-candidate rules with declared action, disabled state, timers and schedule expression. Effective precedence, exceptions, group/network inheritance, enforcement completion and schedule timezone remain unresolved. Video's local category ID is `av`; Gaming is `games`, Social `social`, Porn `porn`, VPN `vpn`. These identifiers differ from some MSP naming conventions.

`stage_device_control` creates a **non-executable proposal** with current observations. It does not create an `apply_change` plan. Executable previews for selected device controls are now available separately; see [managed writes](managed-writes.md). Their stored-state verification does not establish effective behavior. For category/app/Internet controls, `enable` means enable blocking; it does not install, launch, uninstall or disable software on a device OS.

Sources: official [Monitorable](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/Monitorable.js), [SafeSearchPlugin](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/SafeSearchPlugin.js), [UnboundPlugin](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/UnboundPlugin.js), [AdblockPlugin](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/AdblockPlugin.js), [PolicyManager2](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/PolicyManager2.js).

## Dynamic app discovery

`app_catalog` projects IDs and feature flags from the existing locally cached `app_time_usage_cloud_config.appConfs`. It performs no cloud request. An ordinary app rule target `TLX-fw-<id>` is reported only when that app's `features.acl` is exactly true. `features.timeUsage` is a different capability: usage-tracked does not imply blockable. The supported usage set is named `app_time_usage_apps`, not `app_time_usage:apps`.

Model, firmware, beta features and cached catalog freshness can vary. This project does not hardcode a screenshot's app labels as supported. App block schedules are ordinary Rules using action `block`; they are distinct from compatibility-specific quota actions such as `app_block`. User Time Limits are not represented as device quotas. App block/unblock, schedules and usage-limit mutations are not currently executable here.

Sources: [HostManager.appConfsForInit](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/HostManager.js), [AppTimeUsageSensor](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/AppTimeUsageSensor.js), [official application blocking guide](https://help.firewalla.com/hc/en-us/articles/360050863873-How-do-I-block-an-application). No full `init` response is read; it can contain sensitive authentication material.

## Per-device flow listing

`list_device_flows` requires an exact MAC and explicit UTC epoch `start`/`end`, at most seven days apart. Query `connections`, `blocked`, or `all`; choose inbound/outbound/all direction and include/exclude category ID lists. The adapter uses bounded Redis score queries and applies filters in its own projection, so no filter is silently lost inside an internal API message wrapper.

Each page reads at most `limit` (1–25) candidates per selected source: two connection-direction indexes and, optionally, the blocked-audit index. A page can contain up to 75 records. `next_offset` advances the same offset in each source. Identical timestamps do not cause a timestamp-cursor skip within a stable index, but indexes are mutable: insertion, expiry or aggregation between calls can cause duplicates/gaps. Do not claim lossless pagination or a consistent historical snapshot.

Results include observed timestamp, direction, IP, port, protocol, available domains, available category and known upload/download bytes. Blocked bytes can be unknown (`null`), not zero. Country is currently unknown (`null`); no geolocation is invented. DNS/app-host attribution may be missing, shared, stale or unrelated to a deliberate browser action. Numeric category codes are decoded using the target's local enum, never guessed from another firmware version. Unknown categories cannot satisfy an include filter; the page reports their count. Raw `fd=in` means locally initiated/outbound and `fd=out` means externally initiated/inbound, which differs from intuitive names.

`index_counts_before_filters` counts retained indexed records in the score range, not unique sessions, packets, blocked attempts or filtered UI totals. Candidate selection uses index scores; event timestamps are filtered afterward, so score/event-time differences can omit records. The app's apparent 24-hour history is not a retention guarantee: raw flow/audit retention and per-key caps vary by platform/configuration, and busy devices may retain less. A seven-day request does not create seven days of data. Long-term bandwidth aggregates are not raw flow history.

`analyze_device_flows` summarizes **one page** into known bytes, top destinations, UTC hourly record counts and destinations repeated in at least three UTC hours. It does not silently fetch all pages or label traffic malicious. Without a baseline, anomaly status is `not_assessed_without_baseline`. Repeats can reflect background services and overlapping aggregates. Never infer sensitive interests or intentional browsing from categories or connections.

Sources: official [FlowTool](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/FlowTool.js), [AuditTool](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/AuditTool.js), [BroDetect](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/BroDetect.js). No packet payload capture or URL/query-string output is implemented.

## VPN M-to-N requests

`stage_vpn_switch` resolves a device by exact MAC and checks that its explicit VPN policy is enabled and matches expected profile M. A mismatch or inherited/absent selection returns `stale_or_unresolved`. A match produces a **non-executable proposal** to N, explicitly preserving strict VPN/kill-switch, DNS and all other settings.

Destination profile validation, secret-free settings fingerprints, persistent management invocation, effective device routing/return-path checks and safe rollback remain required. The tool does not claim these passed and issues no apply token. Profile import/addition, group switching and connect/disconnect remain unsupported. `preview_managed_vpn_switch` separately implements revision-pinned executable M-to-N plans for existing profiles with matching safety settings; it does not claim effective path validation. No tool accepts raw VPN configurations, keys or passwords. Existing interface state and profile references are observations, not proof that a device uses a VPN.

A live profile-list API check was rejected by automatic approval review because that response can include credentials/configuration; no workaround or retry was performed. Source review confirmed that concern. Separate approval for an exact secret-scoped verification is required before live profile access. SSH-only transport remains the requirement; no MSP backend is present.
