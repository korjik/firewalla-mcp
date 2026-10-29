# Experimental persistent management adapters

These are executable adapters, distinct from the temporary Linux tools and the non-executable `stage_*` proposals. They call fixed `cmd policy:create`, `cmd policy:delete`, or `set policy` requests on `http://127.0.0.1:8834/v1/encipher/simple` **inside the appliance over verified SSH**. No local API port is exposed or forwarded. No HTTP proxy/redirect is followed. No service is started and no endpoint is enabled. Requests use existing Firewalla management logic and its asynchronous enforcement/background persistence machinery.

The reviewed contract is official source commit `4b4d9fecbd9fd56613ffba91a7c88b26f1b67396`. The adapter requires that exact installed `/home/pi/firewalla` HEAD and a clean tracked source tree, then sends the harmless `cmd ping` operation to check existing API availability. Other revisions fail closed. This strict experimental guard may reject released appliances; do not change or upgrade a router merely to satisfy it. Add another compatible revision only after source/contract review and tests. A clean checkout and ping do not prove the running process loaded that source; the operator must verify runtime/source alignment before enabling writes. No live compatibility claim is made for Gold Plus or Gold SE management APIs.

Add to an existing box entry, alongside the existing SSH settings:

```json
{
  "management_revision": "4b4d9fecbd9fd56613ffba91a7c88b26f1b67396",
  "managed_devices": ["02:00:00:00:00:01"],
  "managed_vpn_profiles": ["vpn-a", "vpn-b"]
}
```

This alone does not enable writes. The top-level `writes_enabled`, protected approval directory and audit file from [writes.md](writes.md) are still required. Each preview binds the exact arguments, device, revision-dependent snapshot, expiry and rollback context to the operator approval digest. HTTP read-only mode excludes all three managed previews and `apply_change`. Run only one writer process.

## Implemented contracts

- **Device features:** Ad Block is a scalar tri-state; Safe Search, Unbound and DoH use `{state: ...}`. True enables, false inherits, null explicitly disables at device scope. Only an existing explicit value with exactly the recognized fields can be changed. Missing/extended schemas fail closed so rollback never invents an absent prior state. Other policy fields are untouched. Inheritance/global precedence is not resolved by this adapter.
- **New device block rules:** Internet uses `type=mac` and the exact MAC target. Category/app/IP/domain rules use a single-device scope, `action=block`, `direction=outbound`. Apps resolve dynamically to `TLX-fw-<id>` only when the cached catalog declares `features.acl=true`. Video uses `av`. At most 128 active policy IDs are inspected. A fixed, read-only Redis Lua projection returns selected policy fields plus an opaque full-record hash computed within Redis; arbitrary policy fields never leave Redis. Possible duplicate type/target pairs are rejected even when scopes differ. The created numeric ID is retained for approved rollback. No existing rule is edited or broadly deleted.
- **Existing-profile VPN switch:** Requires an explicit enabled `{state:true, profileId:M}` policy and exactly the expected M. Both M and N must be operator-allowlisted and have unambiguous OpenVPN/WireGuard profile-file existence. Profile configuration files are never opened. Bounded `.settings` files are inspected locally; explicit boolean `strictVPN`, `routeDNS`, `overrideDefaultRoute`, and `c2sSNATDisabled` must match. Full settings hashes participate in stale-state checks, but raw settings do not leave the appliance. Profile settings are never changed. Only `profileId` changes; rollback restores the exact original selected policy. No profile API, credentials or private keys are read.

Preview makes no mutation. `apply_change` consumes an independently created approval, rechecks state and calls management logic once. Result `persistent_state_verified=true` means selected stored policy/rule readback matches, **not** that firewall/DNS/routing enforcement completed. Results always label enforcement and effective device VPN path unverified. Asynchronous Firewalla events may later fail. Independent traffic/DNS/kill-switch checks are necessary before claiming the requested behavior works.

Rollback needs a new preview and approval and refuses changed snapshots. Kernel and managed operations share the ten-minute plan window. Unknown/timeout outcomes are never retried automatically. A process restart loses plan state. There is no transaction against other Firewalla app/API writers: avoid concurrent changes. In particular, a duplicate rule introduced between snapshot and creation can produce an ambiguous management result; inspect before doing anything further.

## Exact remaining gaps and evidence needed

| Gap | Why it is not enabled | Minimum evidence/design needed |
|---|---|---|
| VPN profile import/addition | `saveVpnProfile` validates/saves credential-bearing content, writes settings, runs setup and returns `getAttributes(true)` including configuration; timeout may leave partial files. This project has no approved secret-ingress, upstream logging audit or exact partial-failure recovery contract | Review all supported profile validators and their logs; define mounted one-use secret input without MCP argument/log exposure, file ownership/permissions, duplicate prevention and partial-write recovery; approve a disposable profile test. Merely discarding the response is insufficient |
| VPN start/stop | `startVpnClient` runs setup, can stop on failed start, and can exceed the helper deadline; stop returns statistics. Runtime/interface state alone cannot establish the initial management state for safe rollback | Selected non-secret lifecycle state contract, bounded asynchronous completion and failure recovery, and independent device kill-switch/route tests |
| Group/global/network controls and schedules | Different precedence and target semantics; scoped false/null differ from global state, and scheduling/time-limit side effects need separate contracts | Target-specific fixtures, inherited/effective observations and rollback tests; Users time quotas must not be modeled as device quotas |
| Existing arbitrary rule edits/deletes | Unknown fields, schedules and identity preservation make exact reconstruction unsafe | Complete supported typed schemas and management update/idempotency/conflict contracts; no raw-policy passthrough |
| Custom DNS CRUD, provider configuration, NTP/RADIUS changes | Current read adapters do not establish full mutation scopes, defaults, restart effects or exact rollback; RADIUS also carries enrollment/secrets | Dedicated typed contracts and sandbox tests per operation, plus exact approval for any service/security change |
| Persistent routes/port forwards | Broader FireRouter configuration versions and restart effects are not equivalent to kernel state | Configuration transaction/version contract and rollback with service impact accounted for |

## Live validation approval boundary

No new adapter, profile settings extraction or live management write has run on the appliances. The earlier credential-bearing `vpnProfiles` query was denied and is not used by this implementation.

Before live VPN validation, request approval for **the exact two owner-selected profile IDs** on one selected appliance: check only their config-file existence (never open configs), read each bounded `.settings` file locally, retain only the four safety booleans and opaque hashes, and read the selected device's `vpnClient` field. Do not retrieve profile API responses, raw settings, provider credentials, keys or other profiles. This is a proposed separate approval scope, not permission already obtained.

A later mutation test needs its own explicit approval for one device M-to-N policy change, expected current M, matching safety settings, an independent effective route/DNS/kill-switch test plan, and a separately approved rollback to M. For rules, use one owner-selected disposable device and destination; approve creating that exact block and deleting only its resulting ID. No router changes are necessary for contract/mock tests.

## Primary source contracts

Reviewed, independently implemented (no upstream source copied): [encipher route](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/api/routes/encipher.js), [netbot set/cmd handlers](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/controllers/netbot.js), [Monitorable policy storage/events](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/net2/Monitorable.js), [Policy equality](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/alarm/Policy.js), [VPNClient settings/defaults](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/vpnclient/VPNClient.js), [DNSCrypt scoped tri-state](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/sensor/DNSCryptPlugin.js).
