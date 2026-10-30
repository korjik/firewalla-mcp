# Firmware contract design for contributors

For supported revisions and operator behavior, see [firmware compatibility](../firmware-compatibility.md). This source comparison is evidence for specific adapters, not live enforcement certification.

## Reviewed paths and differences

Comparison base: `4b4d9fecbd9fd56613ffba91a7c88b26f1b67396` (the prior adapter
pin). No vendor implementation was copied into this project's code or fixtures.
The source-file digest manifest is in `remote.py:VPN_SOURCE_HASHES`.

- `api/app-local.js`: identical; existing production local encipher mounting.
- `api/routes/encipher.js`: non-streaming `/simple` request mapping and HTTP
  response-code handling match. The differing streaming-error path is unused.
- `controllers/netbot.js`: the full `setHandler` is identical. MAC target resolves
  to a Host, writes only supplied fields with `setPolicyAsync`, schedules Redis
  persistence and returns the full policy (which this adapter never reads).
  Lifecycle commands construct `VPNClient.getClass(type)` directly instead of
  the newer helper; setup/start/failed-start-stop and setup/statistics/stop order
  match the intended operations. No profile attributes API is called by our adapter.
- `net2/Host.js` / `net2/Monitorable.js`: device VPN policy key, policy storage,
  change-event publication and shared VPN-rule/DNS tag handling are compatible.
  The shared VPN-policy implementation is unchanged; the only Monitorable diff
  is in unrelated QoS timer validation. Device selection is distinct from global
  VPN lifecycle policy, and asynchronous enforcement is not inferred from readback.
- `net2/PolicyManager.js`: VPN policy priority/dispatch remains compatible. The
  installed version lacks the newer general control-character guard; our typed
  MAC/profile identifiers and exact two-field VPN policy cannot carry those values.
- `net2/HostManager.js`: global multi-client policy may independently start/stop
  profiles. We do not modify it. Runtime lifecycle calls do not establish persistent
  global startup intent, and concurrent external edits can still race a snapshot.
- `extension/vpnclient/VPNClient.js`: verified settings defaults, setup, start,
  stop, events, cache and route/DNS side effects. The older installed cache can
  combine link and connectivity observations; it is never labeled authoritative
  administrative state or health. `_started` remains process-local. Native stop
  clears intent in its process and signals FireMain; asynchronous state remains
  unverified by this adapter.
- `OpenVPNClient.js`: runtime-profile generation and native unit start/stop match;
  first launch can restart, and stop disables the unit. The visible diff concerns
  an unused session-log reader. Requiring an already-disabled unit prevents an
  unapproved change from enabled to disabled startup configuration.
- `WGVPNClient.js`: equivalent interface/config/handshake flow, but the installed
  implementation uses shell execution where the newer source uses argument arrays.
  Adapter inputs remain strict identifiers and existing strictly validated
  profiles. The adapter does not import or return WireGuard configuration.
- `util/i18n.js`: localization loads translation data for notifications. No VPN
  request dispatch, policy value, profile ID, command or path is derived from
  `locales/en.json` in these contracts. That file is checked as a bounded regular
  JSON string dictionary; permitted localization edits are neither reverted nor rewritten.

## Guard and adapter changes

The current revisions support the reviewed VPN operations and separately guarded forwarding/policy adapters.
The guard checks exact commit, tree, tracked modifications and the 11 working-file
digests on every call. Any other tracked edit, deletion/rename, digest mismatch,
source symlink, malformed locale or unknown revision fails closed. The original
pin/clean-tree gate for all unrelated management adapters is unchanged. The
router-local import dispatcher reuses this same source guard.

Absent safety settings use the verified defaults: strictVPN=false, routeDNS=true,
overrideDefaultRoute=true, c2sSNATDisabled=false. Explicit invalid/null settings
remain rejected. Source/destination effective flags must match for a device
switch; full stored-settings hashes bind approval and no settings file is edited.

A missing cache with absent interface and inactive disabled OpenVPN unit yields
`observed_connected:null` and `administrative_intent:unknown`. It never yields
already-stopped/no-change. A later approved connection must produce positive
post-observations; disconnect still requires the explicit management stop.
Conflicting cache/interface/unit state fails closed.

Tests use synthetic files, policies, settings and cache observations. They cover
both pins, changed tree/commit, every relevant dirty-file class, hidden digest
drift, locale validation, symlinks, VPN-only scope, defaults vs explicit null, and
unknown cache handling. Dependency/runtime integrity and effective traffic routing
are outside these source checks; no blanket all-model compatibility is claimed.

The candidate SSH gate is `scripts/vpn_only_ssh_gate.py`. Its two placeholders
must be replaced with reviewed immutable hashes before installation; unfilled
pins reject all requests. Existing read operations retain their allowlist. Only
`managed_vpn` and `managed_lifecycle` can use `managed_write`; general/kernel writes
remain rejected. Import uses the fixed literal command and a hash-verified open
file descriptor, preventing pathname replacement between verification and exec.
VPN rollback context must restore exactly the preview's expected enabled profile;
arbitrary policy fields cannot be smuggled through the rollback context.

## Policy/control dependency manifest

`POLICY_SOURCE_HASHES` additionally pins Policy.js, PolicyManager2.js and the SafeSearch, Unbound and Adblock plugins. The shared eleven-file guard also applies. This covers reviewed device/group/network features and new rule/DNS contracts; DoH/NTP remain blocked on these revisions. See [managed writes](../managed-writes.md). Keep synthetic contract fixtures independent of vendor implementation code and verify each newly supported operation separately.
