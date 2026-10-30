# Inactive OpenVPN clone/import core — experimental, sandbox only

`firewalla_mcp.vpn_import.InactiveImport` implements local file transactions for
creating up to three inactive OpenVPN profiles. It is **not exposed as an MCP
write tool**, has no production firmware/state adapter, and has not been run on a
router. The deployed read-only catalog is unchanged. Do not wire a constant-true
state probe into a live deployment.

The executable demonstration uses only temporary synthetic files:

```sh
python scripts/vpn_import_sandbox.py
pytest -q tests/test_vpn_import.py
```

The demonstration intentionally accepts no target directory, SSH host or real
credentials. Its synthetic approval writer is not a production approval interface.

## Credential-free firmware/discovery preflight

`vpn_import_state.py` adds read-only source-hash checks, bounded exact-label profile
resolution, filename-collision checks and credential-file permission/type metadata.
It opens only application source and `.settings` metadata; `.ovpn`, `.userpass`
and `.password` contents are not read. Its output projects IDs/display names and
booleans, never whole settings. Duplicate labels, malformed metadata, symlinks and
incomplete enumeration fail closed. Example (local paths on a reviewed appliance):

```sh
python scripts/vpn_import_preflight.py \
  --source-root /home/pi/firewalla \
  --profiles /home/pi/.firewalla/run/ovpn_profile \
  --source-label 'Provider Region A' \
  --target region_b --target region_c
```

This command is diagnostic only and exits 2 while import is blocked. It does not
install anything or return an approval. Do not execute it through a general shell
MCP tool or replace the deployed read-only SSH gate's approved hash automatically.

Five installed source files at revision
`173ac36dccb5239a5195a5b4e64d20cb1b618a91` were inspected: OpenVPNClient,
VPNClient, HostManager, netbot and VirtWanGroup. The preflight pins their hashes.
OpenVPN discovery enumerates `.ovpn` filenames. However, `_started` is held in
process memory and set by start/stop operations and inter-process events;
`VC:<id>:connState` is only a cached connection observation. Neither an absent
interface, disabled unit nor a false/missing cache value proves stopped intent.
Existing profile APIs call credential-bearing attribute methods and are not used.

Consequently the live state adapter remains blocked, even when all five source
hashes match. This is not a claim that all extensions/watchers were audited. A
separately reviewed credential-free FireMain observer, plus reference and concurrency
checks, is needed before it can authorize an import. Enabling an inspector, adding
a sensor/API handler, restarting Firewalla, or emitting lifecycle events is outside
this read-only preflight and requires a separate reviewed plan and approval.

App metadata handling is explicit in the preview: `displayName` becomes the new
label; existing `serverDDNS`/`serverVPNPort` fields become the verified destination
and 1194; `subtype` is preserved; `createdDate` is omitted so the clone does not claim
the source's creation date or guess timestamp units. Strict-VPN, DNS and routing
values remain unchanged. Unknown fields or malformed metadata are rejected. This
has been mock-tested; app rendering of imported metadata is not live-tested.

## Implemented behavior

| Operation | Inputs | Effect and safety checks |
|---|---|---|
| `validate_profile` | profile bytes (potentially secret-bearing), expected SHA256, expected endpoint | Bounded ASCII OpenVPN subset; UDP/1194, tun, explicit server certificate validation, inline parseable CA, auth-user-pass without a path. Rejects HTML, unknown directives, scripts/plugins, external paths, inline private-key blocks, duplicate directives and digest mismatch |
| `plan` | source ID; up to three target IDs/display names/profile bytes | Checks source file identity and target absence, preserves explicit strict-VPN/DNS/routing settings, writes a private preview journal. Public preview omits credentials, secret-file hashes and settings content; explicitly lists copied file types |
| `apply` | transaction ID plus independent owner-local approval file | Consumes matching unexpired approval; rechecks source, payload, inactivity and collisions; creates owner-only files using no-overwrite hard links; publishes `.ovpn` discovery markers last. No API/start/connect calls or policy changes |
| `rollback_plan` | transaction ID | Checks unchanged owned files, no unexpected target files, stopped intent and no references; issues a new approval digest |
| `rollback` | transaction ID plus separate rollback approval | Removes only journaled unchanged inode/content pairs, discovery markers first. Refuses active/referenced/modified targets; leaves source files untouched |

The core takes a mandatory `state_probe`. It must independently establish
administrative stopped intent, inactivity and absence of references for every
target before each publication/removal step. Missing interfaces or cached
`connected=false` are insufficient. No validated live implementation of this
probe is supplied yet, so these facts cannot currently be established by this
module on a real router.

Secrets are copied within the same local profile filesystem. Source `.userpass`
and optional `.password` files are never returned, logged, sent to a management
API or placed in process arguments. No existing private key is copied between
systems. Source secret files must be owner-only by default. A narrowly scoped
existing-file compatibility option is documented below; this code never changes
source permissions. Profile IDs are restricted to 11 characters.

## Existing readable source-file compatibility

An explicit `legacy_readable_userpass_source="source-id"` argument to
`InactiveImport` permits only that existing source's `.userpass` at exactly `0644`.
It does not cover another profile, `.password`, destinations, staging, journals or
approval files. The exception is included in the public preview/approval digest;
changing it between preview and apply is rejected. It is not enabled by default.

Before reading, the opened file must match the trusted path and be a regular,
single-link, non-symlink file owned by the executing account. The profile directory
must belong to that account with no group/world write. All ancestors must be real
directories owned by root or the same account, without group/world write; root-owned
sticky temporary-directory ancestors are allowed only with checked child ownership.
Unknown/remapped ownership fails closed. These checks are repeated at read time.
An optional preflight flag `--legacy-readable-userpass-source source-id` performs
only the corresponding stat checks; it does not read credentials or authorize import.

Source mode, owner and contents are left unchanged. New credential files are always
`0600`. Existing readability is a residual risk: other local users who can traverse
the source path may still read the original file. The exception does not repair or
expand that access, and does not defend against root or another process using the
same account. No actual source credential read/import has been tested under this
option. One authorized stat-only appliance check verified parent-path/ownership
eligibility without reading credentials; those checks must be repeated at execution.

## Observation-only FireMain helper

`scripts/firemain_import_observer.cjs` is an uninstalled, side-effect-free prototype.
An eventual reviewed in-process host would supply the already-loaded
`VPNClient.getInstance` function. The helper reads `isStarted()` only for an existing
instance, never instantiates a client or calls attributes/settings/start/stop. It
distinguishes absent, explicitly stopped, started and unknown observations; null or
false connection cache values are not substituted for administrative state.

Node contract tests ensure credentials/settings are not touched, errors are
redacted, target IDs are bounded, and every result remains observation-only with
`safe_to_import=false`. It has not been attached to FireMain. Secure attachment,
complete reference checks and exclusion of concurrent lifecycle/events remain
unimplemented and require a separate reviewed deployment plan. The current live
state gate continues to refuse import; this prototype is not a workaround for it.

The private `.mcp-import` directory is mode `0700`; journals/staging/approval files
are mode `0600`. The journal records private source/target hashes and inode identities
for stale-state and recovery checks. Do not export it: it contains sensitive
fingerprints and target settings. Staged hard links retain credentials until
approved rollback or a separately reviewed retention cleanup. Public results
contain only IDs, public profile hashes/endpoints and fixed status messages.

Publication of several files/profiles is not atomic. A write-ahead journal records
each intended link before publication, enabling recovery after interruption.
Partial apply is never retried automatically. Recovery requires a fresh rollback
preview and approval; external edits or new runtime files stop recovery. A
cooperating importer lock and atomic no-overwrite links prevent import collisions;
Firewalla itself does not honor this lock. Production use therefore also needs a
reviewed concurrency/maintenance procedure and current state evidence. Root or
another process running as the same account is outside this file-permission trust
boundary.

## Source contract and remaining blockers

The implementation is independently written Python; no upstream AGPL source was
copied. Source review used Firewalla's
[OpenVPNClient](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/vpnclient/OpenVPNClient.js)
and [VPNClient](https://github.com/firewalla/firewalla/blob/4b4d9fecbd9fd56613ffba91a7c88b26f1b67396/extension/vpnclient/VPNClient.js).
Those files describe `.ovpn`, `.settings`, `.userpass` and optional `.password`.
Runtime `.conf`, IP/gateway/subnet/push files, cached state and policies are not
cloned. Direct file import bypasses normal management events; discoverability,
startup/watchers and administrative intent must be validated for the installed
revision before any live adapter is enabled.

`getAttributes(false)` still returns credentials in the reviewed upstream source.
Profile-save APIs can return full attributes, while message handling can log or
forward request/response data. This implementation does not call those APIs.

The [official PrivateVPN UDP 1194 download page](https://help.privatevpn.com/en/articles/302433-openvpn-configuration-files-udp-1194)
lists Seattle, Phoenix and Las Vegas profiles. Ordinary fetch attempts did not
produce validated profile bytes in the build environment; earlier HTML responses
are not configurations. Obtain the three original `.ovpn` files through the
provider's ordinary download path or an owner upload. Actual directive compatibility
and endpoint/public-config hashes remain unverified; the conservative subset may
reject legitimate settings until individually reviewed. Never remove TLS checks
or enable unsafe directives merely to pass validation.

Before approving a live import, review all of:

1. Exact installed source hashes/revision and a live read-only state-probe adapter,
   including absence of persisted start intent, group/device references and startup
   watchers that could activate newly discovered profiles.
2. Exact source profile ID resolved by metadata, required credential filenames and
   ownership/permissions. No credential-bearing API dump.
3. Three valid provider configuration files (private handling for inline shared keys), endpoint/UDP 1194 and SHA256 values.
4. Absent target IDs (for example `pv-sea`, `pv-phx`, `pv-las`), display names,
   settings fields preserved and the exact file creation list.
5. Single-use plan approval, protected journal location, maintenance/concurrency
   window, post-import metadata/inactivity/reference checks and reviewed rollback.

No live import approval is implied by development or sandbox tests. Credential
import, start/connect and device-policy changes remain separate operations.
# Archive intake and provider compatibility

`vpn_archive.read_profile_archive` reads at most three bounded `.ovpn` members
in memory, without filesystem extraction. It rejects paths, links, duplicate
case-insensitive names, unsupported/encrypted members, excess expansion and
malformed archives. Returned bytes can contain inline shared key material and
must remain private; archive acceptance is not profile or import approval.

The default profile validator rejects `comp-lzo`, `key-direction` and inline
`tls-auth`. An explicit `provider_features=True` option on `InactiveImport`
accepts a strictly formatted inline 2048-bit OpenVPN static authentication key,
requires client key direction 1, and validates compression values. It does not
accept external key paths, executable hooks or other unreviewed directives.
The option, compression mode and shared-key presence appear in the approval-bound
preview; changing the option invalidates apply. Profile bytes are preserved,
including shared key material, in private journals and mode-0600 destination
files. Public results contain only the profile digest and sanitized metadata.
This is an inactive import option, not approval to connect or use compression.

OpenVPN documents `comp-lzo` as deprecated, with adaptive compression as its
default; even `comp-lzo no` permits a server-pushed change. Compression can leak
information through ciphertext lengths. See the
[official OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/).
Synthetic tests cover validation, approval-policy drift, byte preservation,
private destination permissions and rollback. Actual provider files have not
been materialized in this executor; their compatibility remains unverified.



## New-ID maintenance mode

See [the maintenance contract](vpn-import-concurrency.md) for the explicit
no-concurrent-edit window, absent-instance semantics, exact-ID checks and residual
race. This local mode does not supply the still-missing live reference/state
adapter or authorize live credentials/import.

## Credential staging failure recovery

For each target file, the importer first creates an empty mode-0600 inode and
persists its exact device/inode, expected length/hash and staging name in the
private journal. Only then does it write credential/profile bytes. Publication
requires successful byte verification. A process death during writing therefore
leaves a recorded partial copy, not an unjournaled credential file.

Caught staging failures remove only that known, single-link, owner-owned inode.
Separately approved rollback can clean recorded partial copies after its state
checks. Cleanup rejects replacement inodes, symlinks, extra hard links, unsafe
permissions and oversized files; it never sweeps transaction-prefix matches.
Synthetic tests include actual child-process exit during credential writing.

Private journals intentionally remain for recovery/audit and may contain inline
TLS-auth profile material. A hard process death while replacing a journal may
also leave a private temporary journal; automatic garbage collection of those
journal snapshots is not implemented. This differs from the fixed unrecorded
source-credential staging gap. Do not treat rollback as secure erasure or claim
that it removes every private journal copy.
