# New-ID maintenance import: scope and residual race

A narrowly scoped one-off import of previously nonexistent, unreferenced IDs does
not inherently require a global FireMain lock. Local implementation now supports
an explicit maintenance mode; it is not a production firmware adapter and makes
no atomic concurrency guarantee.

## Source facts

Reviewed public source revision: `173ac36dccb5239a5195a5b4e64d20cb1b618a91`.
OpenVPN discovery enumerates `.ovpn` filenames. `getVPNProfilesForInit` constructs
instances and reads attributes but does not start them. HostManager policy-driven
starts require a matching exact profile ID and `state: true`. Explicit
`startVpnClient` can independently start an ID. Snapshots and filename publication
alone therefore do not exclude concurrent management actions. Do not use the
credential-bearing profile-list API to obtain state evidence.

## Local implementation

`fresh_profile_id()` generates a 10-character hex candidate. All profile IDs
follow upstream's alphanumeric/underscore format, length 1–10. Fresh candidates
still require collision and complete exact-ID reference checks.

`InactiveImport(..., maintenance_window={"nonce": <32 hex characters>,
"expires": <Unix seconds>})` accepts a window up to 10 minutes. A window object
is not owner permission by itself. The public plan includes its nonce/deadline,
the owner's required no-concurrent-VPN/profile/policy-edit condition, and explicit
`atomic_guarantee: false`. The existing separate approval must bind that complete
plan before apply. Live use requires actual owner agreement to that window.

Only this mode accepts `administrative_intent: "not_instantiated"` alongside
`inactive: true` and `unreferenced: true`; strict mode still requires stopped.
An instance created by enumeration may instead be observed stopped. Unknown,
started, referenced or incomplete evidence must fail closed. There is no constant
or synthetic probe suitable for production.

Target files must be absent. Ancillary files are written first and `.ovpn` markers
published last via no-overwrite links. Guards run before writes and immediately
after publication. Changed evidence interrupts the transaction without automatic
cleanup. Rollback needs its own approval and unchanged inactive/unreferenced state.
Expired windows or policy drift fail closed; recovery after an expired window
requires separate reviewed recovery, not silently extending an existing approval.

The optional source `.password` absence is recorded in the private journal.
Appearance of any object at that path between preview and apply is rejected,
including a dangling symlink. Existing source credential permissions are untouched.

## Required live evidence and approval

Before any credential read/import, identify exact fresh IDs and obtain complete,
bounded exact-ID reference checks across global VPN/multiClient policy, device,
group/tag, network, routing rules and virtual WAN groups, plus filename/runtime
collisions and authoritative instance/start intent. Unknown schemas or incomplete
inventories must block. A credential-free installed-firmware adapter for these
checks is still outstanding; this module does not fabricate those observations.

Then obtain owner approval for the exact source, target IDs, supplied profile
hashes/endpoints, inline TLS-auth/compression options, source-permission exception,
and short no-concurrent-edit window. Preserve original provider bytes and leave
profiles disconnected/unassigned. The actual uploaded archive remains inaccessible
in this executor, so its real-byte validation is still pending.

Even with owner cooperation and postchecks, another process can race between a
snapshot and publication. This is a disclosed maintenance risk, not a lock-backed
transaction. No global FireMain modification, service stop, router installation,
credential read or live import has occurred as part of this implementation.

## Explicit observational fresh-ID mode

`observational_new_ids=True` is a separate, approval-bound maintenance contract.
It never labels passive observations as FireMain stopped intent. Its reviewed
collector completes reference enumeration and checks exact-ID file/cache
collisions before the transaction, absent interface, inactive/dead/disabled unit,
and cache not true on subsequent checks. A false cache may appear simply from
profile discovery (`status()`/`_checkConnectivity`); it does not prove stopped.

The mode still requires a fresh nonce ID and short no-concurrent-edit window.
A concurrent start can set in-memory intent before a unit/interface appears;
therefore this is a disclosed residual race, not atomic exclusion. The result is
`imported_unassigned_passive_checks`, never an authoritative-state assertion.
Strict mode retains its original stronger requirement. A changed mode/window
invalidates approval. A one-shot SSH gate can scope execution to one reviewed
helper digest, exact command, bounded stdin archive and expiry, then be restored.
It is not deployed as a persistent MCP write feature.

An authorized three-profile operation exercised this path. Original source files
and routes compared unchanged; new credentials were copied only on-box with0600
mode and profiles remained unreferenced with inactive units/no interfaces. An
aggregate policy fingerprint differed, so complete policy immutability was not
established. Future verification should record private per-field fingerprints
before execution to attribute changes; never undo unknown external updates.
