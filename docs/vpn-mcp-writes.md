# VPN-only MCP writes

Private pilot deployment was verified on 2026-10-30: 43 tool schemas, router reads, authentication and unapproved-write rejection passed through the existing gateway. The reference deployment now uses approval-bound targets and host-confirmed execution; installation alone authorizes no mutation. No VPN mutation was used as a deployment test.

The optional VPN catalog retains the same MCP endpoint and gateway identity. It
contains 36 read tools plus seven VPN methods. It does not expose general route,
firewall, device-control or service writes. Default stdio and HTTP remain read-only.
The combined candidate catalog is a separate security review, not a prerequisite.

| Tool | Inputs | Effect and limits | Evidence |
| --- | --- | --- | --- |
| `preview_vpn_import` | box_name, source_profile, archive_id, maintenance_until (UTC epoch seconds), destination_mode 0600/0644 (default 0644) | Reads a registered router-local archive and local source credentials; writes a private preview journal. Up to three fresh random IDs, ten-minute maximum maintenance window. No VPN start/assignment | Local MCP transaction and synthetic filesystem tests |
| `apply_vpn_import` | plan_id | Requires exact single-use host approval. Creates ancillary files first and publishes `.ovpn` last; preserves original source. No automatic retry after uncertainty | Local complete import, stale-state and replay tests |
| `verify_vpn_import` | box_name, transaction | Checks owned file fingerprints/modes and current reference/passive observations. Never reverses another actor's changes | Local checks, mutation detection |
| `preview_vpn_lifecycle` | box_name, profile, vpn_type openvpn/wireguard, desired connect/disconnect | Existing-profile start/stop plan. Can affect all devices using the profile. No exact rollback | Exact source contract and read-only guard verified; no live mutation test |
| `preview_managed_vpn_switch` | box_name, device MAC, expected_profile, destination_profile | Switch explicit enabled device VPN selection; safety/DNS flags must match. Does not rename or start profiles | Existing revision-pinned contract tests; effective device path unverified |
| `apply_vpn_change` | plan_id | Applies only the two previous VPN operation types after single-use approval | Local capability and approval tests; no live invocation |
| `preview_vpn_change_rollback` | plan_id | New approval to restore an unchanged, verified device policy switch. Start/stop inverse is a separate operation | Existing conditional rollback tests |

All tools use pi's existing privileges. No arbitrary file paths, configuration
contents, passwords or shell commands are tool arguments. Profiles may contain
inline shared TLS material; never put archives in the repository or tool output.
A preview does read credentials into router-local memory to validate and bind the
source, but only public profile metadata and an approval digest leave the router.
Credential values and credential fingerprints are absent from public plans.

## Current confirmation and gates

Use `--vpn-write-catalog`, `vpn_writes_enabled=true`, `writes_enabled=false`,
`vpn_confirmation_mode=host_confirmed`, `vpn_target_policy=approval_bound`, and
protected ledger/audit mounts. The authenticated host obtains exact confirmation,
then calls MCP apply directly. No external issuer or per-target list editing is
required. Registered import sources/archives, firmware and SSH operation boundaries
remain enforced. See [installation](install.md) and [trust model](host-confirmed-vpn.md).

## Router import installation contract

Build an immutable stdlib-only helper with:

```sh
python scripts/build_vpn_import_helper.py /private/staging/vpn-import.pyz
```

The builder prints its SHA256 and performs no deployment. A reviewed forced-command
gate must recognize **only** the literal `firewalla-vpn-import-v1`, verify the
installed helper hash on each call, and execute it with isolated Python and a
bounded timeout. Request JSON travels over stdin, never in command arguments.
Retain the read helper and its existing operation restrictions. Do not add an
unrestricted Python command, arbitrary module selector or writable helper directory.

The router dispatcher uses fixed account-relative paths:

- `~/.ssh/firewalla-mcp-vpn-import-policy.json`: mode0600 in mode0700 `.ssh`.
- `~/.firewalla/run/ovpn_profile/.mcp-import-inputs/`: owner-only directory.
- `<archive_id>.zip` and `<archive_id>.json`: owner-only registered inputs.
- `.mcp-import/`: mode0700 transaction journals and recovery artifacts.

The operator policy has exactly `revision`, `sources` (profile ID to boolean
allowing the reviewed legacy0644 userpass exception), `archives`,
`destination_modes`, and `provider_features`. It requires an exact reviewed git revision/tree and 11 matching contract-file hashes.
Only a valid string-dictionary edit to `locales/en.json` is tolerated for the
reviewed VPN revisions; every other tracked edit fails closed. See the
[firmware review](vpn-firmware-contract.md).
The manifest has `sha256` for the ZIP and `profiles`, each containing only
`filename`, `display_name`, `endpoint`, and profile `sha256`. Labels/endpoints and
all directives are validated again on the router. ZIP traversal, links, unknown
members, duplicate names and oversized data are rejected. Matching AppleDouble
metadata may be ignored but is never extracted. The router generates new IDs;
the client cannot choose an existing destination or overwrite a profile.

Changing the registered archive, manifest, policy, source files or destination
mode between preview and apply blocks the transaction. Provider TLS-auth and
compression require explicit policy opt-in and appear in the approval preview.
0644 makes saved credential files readable by other local users when directory
traversal permits. 0600 remains available; source permissions are never modified.
Journals have count/byte bounds and need operator-reviewed retention/cleanup.

## State guarantees and remaining compatibility work

The new-ID import path requires an owner-agreed no-concurrent-VPN/profile/policy-edit
window. It enumerates reviewed reference stores, checks filename collisions,
interfaces, units and cached connectivity, then repeats checks during publication.
It does **not** observe FireMain's process-local administrative `_started` flag,
and cannot atomically prevent a concurrent start. Results say
`imported_unassigned_passive_checks`, never claim authoritative stopped intent.
There is no automatic cleanup when another actor changes state. Import rollback
remains a separate reviewed local recovery operation, not an MCP delete method.

Lifecycle/switch adapters support the two exact VPN revisions documented in the
[firmware review](vpn-firmware-contract.md). Other managed-write types retain the
older pin and strict clean-tree requirement. Existing management routes must be
reachable; none is enabled. Missing safety fields use the reviewed `loadSettings`
defaults; explicit null, string or numeric values are rejected. Settings bytes are
never rewritten, and fingerprints still bind the full stored settings file.
An absent connection cache with no interface/inactive unit is unknown, not proof
of administrative stop. Disconnect always needs an approved stop request. Link
cache/unit observations do not prove peer reachability or a device's effective
route. Native start can restart OpenVPN on first launch; native stop disables its
unit and updates routing/DNS runtime state. These effects are disclosed in preview.
There is no claim that a runtime start updates persistent system VPN policy.

Deployment must separately approve the helper hash and narrow SSH operations,
protected registry and approval mounts, and replacing the same backend image.
Refresh the existing MCP gateway tool catalog and verify all seven schemas and
rejected unapproved calls, then refresh tools in the existing ChatGPT app. No new
OAuth provider client, audience, callback or integration is required. The private pilot received the separately approved narrow SSH gate expansion; no live VPN mutation was performed during deployment verification.
