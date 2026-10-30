# Write modes, confirmation and failure handling

Use the [approval workflow across tools](approvals.md) for the reference installation. Default read-only mode remains safe to install without writer configuration. Do not enable source adapters merely because they appear in the generated catalog.

## One action

1. Call its typed preview. Display exact box, resolved device/profile, before/after settings, scope, expiry, risks and verification limits.
2. Obtain explicit user confirmation for that unchanged plan through the authenticated MCP host.
3. Call its advertised apply tool with the plan ID. SSH executes internally. Do not issue an external operator file in host-confirmed mode.
4. Report verified/partial/uncertain outcome and remaining observations. Stored readback is not proof of effective traffic enforcement.

Changing a target, setting or action requires a fresh preview and confirmation. Replayed or stale plans cannot re-dispatch. Pending plans live in memory and disappear on restart; durable consumption records prevent replay. Never erase those records to retry a change. The host is trusted to enforce human confirmation; tool annotations are hints, not cryptographic proof.

## Multiple actions

`preview_forward_plan` binds 2–4 same-target mappings. `preview_network_plan` binds start → explicit device switch → 1–2 mappings and dependencies. One confirmation authorizes that immutable sequence only. Expected changes from earlier steps are accounted for; unrelated drift stops execution. Asynchronous start acknowledgment without connected observations stops before switching the device.

Plans are not atomic transactions. On partial/uncertain failure, inspect actual state, preserve completed effects, and request a fresh remaining plan. Do not automatically undo changes another actor may own. Conditional single-action rollback is available only where the complete verified after-state is unchanged. Mixed-plan inverse/resume is not implemented. External application/probe tools are coordinated by the host, not executed by this server.

## Enablement and compatibility

VPN-only uses `--vpn-write-catalog`, `vpn_writes_enabled=true`, `writes_enabled=false`, `vpn_target_policy=approval_bound`, `vpn_confirmation_mode=host_confirmed` and private ledger/audit mounts. No redundant per-device/profile target list is required in that mode. Import archives/sources remain registered inputs, not arbitrary paths.

General writes additionally require `--allow-write-catalog`, `writes_enabled=true` and `write_confirmation_mode=host_confirmed`. This is a separate permission expansion, not deployed by the capture update. Kernel tables/chains remain explicitly scoped. Current-revision Ad Block/Safe Search/Unbound and rule/DNS adapters are source-pinned; DoH/NTP remain blocked pending their own implementation review. See [support matrix](features.md).

Temporary kernel routes/filter/DNAT are explicitly nonpersistent. Managed VPN forwarding uses native Firewalla management and source-reviewed startup restoration, but live persistence/enforcement has not been tested. No adapter enables a development endpoint or changes raw policy Redis data.

File-based approval is no longer supported. Existing configurations require explicit [migration](approvals.md#migrating-from-file-based-approval); there is no automatic trust-model switch.

## Restricted router key

An unrestricted `pi` key remains powerful. Use the reviewed `scripts/vpn_only_ssh_gate.py` or capture extension `scripts/capture_ssh_gate.py` as a forced command for the dedicated key. These are templates, not automatic installers. Compute SHA256 of the exact release `src/firewalla_mcp/remote.py`, capture helper where enabled, and the import zipapp produced by `scripts/build_vpn_import_helper.py`. Replace only the digest placeholders in the gate. Unknown pins fail closed.

Install reviewed gate/import artifacts in the account's mode0700 `.ssh` directory, owner `pi`, preserving existing files and keeping rollback copies; import helper mode0600. Attach a fixed forced-command path with `restrict` to only the dedicated public-key entry in `authorized_keys`. Preserve unrelated keys and verify the public-key fingerprint. Review source and operation allowlist before enabling it. Never allow arbitrary Python source or shell. Capture permits only the pinned helper under a fixed timeout and existing noninteractive sudo; verify `/usr/bin/tcpdump`. No sudo grants are supplied by this project.

Import requires additional protected registered inputs and policy described in [VPN import contract](vpn-mcp-writes.md). Merely enabling the catalog does not upload/register archives or authorize copying credentials. General forwarding/kernel/device-control permissions are excluded from the VPN/capture gate. The separate `scripts/managed_ssh_gate.py` template can permit reviewed device/app/DNS operations only after deployment review; it does not permit temporary kernel writes or unreviewed DoH/NTP.
