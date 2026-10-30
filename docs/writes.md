# Write modes, confirmation and failure handling

Use the [host-confirmed workflow](host-confirmed-vpn.md) for the reference installation. Default read-only mode remains safe to install without writer configuration. Do not enable source adapters merely because they appear in the generated catalog.

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

Legacy `operator` mode is retained for existing operators who intentionally choose separately issued approval files. Its historical guide is [here](approval-bound-vpn.md); it is not required by the host-confirmed installation.
