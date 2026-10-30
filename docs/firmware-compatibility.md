# Firmware compatibility

Read tools detect available utilities and data shapes. Managed writes have a stricter contract: the configured revision must match reviewed source and relevant file hashes on the appliance. Do not change a configuration pin merely to suppress an unsupported-version error.

| Contract | Reviewed revision(s) | Scope |
|---|---|---|
| Original managed adapters | `4b4d9fecbd9fd56613ffba91a7c88b26f1b67396` | Original guarded adapters; feature-specific constraints still apply |
| Current VPN and policy contracts | `173ac36dccb5239a5195a5b4e64d20cb1b618a91`, `a92caef41689e5d4c929207c003b1a667f39ece2` | Existing-profile lifecycle, device switching, registered import, VPN forwarding; separately pinned Ad Block/Safe Search/Unbound and rule/DNS dependencies |

The two current revisions share tree `85d99a2bc15d97cc4523d00d4a2f67263a0b22a1`. The guard checks the commit/tree, tracked modifications and working-file digests. Only a bounded regular `locales/en.json` string dictionary may differ for these contracts; other relevant drift, symlinks, malformed data and unknown revisions fail closed. DoH/NTP writes are not enabled by the current policy contract.

Bounded MCP/SSH reads and source checks have been exercised on Gold Plus (x86_64) and Gold SE (aarch64). This does not establish compatibility for every model, dependency or firmware build. Configured-state verification does not prove asynchronous enforcement, kill-switch behavior, external reachability or restart persistence. See [feature evidence](features.md).

A firmware update can intentionally stop managed writes until its contract is reviewed and tested. Keep the prior image and matching helper pins for software rollback, but do not downgrade router state or overwrite another administrator's changes automatically. Existing management endpoints must already be available; the server never enables disabled development routes.

Contributor details and source manifests: [firmware contracts](development/firmware-contracts.md). Deployment requirements: [installation](install.md) and [restricted router commands](writes.md#restricted-router-key).
