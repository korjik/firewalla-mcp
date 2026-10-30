# Approvals across Firewalla MCP operations

The preview → explicit confirmation → apply workflow covers supported general writes as well as VPN operations. Capture uses the same host-confirmed trust model but has its own start/cancel lifecycle. This guide describes the current source catalog; your deployment may expose a smaller subset. Check `write_capabilities`, the advertised schemas and the [support matrix](features.md).

## Common workflow

1. Resolve the intended box and stable target IDs. Names must be unambiguous; do not infer device ownership from a name.
2. Call the relevant preview. Show the exact operation, targets, settings, expected prior state, expiry, impact and verification limits. For multiple actions, show the entire ordered sequence and dependencies.
3. Obtain explicit user confirmation through the authenticated MCP host for that unchanged plan.
4. Invoke the corresponding apply/start tool with its plan ID. The server performs SSH internally; the assistant does not need an SSH connector or approval-file step in host-confirmed mode.
5. Report verified, partial, stale or uncertain outcomes. Inspect an uncertain result before proposing anything further. Do not repeat an action merely because the transport timed out.

Target/settings changes require a new preview and confirmation. The server binds plans to configuration and prior state, checks expiry and consumes execution claims once. A repeated apply may return a recorded result, but must not dispatch the mutation again. Pending plans disappear on restart; the persistent consumption ledger must remain intact. These guards do not make concurrent external changes atomic or prove effective traffic enforcement.

## Which tools use which approval?

| Operation | Preview | Execution and approval semantics |
|---|---|---|
| Temporary kernel route, filter or DNAT addition | `preview_route_change`, `preview_firewall_rule`, `preview_port_forward` | `apply_change` after exact confirmation; only configured tables/chains; temporary Linux state, not persistent Firewalla configuration |
| Device feature override or new block rule | `preview_managed_device_control`, `preview_managed_block_rule` | `apply_change` after confirmation of exact device, feature/target and before/after state |
| Scheduled app/category block or DNS answer | `preview_scheduled_block_rule`, `preview_dns_override` | `apply_change`; schedule, target, answer and device are part of the plan |
| Group/network feature override | `preview_scoped_service_control` | `apply_change`; explicit scope and tri-state setting; only features allowed by the verified firmware contract |
| Existing VPN start/stop or device VPN switch | `preview_vpn_lifecycle`, `preview_managed_vpn_switch` | `apply_vpn_change` in the VPN catalog; the combined catalog also exposes `apply_change`. Confirm exact profile/device and preserved safety/DNS behavior |
| New inactive OpenVPN profiles | `preview_vpn_import` | `apply_vpn_import` after confirmation of returned IDs, registered source/archive, permissions and maintenance deadline; special preview side effects below |
| One persistent VPN mapping | `preview_persistent_vpn_forward` | `apply_change` after confirmation; mapping scope and maintenance deadline are bound |
| 2–4 same-target persistent mappings | `preview_forward_plan` | `apply_change`; one approval binds all listed mappings, not arbitrary later additions |
| VPN start → device switch → 1–2 forwards | `preview_network_plan` | `apply_network_plan`; one approval for the ordered plan, with expected transitions and stop-on-failure behavior |
| Bounded packet metadata capture | `preview_capture` | `start_capture` after scope confirmation; a separate capture plan, not a general writer plan |
| Conditional rollback | `preview_rollback`, `preview_vpn_change_rollback` | A new rollback plan needs fresh confirmation and the corresponding apply tool; not implicit permission from the original action |

Current-source Ad Block, Safe Search, Unbound, block-rule and DNS-answer contracts are reviewed for the pinned revisions. DoH/NTP writes remain blocked on those revisions. The existence of a general preview function does not make every advertised feature executable. Permanent route management, arbitrary existing-rule CRUD, RADIUS enrollment and unrelated maintenance are unsupported. No general arbitrary-command or arbitrary-file writer exists.

## Important exceptions

### Import preview is not a pure read

`preview_vpn_import` reads credentials locally on the router and creates a private transaction journal. It is correctly annotated as non-read-only. It does not publish the new profiles, start a VPN or assign devices, but the host should explain and obtain authorization for this preparatory secret access/journal creation before invoking it. The server does not require a separate pre-preview approval artifact. Final profile creation still requires confirmation of the returned exact plan.

Only registered router-local inputs are accepted; credentials/config contents are not returned. `destination_mode` currently defaults to `0644`, which permits other local users to read the new files; select `0600` when owner-only access is intended. The existing-source permission option is separate and does not authorize a source-file chmod. TLS-auth/compression allowances and the maintenance window must be explicit. Passive checks cannot atomically prevent another actor starting a fresh profile. See [VPN import details](vpn-mcp-writes.md).

### Capture cancellation reduces scope

`cancel_capture` requests termination of an existing job and does not require another preview or approval artifact. Poll `capture_status` for actual completion; the remote timeout remains a cleanup backstop. Repeated `start_capture` for an existing job returns its status rather than starting another capture. `capture_status` is read-only.

Capture is host-confirmed regardless of the general writer's legacy operator-file mode. Its plan expires after two minutes; it is limited to 15 seconds/100 packets and one explicit IP or MAC on an explicit interface. Starting an external probe is a separate action outside this server. See [capture limits](traffic-capture.md).

### Verification and proposals do not apply changes

`verify_vpn_import`, status tools, `write_capabilities` and inspection tools do not require apply confirmation. `stage_*` tools produce non-executable proposals, not approved plans or completed mutations. Ordinary previews may read router state; import preview is the exception above.

### Rollback is conditional, not a general undo

Single-action rollback requires a verified applied change, an unexpired rollback window and the expected complete after-state. It returns a new plan. VPN lifecycle start/stop and mapping batches have no exact rollback through `preview_rollback`; inspect and preview a separate compensating operation. Mixed plans have no exposed inverse/resume, and the import MCP surface has no rollback tool. Never remove or overwrite state changed by another actor.

One existing tool description, `preview_rollback`, still says “new operator approval.” That is legacy wording: the implementation uses the configured general confirmation mode, including host-confirmed mode. It does not require an external issuer in host-confirmed mode. This documentation audit did not change the runtime schema.

## Multiple actions and partial outcomes

A compound preview binds its ordered steps, target IDs, settings, expected initial state, dependencies and expiry. Execution accounts for its own expected earlier changes while rejecting unrelated drift. A VPN start acknowledgment without the required connected observations stops the workflow before device switching.

This is not an atomic transaction. On failure, report completed and unverified steps, inspect state and obtain a fresh remaining plan. There is no automatic mixed-plan resume or compensation. Actions in another plugin—such as application configuration or an external reachability probe—can be coordinated in the host's user-facing plan but are not executed by Firewalla MCP.

## Configuration and trust

- **VPN catalog:** enable `vpn_writes_enabled`, select `--vpn-write-catalog`, set `vpn_confirmation_mode: "host_confirmed"` and `vpn_target_policy: "approval_bound"`.
- **General catalog:** select `--allow-write-catalog`, enable `writes_enabled` and set `write_confirmation_mode: "host_confirmed"`. Enable/configure VPN writes separately for import and related capabilities in that catalog.
- **Capture:** enable `capture_enabled` with the required persistent ledger. Capture uses host-confirmed scope approval.

Use [installation](install.md) and [write setup](writes.md) for mounts and restricted SSH helpers. Enabling broader catalogs is a deliberate permission expansion, not part of refreshing client metadata. The configuration field named `vpn_target_policy` concerns VPN target selection; it is not the name of the entire approval system. General host-confirmed writers use their own mode and retain operation-specific restrictions such as allowed kernel tables/chains and registered import inputs.

**The authenticated host enforces the human confirmation.** An authenticated client that ignores the workflow can call apply without asking; the server does not attest the human reply. MCP annotations are hints, not mandatory UI enforcement. Exact plan/state/replay checks still run server-side. Use only trusted clients, private authenticated access and reviewed router command gates. The [VPN trust-model detail](host-confirmed-vpn.md) explains that boundary further.

Legacy `operator` mode remains in code for deployments deliberately using separately issued, owner-protected approval files. It is not the normal host-confirmed setup. The superseded external-issuer deployment narrative has been removed from the current guide; repository history retains it. No new issuer, credential or external SSH approval step is needed for host-confirmed operation.
