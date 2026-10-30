> Historical design/status record. This is not the current installation guide. Use [installation](install.md), [host-confirmed workflow](host-confirmed-vpn.md) and [current support](features.md). External SSH approval issuance described below is not used by the reference deployment.

# Historical preparation record — superseded

The blockers and counts below describe earlier preparation, not current status. A bounded one-shot import was subsequently completed under an explicit maintenance window. Reusable MCP methods now have local transaction tests; see [current VPN write guide](vpn-mcp-writes.md) for the undeployed catalog, exact gates and remaining firmware compatibility limitations.

# Inactive VPN import: shortest remaining path

No real profiles have been imported. Existing source credentials, permissions,
VPN connections and device routing are unchanged. The deployed read-only inventory
is separate from this unpublished importer.

## What already works locally

The core supports exactly three bounded provider profiles, strict provider
validation, explicit inline TLS-auth/compression opt-in, fresh 10-character nonce
IDs, destination collision protection, source settings preservation, local-only
credential copying, durable transaction ownership, idempotence, separately
approved rollback, and a short owner-agreed no-concurrent-edit window. The exact
legacy source `.userpass` may remain 0644; destinations are 0600. The source file
is never chmodded or rewritten. Optional `.password` appearance between preview
and apply blocks the transaction. No synthetic state probe may be used live.

Latest focused check: **132 tests passed** across importer, compatibility,
references, maintenance, provider, archive, staging-recovery and observer tests.
The sandbox demonstrated three synthetic imports, idempotent apply and separately
approved rollback. These are fixture tests, not validation of the uploaded files
or a production import.

## Two concrete blockers

1. **Provider bytes unavailable in this executor.** The existing Library upload
   has not been materialized. Its download hostname is absent from the enforced
   executor allowlist. No unchanged retry or alternate download route was used.
   Smallest practical data action: the owner can place the original Archive.zip
   in a private NAS directory and provide its exact path, or restore supported
   Library materialization access. Do not paste inline TLS material into chat,
   put it in the repository, or disable TLS/network restrictions. NAS staging
   must use owner-only directory/file permissions and normal authorized access.
2. **Production state/reference adapter incomplete.** The importer currently
   requires observed stopped/not-instantiated intent and complete unreferenced
   state for the exact new IDs. The installed FireMain `_started` flag is
   process-local. The standalone observer cannot read another process's flag;
   Redis cached false, absent interface and inactive units are not substitutes.
   Reference parsers cover individual selected fields but do not yet constitute
   complete enumeration of every production reference family. No safe existing
   authenticated in-process observer has been established. Do not enable debug
   endpoints, inject into FireMain, restart it, or weaken the guard to unblock.

A fresh-ID maintenance-only path may avoid a global lock, but it needs a reviewed
production collector and an explicit conditional safety contract. An agreed window
alone does not supply missing state evidence or make a snapshot atomic. This
technical review must finish before asking the owner to approve live copying.

## Exact eventual plan, once blockers are resolved

1. Safely inspect the owner-provided archive; require exactly the three expected
   city profiles, validate real bytes, produce SHA256 hashes and public endpoints.
2. Confirm the exact existing source label/ID from selected metadata; stat its
   credential files without opening them during preparation. Preserve 0644.
3. Generate three fresh nonce IDs; verify absent files/runtime collisions and
   complete exact-ID reference checks across global/scoped VPN, DNS-VPN, routes
   and virtual-WAN membership. Block incomplete or unknown evidence.
4. Present names, IDs, hashes, endpoints, preserved settings, permission exception,
   rollback limits and a maximum ten-minute no-concurrent-VPN/policy-edit window.
   Obtain approval binding this exact plan before opening source credentials.
5. Copy credentials only within the appliance, create new settings/credentials
   first and publish `.ovpn` last without overwrite. Never clone runtime files,
   start state or device assignments. Never use credential-bearing save APIs.
6. Immediately repeat state/reference checks and validate projected saved-profile
   metadata. Do not start/connect profiles or change any device routing.
7. If state changes, stop without automatic deletion; recover only under a
   separately reviewed rollback approval. Report each actual created artifact.

Until both blockers are resolved, an automated live-import command is deliberately
not presented as ready to execute. Existing read-only service and OAuth stay intact.

## Production reference collector completed

`vpn_import_inventory.collect_references` now performs bounded read-only Redis
EVAL enumeration of all `policy:*` hashes (including orphaned/inactive policy
records), `virt_wan_group:*` membership and `ext.unbound.vpnClient`. Selected
fields are `vpnClient`, `wanUUID`, `owanUUID` and `wans`; raw values never leave
Redis. Matching is exact against profile IDs and `VC:<id>`. All virtual-WAN
members are inspected, even if their group is not currently referenced, so indirect
routes do not hide a target reference. Disabled references still count.

The scan has a fixed iteration limit, field/byte/depth bounds and schema checks.
Unknown key types, malformed JSON or incomplete scans yield unknown reference
status. Exactly three installed-source-verified metadata strings are excluded:
`policy:id` (ID counter), `policy:state` (enforcement state), and
`policy:enforce:spend` (timing metadata). Wrong types still block.

On the primary appliance, this read-only collector completed enumeration of 809
policy hashes, zero virtual-WAN groups and one DNS-VPN configuration. It detected
the existing source-profile reference and no references for two synthetic
candidate IDs. Candidates are not approved import IDs. No credential value or
raw policy object was returned. Fifteen new local tests cover completeness,
unknowns, every reference family, input validation and fixed read-command scope.
This is complete enumeration of the reviewed stores, not a guarantee about
unreviewed firmware extensions or future reference schemas.

## Precise remaining administrative-state contract gap

Installed source evidence:

- `VPNClient.js:95–101`: `getInstance` reads the current process's private instance
  map; it cannot inspect another process's map.
- `VPNClient.js:630–640`: lifecycle events update `_started` in memory.
- `VPNClient.js:1205–1206`: `isStarted()` returns that in-memory value.
- `VPNClient.js:1522–1541`: Redis stores **connectivity**, expiring after seven
  days; it does not persist administrative `_started` intent.
- `netbot.js:3463–3488`: explicit start constructs/starts the client directly;
  a stored policy snapshot alone is not an authoritative runtime observation.
- `netbot.js:1834–1874`: profile read routes call credential-bearing attributes
  and may construct clients; they are not a safe state-only inspection contract.

The existing pure JS observation helper can project an already-loaded instance
without constructing one, but there is no established authenticated in-process
host for invoking it. Running it in a new Node process would falsely observe a
new, empty map. Subscribing to lifecycle events cannot reconstruct prior state.
No denied API call was retried, and no debugger, new endpoint, module constructor,
service restart or production instrumentation was used.

**Smallest technical next decision:** obtain a supported read-only in-process
state contract from the installed firmware/vendor, or explicitly review a revised
fresh-ID maintenance import contract that does not claim authoritative runtime
state. The latter is a changed guarantee, not a hidden implementation shortcut;
it must be reviewed before any live import approval. Installing an observer or
restarting FireMain would be a separate production change and is not proposed as
an automatic workaround. Until this decision, the adapter returns
`safe_to_import: false` and `administrative_intent: unknown`.
