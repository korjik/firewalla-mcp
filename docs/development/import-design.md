# Inactive OpenVPN import transaction design

This document describes transaction internals for contributors. For installation and supported MCP operations, use [VPN operations](../vpn-mcp-writes.md). The MCP workflow imports registered router-local OpenVPN inputs into fresh, unassigned profiles. It requires a confirmed maintenance window and does not prove authoritative stopped state or prevent concurrent Firewalla actions.

## Inputs and secret boundaries

The dispatcher accepts registered archive IDs, not arbitrary upload paths. Bounded ZIP/manifest validation rejects traversal, links, duplicate/unknown members, oversized data and unsafe OpenVPN directives. Source and destination IDs contain only alphanumeric/underscore characters and have at most **10 characters**. New IDs are generated with random nonces and checked for collisions/references.

Credentials are copied entirely within the router profile filesystem. They are never returned, logged, sent in management API payloads or process arguments. The source, optional-password presence/absence, settings, provider bytes and permission choices are bound to the preview. Changes invalidate execution. Only selected public metadata and transaction digests leave the router.

The transaction core defaults new credentials to `0600`; the MCP interface explicitly exposes `0600`/`0644` and currently defaults to `0644`. Preview must disclose that `0644` permits other local users with directory access to read credentials. Source permissions are never changed.

The optional `existing_0644` source exception applies only to the exact existing `.userpass`: expected account owner, regular single-link file, non-symlink path and trusted non-writable parent chain. It does not apply to arbitrary source secrets, journal files or unsafe destinations. The path and opened inode checks repeat at read time. This preserves existing readability rather than fixing it and does not defend against root or another process using the same account.

Provider TLS-auth/compression directives require explicit registry policy opt-in and are disclosed in the preview. Original bytes are preserved; nothing silently starts a connection or rewrites a provider profile to work around validation.

## State and concurrency

Strict state mode requires authoritative stopped intent from a valid observer. FireMain's `_started` is process-local: cached `connected=false`, an absent interface or an inactive unit is not equivalent. The uninstalled `firemain_import_observer.cjs` prototype can observe an already-loaded instance without constructing it; it is not a production state bridge.

The supported fresh-ID maintenance mode instead requires complete exact-ID reference enumeration, collision checks, no interface, inactive/dead/disabled unit and cache not true. It checks system VPN/multi-client, device, group/tag, network and policy references. Unknown or incomplete evidence fails closed. It repeats checks around publication and returns `imported_unassigned_passive_checks`, not authoritative stopped state.

Discovery may instantiate a profile without starting it, and an explicitly concurrent start can race passive observations before a unit/interface appears. Random fresh IDs and an owner-agreed no-concurrent-VPN/profile/policy-edit window reduce risk but do not provide atomic exclusion. Do not modify FireMain, stop services or claim a global lock as part of this importer.

## Publication, replay and recovery

Preview reads router-local credentials and writes a private transaction journal; it is not pure read-only. MCP apply follows exact host confirmation and a durable server execution claim. The controlled router dispatcher then creates its internal exact transaction marker. This journal mechanism is not an independent operator-file authorization mode or a user-managed issuer.

Ancillary files are staged first; `.ovpn` is published last. Journals record ownership/fingerprints, and destination collisions or source/registry/policy drift block execution. Transaction-owned cleanup is bounded to verified entries: it rejects replaced inodes, symlinks, extra links, unsafe modes and unexpected sizes. Failure-injection tests cover a process exiting during credential staging before journal persistence.

An uncertain transport outcome must be inspected, never blindly repeated. Recovery/rollback is conditional on owned files and unchanged inactive/unreferenced state. There is no public MCP delete/rollback tool for imports, and automatic cleanup must not remove a profile started or assigned by another actor.

Private journals may contain inline TLS material and remain for recovery/audit. A hard process death during journal replacement can leave a private temporary journal. Automatic garbage collection and secure erasure are not guaranteed; cleanup needs explicit inspection and must not erase evidence needed for recovery.

Use the disposable `scripts/vpn_import_sandbox.py` and related tests for transaction development. Real provider files, credentials and live mutation are never required in public fixtures. Source compatibility is documented in [firmware contracts](firmware-contracts.md).
