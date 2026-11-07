# Complete WAN forwarding lifecycle

This opt-in workflow combines persistent IPv4 TCP NAT mappings and scoped inbound
allow policies under one host-confirmed plan. It is not enabled by the normal
read-only or VPN-only catalog. Local contract, mocked lifecycle/recovery and
isolated packet tests are available. Deployment and read-only inspection/preview
have been exercised; native lifecycle mutations have not been live-write-tested.

## Scope shown before confirmation

Inspection identities and reset eligibility are different contracts. The general
`preview_forwarding_lifecycle` removal schema accepts only `mapping:mcp:...` and
`policy:mcp:...` keys. Digest-based app mapping keys (`mapping:<64 hex digits>`)
belong to `preview_forwarding_reset`, when app management is enabled. Do not
rewrite an inventory key or fabricate an MCP label to pass the other schema.

Both inspection tools return `app_reset` guidance on mappings. Its `supported`
flag describes structural eligibility for a fresh preview, not authorization or
proof of effective connectivity. Existing identity/fingerprint checks and live
enforcement checks still apply. `autoFirewall` metadata does not select policies;
policy removal always requires an explicit selection.

The ordinary reset path supports the selected explicit WAN UUID. An omitted
`wanUUID` uses native default WAN scope and must not be silently replaced by the
selected WAN. Inspection reports it as unsupported for ordinary reset. The guarded
migration path requires one exact mapping, one replacement preserving the device,
IP, protocol and external port with a different internal port, no policy removals,
and `all_mappings=false`. It verifies enforcement and separately discloses WAN
narrowing and the new IPv4 inbound allow for explicit confirmation. Recovery
restores the original default-WAN scope with fresh confirmation.

Each action names a device, destination IPv4 address, current WAN UUID, TCP external
and internal ports, and an explicit IPv4 source CIDR. A source of `0.0.0.0/0` means
all IPv4 sources; there is no implicit source default. Up to four actions and eight
exact removal selections are accepted, with at most sixteen ordered native steps.

The native allow uses device/source/port/WAN scope. It **does not require DNAT** or
one exact original public destination IP. Matching routed IPv4 traffic or traffic
through another mapping can qualify. The device allowance follows its native
address set; the NAT destination is pinned to the selected address. UDP, other
ports and IPv6 sources are excluded by this workflow. A positive IPv4 source set
and an empty IPv6 counterpart are verified alongside the native rule shape.
Existing policy precedence can still block traffic. Neither configuration nor
kernel evidence proves service availability or external reachability.

## Workflow

1. `inspect_forwarding_lifecycle` reads bounded object identities and fingerprints.
   These are private metadata, not deletion authority or ownership proof.
2. `preview_forwarding_lifecycle` preserves equivalent configured objects, creates
   new allows disabled, creates NAT, then enables the allows. Exact removals are
   separately listed and checked for dependencies. A label alone never authorizes
   deletion. Exact native selectors and shared hairpin resources are checked.
   Policy applicability is reported separately and does not confer deletion ownership.
3. Show the entire preview, exposure, ordered steps and maintenance deadline to the
   user. Obtain explicit confirmation, with no concurrent app/API policy or mapping
   edits during the window.
4. `apply_forwarding_lifecycle` executes that immutable, single-use plan using SSH
   internally. It checks state and deadline before each step and stops on uncertainty.
5. After interruption or restart, `preview_forwarding_recovery` inspects the durable
   journal and current state. Set `rollback` to `true` to reverse verified changes,
   or `false` to continue remaining steps. Either result is a **new plan requiring
   fresh confirmation**. Never clear the journal or execution ledger to retry.

Creation/deletion is not atomic. Recovery checks configured state, native rule evidence and removal remnants.
A lost response followed by unchanged stored state is **not** sufficient to retry:
the native queue might still execute later. That case blocks recovery until the
queue/outcome is independently resolved; it never becomes an automatic retry. Policy IDs and creation timestamps are retained so replacement
objects are not mistaken for the originals. Restoring a deleted policy allocates
and binds a new native ID. Partial failure never triggers blind compensation.

## Example action

Use current IDs and fingerprints from inspection, never copied example identities:

```json
{
  "protocol": "tcp",
  "external_port": 443,
  "destination_port": 443,
  "source_network": "203.0.113.0/24"
}
```

An exact removal selection contains `key` and `fingerprint`. Leave `removals` empty
to preserve existing objects and add only missing configuration. A matching
unowned or disabled policy is a conflict, not permission to reactivate it.

## Installation and permission boundary

Use the general catalog (`--allow-write-catalog`), existing explicit
`write_confirmation_mode: "host_confirmed"`, persistent audit and consumption
storage, and:

```json
{
  "forwarding_lifecycle_enabled": true,
  "forwarding_recovery_directory": "/state/forwarding"
}
```

Provision `/state/forwarding` as a persistent, process-owned `0700` directory.
Journals are `0600`, contain private target metadata, and are not approvals. Back
up the journal and execution ledger together. An interrupted final journal record
fails closed; do not truncate it to force recovery.

The workflow requires a separately reviewed router helper built with:

```sh
python scripts/build_forward_helper.py /tmp/firewalla-mcp-forward.pyz
```

Review the artifact and its printed digest before installation. The candidate
network gate adds only the fixed command `firewalla-forward-lifecycle-v1`, executing
that pinned helper from the existing private SSH directory. It does not allow
arbitrary shell commands, helper paths or general device/DNS writes. Router gate
installation and the new capability flag are security changes requiring explicit
operator approval. Preserve existing key entries, fingerprints, credentials and
gateway identities. No additional user-facing SSH plugin or approval issuer exists.

The helper combines the reviewed policy, forwarding and `control/Block.js` source
guards. Unsupported revisions, unknown object fields, indirect rule-group
references, ambiguous matches and incomplete dependency evidence fail closed.
A trusted authenticated MCP host enforces human confirmation; the server does not
independently attest a human reply.

## Validation

The isolated family test runs only in a disposable container with no host/LAN
network. It verifies actual IPv4 packet acceptance and IPv6 packet rejection by
the source-set constraint. It does not test Firewalla's complete packet path.
The mock native tests cover create, exact legacy mapping selection, preservation,
delete, restart, partial execution, native ID replacement and conditional recovery.
No successful mock or isolated test is a claim of live appliance enforcement.

## Existing policy metadata

Creation compares the reviewed native identity selectors before considering
unknown ancillary fields. A provably different policy does not block a new allow
merely because it contains additional metadata. Matching incomplete identities,
legacy identity aliases and malformed scopes still fail closed. This distinction
does not relax exact deletion: ambiguous native selectors and unresolved/shared
structural NAT or hairpin resources block adoption and removal. Global block and
DNS policies are preserved, not mistaken for objects owned by a NAT mapping.
Selected companion-policy deletion still requires strict identity/reference checks. Preserving existing NAT and adding missing allows
is a different plan from deleting and recreating existing configuration.

The native removal selector ignores descriptions and can match more than one
stored mapping. The lifecycle requires exactly one match, rejects wildcard
selectors and blocks shared destination/protocol/internal-port hairpin resources
even across WANs. It checks native-shaped kernel hairpin evidence before removal
and verifies its absence afterward. A later exact, verified replacement may own
the same kernel tuple while the old stored identity must remain absent.
These guards do not make native operations atomic against concurrent app edits.

## Display names and app metadata

Use `preview_forwarding_metadata` for exact HTTP/HTTPS display-name changes and separately opted-in removal of the default type field. Names are independent of journal-backed ownership, including after restart. Native metadata changes require a brief remove/recreate interruption and exact confirmation; policies remain unchanged. See [metadata workflow and recovery](development/forwarding-display-names.md).

### Long operations and expired maintenance windows

The preview expiry is a hard dispatch deadline, not only a deadline for starting
an operation. The server checks it before each mutation and the router helper
also checks the confirmed maintenance window. A long reset can therefore stop
partway through. It must not silently extend the window after confirmation.

Each step checks complete stored state and relevant kernel evidence. Repeated
verification, SSH round trips and native asynchronous policy processing can make
large resets slow. Each native or legacy policy-verification layer reads each kernel filter table
once per pass; a mixed pass can read it twice. Evidence is never reused across
passes or mutations. This reduces duplicate reads but does not guarantee a
completion time.

A client or gateway timeout is not evidence that execution stopped. Do not
resubmit apply. Use durable recovery inspection; a busy transaction must be left
to finish or reach its deadline. After it releases the lock, inspect the verified
partial state and obtain fresh confirmation for a continuation or conditional
rollback. Do not clear recovery records or extend a running plan's expiry. A
recovery preview is not permission to execute it.
