# Forwarding display names and app-compatible metadata

`preview_forwarding_metadata` uses the normal forwarding coordinator, internal SSH helper, apply tool and durable recovery journal. It is available with the opt-in forwarding lifecycle catalog. It previews one or two HTTP/HTTPS mappings; it never changes a router during preview.

Select exact keys and fingerprints returned by `inspect_forwarding_lifecycle`. Each change explicitly supplies `display_name` and `remove_default_type`. A rename does not imply type removal. Combining both fields in one confirmed change requires only one remove/recreate for that mapping. Example changes, using keys and fingerprints from a fresh inspection:

```json
[
  {"key":"<HTTP mapping key>","fingerprint":"<current fingerprint>","display_name":"Home Assistant HTTP","remove_default_type":false},
  {"key":"<HTTPS mapping key>","fingerprint":"<current fingerprint>","display_name":"Home Assistant HTTPS","remove_default_type":true}
]
```

The native enabled-to-enabled add path ignores metadata changes. Therefore even a description-only rename briefly interrupts the selected port. Show the exact ordered plan and obtain explicit host confirmation before `apply_forwarding_lifecycle`. Failure may prolong interruption. Policies and all other fields are preserved; the operation does not set `autoFirewall` or invent timestamps. It does not probe reachability or prove app rendering.

## Ownership and restart recovery

Before dispatch, the private transaction journal persists the exact original and replacement objects, stable logical ownership key and box/configuration binding. The display name is never ownership evidence. Normal inspection, subsequent metadata previews, removal and rollback reload receipt history from validated journals and pass bounded exact variants to the pinned helper. The helper recognizes only complete recorded objects; changed or ambiguous native identities fail closed. Existing untagged mappings cannot be adopted merely by giving them a familiar name.

Receipt loading accepts at most 512 private journals and 64 receipt records, with at most eight unique variants and eight exact approved successors for one identity. A replacement retains its own ownership key; successor receipts only acknowledge the previously approved tuple replacement, including subsequent receipt-backed renames. Unrecorded replacements remain blocked. Changed configuration bindings, corrupt receipts, missing ownership history or concurrent journal use fail closed. Retain the journal directory across upgrades and container restarts; do not clear it to fix errors. Journal metadata becomes eligible after a dispatch was recorded, including uncertain execution that requires inspection. This does not prove that an uncertain native queue request completed.

`preview_forwarding_recovery` obtains a fresh, conditional restoration/continuation plan. It preserves the exact original type representation and description. Unknown queue outcomes, state drift and unverified enforcement prevent blind compensation. Restored maps retain their previous ownership history; ordinary metadata inspection continues to work afterward.

## Type compatibility

Future mapping payloads omit the explicit default `_type` field. Matching accepts either absence or exactly `port_forward`, rejects other explicit values, and preserves the original representation during rollback. An owner-observed single-variable experiment showed an omitted type becoming visible in app 1.70 on one appliance. This is evidence for the compatibility change, not proof of every app/platform combination or of timestamp/auto-firewall semantics.

## Deployment

Use the updated backend and pinned forwarding helper together. The existing lifecycle SSH command gains bounded receipt arguments; its native create/remove operations are unchanged. The remote diagnostics/write helper also changes because future mapping construction omits the type field. Update reviewed helper pins and refresh the existing gateway/client tool catalog. No new credentials or identity-provider registrations are required. Existing private recovery storage is reused. Installing the capability does not rename existing mappings or remove their type fields.

Historical identities remain reserved for safe recovery. Deleting a renamed mapping and reusing its tuple in a separate creation plan is currently unsupported; use a same-plan exact replacement or conditional restoration. A successor cannot reuse a predecessor's recorded display identity. These cases are rejected during preview before native writes, rather than discarding provenance. Only the first same-plan ownership replacement is supported: replacing that successor again is rejected because its historical ancestor is not being removed. The bounds also limit repeated renames; an explicit reviewed history-migration design would be needed to exceed them.
