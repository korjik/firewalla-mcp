> Historical design/status record. This is not the current installation guide. Use [installation](install.md), [host-confirmed workflow](host-confirmed-vpn.md) and [current support](features.md). External SSH approval issuance described below is not used by the reference deployment.

# Approve an action, not a standing target list

This is a local candidate, not the deployed policy. The opt-in
`vpn_target_policy: "approval_bound"` lets the supported VPN preview tools inspect
any valid existing device/profile in a configured box. A second per-device or
per-profile configuration edit is unnecessary. Default `allowlist` behavior stays
compatible with existing deployments. This mode applies only to the VPN manager;
it cannot enable general firewall, route, service or arbitrary shell/file writes.

The exact operation, canonical box, stable profile IDs/MAC, expected prior-state
fingerprint, relevant settings fingerprints, source/target selection, rollback
context, permission options and short expiry are bound to the plan digest.
Box connection/configuration changes invalidate the plan. Names must be resolved
unambiguously with read tools; the write tools require exact IDs and never infer
ownership or choose a duplicate name. Changed state rejects execution. A consumed
or uncertain action is never executed again. Firmware/command restrictions remain.
The router checks the action deadline again immediately before management writes.

## What confirmation means today

The existing trusted issuance channel is a protected **operator file on the NAS**.
There is no verified integration forwarding ChatGPT's consent dialog or a chat
"yes" as an authenticated, action-bound approval to this server. MCP annotations
are hints to clients, not proof of consent. The backend uses a dedicated gateway
bearer; that authenticates the caller but does not prove which action the owner
confirmed. A model-provided boolean, quoted user statement, digest or token must
not be treated as confirmation. There is no `approve` MCP tool.

An authorized operator can issue the exact approval artifact after reviewing the
preview and obtaining the owner's confirmation. An independently authorized host
operation can perform that issuance; the VPN change itself then runs through MCP.
This reuses the host-approval mechanism without a standing target edit. The server
verifies the trusted file issuer and exact plan, not the content of a conversation.

To make a native ChatGPT confirmation automatically authorize execution, a trusted
bridge is still required. It must retrieve the authoritative server-held preview,
show the operation/targets/state/impact, authenticate the owner, bind an explicit
confirmation to that immutable digest and expiry, enforce CSRF/replay protection,
and issue the approval through a channel unavailable to the MCP actor. An Okta
login alone is insufficient. No such bridge, new credential or Okta grant is
implemented or provisioned by this change. Do not claim that a generated approval
token solves this gap.

## Separate issuer and executor

Approval-bound mode requires:

- `approval_directory`: issuer-owned directory, not writable by the MCP process,
  mounted read-only. For the NAS pilot, root-owned mode0750, group10001 is suitable;
  approval files are root-owned mode0640, group10001. The trusted issuer UID is0.
- `approval_consumed_directory`: separate directory owned by the MCP UID10001,
  mode0700, mounted read-write. Durable exclusive-create markers prevent replay
  across simultaneous calls and restarts. The server never deletes issuer files.
- `trusted_approval_uid`: a UID different from the MCP process. Symlinks, unsafe
  permissions, hardlinked/nonregular approvals, wrong ownership, incorrect digest,
  altered expiry, extra fields and model-issued files are rejected.

The server checks this separation at startup before advertising approval-bound
writes. An approval document retains the existing exact format:
`plan_id`, `digest`, integer `expires_at`, and literal JSON `approved:true`.
These public values are **not secrets or bearer authorization**. Possessing the
JSON is insufficient; it must come from the separately trusted issuer's file.
The preview response is copied so caller-side mutation cannot alter server state.

The current pilot's old approval directory is owned by UID10001 and writable by
the MCP container. It must not be reused unchanged for this mode. Do not perform
recursive permission changes. Provision a new issuer directory and a separate
consumption directory, preserve the old directory for rollback, then update only
the relevant configuration and mounts under deployment approval.

## Import boundaries

Approval-bound imports may select any syntactically valid existing source profile
in the configured box and any registered archive ID. Registered input is an
artifact-integrity restriction, not a device/profile allowlist: the archive and
manifest must already be in the router's protected fixed registry, with verified
hashes and bounded safe paths. No arbitrary upload, filesystem path, credential or
OpenVPN content is accepted as an MCP argument. Missing/invalid input remains blocked.

The router import policy can opt in with `target_policy: "approval_bound"` and
`source_permission_modes: ["owner_only", "existing_0644"]`; `sources` and `archives`
may be empty in this mode. Destination-mode/provider-directive policies and the
exact firmware guard still apply. The host and router target policies must agree.
`source_permission` in the preview selects the intended source permission rule,
not a claim of user consent. The existing0644 exception still checks the selected
source's owner, path, file type and parent protections, and never changes it.

Preview reads and fingerprints credentials only within the router and writes a
private journal; no values or credential fingerprints leave it. Final approval
binds that journal, selected source, newly generated IDs, provider settings,
permissions, registry hashes and maintenance window. Source changes, newly present
optional credentials, references, collisions or state drift prevent copying.
New profiles remain unassigned; this does not authorize starting or switching them.

## Deployment change requiring review

Deploy the tested backend with the opt-in target policy and new read-only issuer /
read-write consumption mounts. Update the pinned remote helper for deadline
validation and the pinned import helper for approval-bound source selection;
retain the same two management operation kinds and fixed import command. Refresh
the same ContextForge catalog to expose the new source-permission parameter and
policy metadata. Keep existing OAuth/client/server identities unchanged.

No live VPN operation is needed as a deployment test. Test storage separation,
schema propagation, valid previews on explicitly selected examples, and rejection
of absent/forged approvals. Actual apply still requires an exact subsequent action
confirmation and trusted issuance. Native chat-confirmation automation remains a
separate reviewed bridge requirement, not a reason to self-approve a plan.

## Practical integration: one confirmation, authorized SSH issuance

The selected pilot route uses the existing authorized SSH tool and NAS sudo
access. No new broker endpoint, credential or Okta grant is needed. This is a
host action authorized through the existing operator/tool control plane, not an
MCP server approving its own request. The available SSH tool runs authorized
commands; we cannot assert it always presents a particular confirmation UI.
The assistant must obtain the owner's exact action confirmation before invoking
issuance and must honor any tool-review denial. Existing authorization may avoid
a redundant conversational question; a platform-required approval cannot be bypassed.

Workflow:

1. Use Firewalla MCP to resolve the target and preview the supported VPN action.
2. Show the actual action, box, device/profile IDs with readable names, expected
   current state, affected settings and expiry. Ask once for that exact change.
3. After confirmation, invoke the separately installed issuer through the
   authorized NAS SSH route, using precisely that preview's plan ID, digest and
   expiry. The owner does not run commands or edit an approval file.
4. Call the Firewalla MCP apply method with the same plan ID. The server checks
   approval, consumes it once, checks current router state and executes the change.
   Read back the result. Expired/changed plans require a new preview and confirmation.

The candidate `scripts/issue_vpn_approval.py` is installed as a root-owned,
non-writable-by-MCP standalone file at `/usr/local/libexec/firewalla-vpn-approve.py`.
Use the trusted system Python with isolated mode:

```sh
sudo -n /usr/bin/python3 -I /usr/local/libexec/firewalla-vpn-approve.py \
  --plan-id <preview-plan-id> --digest <preview-digest> \
  --expires-at <preview-expiry>
```

It accepts only the three bounded identity fields and writes to the fixed
`/volume1/opt/firewalla-mcp-runtime/operator-approvals` inbox. No path, shell,
credential, target override or `confirmed=true` parameter exists. It validates
root execution, root-owned mode0750 inbox with reader group10001, expiry within
ten minutes and exact hex identifiers. Atomic publication refuses overwrite;
partial staging is cleaned up. Install it outside owner-writable source trees.
The deployment must verify ancestor directory protections and bind-mount the
inbox read-only into the MCP container. Do not expose this issuer as an ungated
Firewalla MCP tool or invoke it from the MCP container. No sudoers expansion is
part of the pilot: it uses the already authorized host administrator route.

**Security limit:** the issuer trusts the authorized privileged host invocation.
It does not independently verify a human clicked a button, retrieve the preview
from server memory, or interpret chat history. The assistant/operator must bind
the reviewed preview to that exact command. The executor independently requires
the matching server-held plan. A caller already authorized to run arbitrary root
SSH commands can bypass file-based controls; this design does not pretend to
sandbox that administrator. If the SSH route cannot be trusted to enforce action
authorization, stop: use a human-authenticated approval page instead. Do not add
an unauthenticated approval API as a workaround.

Alternatives reviewed: the installed SDK supports form and URL elicitation, but
its form helper explicitly allows agent-generated responses. The protocol
requires negotiated client capability and does not mandate a particular UI.
End-to-end human-confirmation semantics through this ContextForge/ChatGPT route
have not been verified, so form acceptance is not used as an approval boundary.
See the [MCP elicitation specification](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation).
The inspected broker snapshot exposes fixed registration/diagnostic operations,
not a per-action approval UI or issuer. Extending that broker with an authenticated
approval page is a viable later alternative, but adds deployment work and is not
needed for the authorized-SSH workflow.

Additional deployment scope: install only the root-owned issuer file at the fixed
path, alongside the previously described approval-bound candidate and separated
mounts. Preserve current SSH credentials, sudo policy, router operation
restrictions and integration identities. Acceptance tests can reject unprivileged
issuance and exercise an isolated synthetic inbox; do not issue a real VPN approval
or change a live VPN merely to test deployment.

## Discoverable instructions in MCP results

Configure optional nonsecret `approval_issuer` metadata on the backend:

```json
{
  "approval_issuer": {
    "ssh_host": "mcp-host",
    "python": "/usr/bin/python3",
    "script": "/usr/local/libexec/firewalla-vpn-approve.py"
  }
}
```

This is guidance, not a new permission or credential. `write_capabilities` exposes
`approval_workflow`; VPN previews return `next_step` with the configured SSH host,
exact quoted command, plan ID/digest/expiry, and subsequent MCP apply arguments.
A missing-approval tool error includes the same actionable JSON. It remains an
error, and no mutation occurs. The assistant must first obtain exact action
confirmation, then invoke the existing authorized SSH tool; it must not fabricate
files or bypass a denial. If SSH is unavailable, report that precise dependency.
The Firewalla MCP can discover the step but cannot itself invoke the external SSH
app. Unconfigured metadata reports `issuer_not_configured`, with no guessed command.
Changing issuer configuration invalidates outstanding plans. Do not reuse an old
screenshot plan; obtain a fresh preview when it has expired or the server restarted.

Deploying this guidance update requires only the backend image/configuration and
refresh of the same ContextForge tool metadata. It changes no router helper pins,
issuer permissions, sudo policy or OAuth configuration. Human workflow acceptance
still requires a real user-confirmed action; synthetic tests do not establish that
another assistant will follow the advertised instructions correctly.
