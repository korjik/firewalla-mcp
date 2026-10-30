# Firewalla-only confirmation workflow

The reference deployment uses this mode. The interface is:

1. Firewalla MCP previews a supported VPN action and returns the exact box, stable
   targets, relevant settings, expected prior state, plan ID and expiry.
2. The MCP host shows that preview and obtains explicit user confirmation.
3. The host calls Firewalla MCP `apply_vpn_change` or `apply_vpn_import` with the
   same plan ID. Firewalla performs its SSH transport internally and verifies the result.

No external SSH plugin, operator approval file, consent boolean, signing token or
new credential is part of this mode. SSH remains the router transport inside MCP.
Import inputs still require a protected validated registry and an explicit
maintenance window; this does not permit arbitrary filesystem uploads.

## Trust model

Opt in with `vpn_confirmation_mode: "host_confirmed"` and
`vpn_target_policy: "approval_bound"`. Retain the private execution ledger and
audit mount. The default remains legacy `operator` mode for compatibility.

This intentionally trusts the authenticated MCP client/host to obtain human
confirmation before apply. The server does **not** independently prove a person
confirmed. An authenticated caller that violates that policy can call apply
without asking. Deploy only when that host trust is accepted. Authentication,
owner scope, private backend access and restricted router commands stay in place.
No universal cryptographic consent requirement is asserted.

Apply tools advertise `readOnlyHint=false` and `destructiveHint=true`, and their
instructions require exact confirmation. These annotations are hints, not
server-enforced UI controls. This runtime does not expose a verified setting that
forces every connected host to show a particular confirmation dialog. The installed
SDK supports elicitation, but an agent may answer form requests; end-to-end human
elicitation through the present gateway has not been verified. The selected mode
therefore relies on the host's explicit preview/confirm/apply behavior, not a
fictional native consent attestation. A trusted host may use a plain confirmation
reply, a platform approval UI, or its own equivalent interaction.

The server independently enforces: supported operation and firmware, configured
box, exact immutable plan/targets/settings, expected router state, short expiry,
configuration binding, serialized execution, durable single-use claims and no
automatic retry after uncertainty. Restart loses in-memory pending plans; obtain
fresh previews. Claims protect against replay but are not evidence of human consent.
Changed state requires a fresh preview and confirmation. An interface being up is
not proof of routing or kill-switch enforcement.

## Deployment scope

Build and replace the backend image, set the two mode fields, keep the private
consumption ledger and audit storage, and refresh the existing MCP gateway tool
catalog. No router helper hash or operation allowlist changes are needed: the
underlying supported SSH commands and state checks are unchanged. Do not recreate
OAuth provider/client/server identities or add credentials/sudo grants. The old issuer and
approval inbox may remain unused for rollback; removing them is a separate cleanup,
not a prerequisite. Do not deploy the abandoned external-helper guidance workflow.

This is a security trust change: **server-verifiable operator artifact → trusted
MCP host confirmation**. Deployment requires approval of that concrete tradeoff.
Local synthetic tests verify plan execution guards, not an actual human-confirmed
workflow in another chat. No real VPN action is needed to test deployment.
