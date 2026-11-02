# Controlled forwarding metadata experiment (not deployed)

This developer-only adapter is not an MCP method and is not included in the trusted router helper. It does not establish a cause for missing app entries.

The experiment binds one existing MCP-owned WAN TCP80-to-TCP80 mapping and changes only the presence of `_type: "port_forward"`. The native backend treats missing type as `port_forward`; its enabled-to-enabled add path ignores metadata changes, so testing the alternate representation requires exact removal followed by recreation. It must not set `autoFirewall`, timestamps, or change companion policies.

Before execution, obtain explicit approval for a brief TCP80 interruption and a no-concurrent-edit maintenance window. Re-read and bind all mapping/policy identities, device/IP/WAN and routing environment; prove a unique native match and no shared hairpin resource. Verify existing DNAT, ingress and hairpin evidence. A private journal and single-use host-authorized execution claim must precede dispatch. The standalone adapter is not an authorization boundary or a general API.

The two actions remove the exact original mapping and recreate its exact fields minus `_type`, preserving the description/ownership token. Check stored identity, unrelated state, DNAT and hairpin evidence after each operation. The app must then be inspected by the owner: source/synthetic tests cannot establish whether it renders the result.

Restoration uses a fresh journal recovery preview and confirmation: remove only the exact alternate form and recreate the exact original object. Expiry after a verified removal permits a new restore-only preview. Unknown queue outcomes, drift, unexpected metadata, missing enforcement or concurrent edits stop recovery; no blind retry or automatic restoration. This is not atomic and failure can leave TCP80 interrupted longer than expected. No conntrack flushing, restart, packet capture or connectivity probe is part of this experiment.

Validation includes pinned native `find`/`addPort`/`removePort` method execution with mocked enforcement, one-variable change and exact restoration, restart-safe journals, expiry, altered fields, shared resources, concurrent changes, replay, and unexpected recreation outcomes. Live app rendering and live experiment execution remain untested.

A separately reviewed temporary administrative helper/invocation is required for any live run. Do not replace the deployed general helper or broaden its forced-command gate merely to perform this diagnostic experiment.
