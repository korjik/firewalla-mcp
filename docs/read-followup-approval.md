> Historical design/status record. This is not the current installation guide. Use [installation](install.md), [host-confirmed workflow](host-confirmed-vpn.md) and [current support](features.md). External SSH approval issuance described below is not used by the reference deployment.

# Read follow-up approval packet

Current running service: audit-v2, unchanged 34-tool read-only catalog.
Candidate source has 36 read tools (48 including separately disabled write tools).
No GitHub publication, router trust change, image replacement or live VPN probe
has been performed for this follow-up.

Candidate remote.py SHA256:
`609947b5415d94daa062c8cd2c4eece01281eaae0f8a0d34a28afc517ea881eb`

Current deployed remote.py SHA256:
`2fcc7740a354a45c08fdbda5fde6471f3041888520903a9c6bbf5e2e72864f61`

Exact proposed read-operation allowlist additions:
- `membership_snapshot`: bounded selected Redis names/membership relationships.
- `saved_vpn_profiles`: bounded selected saved profile labels/endpoints and
  independent interface/cache observations.

No existing operation gains a mutation, and no arbitrary shell tool is added.
The existing helper file and rollback artifacts remain untouched. Before any
trust update, verify the candidate digest again; changes invalidate this packet.

425 local tests pass, including parser secret-redaction, malformed endpoints,
symlink/size rejection, duplicate/missing labels, disconnected/orphan interfaces,
explicit People relationships, cycles, duplicate paths, empty entries and MCP
schemas. Bounded membership collector probes completed on both appliances. No
new MCP tool was deployed or tested through the live gateway.

The owner subsequently approved the on-box VPN projection and helper additions.
VPN validation passed on both appliances. The new `firewalla-mcp:inventory-v1`
image built and passed an isolated 36-tool catalog/digest check.

**Remaining denied operation:** replacing/restarting the running read-only NAS
container and updating its persistent Compose image reference. Automatic review
said the approval did not clearly cover that exact service deployment/restart.
The replacement did not execute. Router gates, briefly updated, were restored to
their exact prior versions so audit-v2 continues working; live plugin health
calls passed on both appliances. No gateway/catalog refresh occurred.

Request exact approval to replace/restart the existing reader with inventory-v1,
update its Compose image reference, reactivate the already reviewed helper hash
and two read operations, and refresh the same gateway catalog. Retain the old
image, Compose and router-gate rollback artifacts. No new integration, credential,
VPN change or write enablement is part of this operation.


## Deployment completed after exact approval

Following explicit approval of the service replacement/restart, inventory-v1 was
deployed privately with the reviewed helper digest above and exactly the two new
read operations. The prior image, Compose file and router gates were retained
for coordinated rollback. No router policies, profile settings or routes changed.

Backend MCP initialize/list/call verified 36 structured read tools, both inventories
on both appliances, invalid-input rejection, writes unavailable and unauthenticated
HTTP 401. Existing gateway/server associations were extended by exactly two tools,
with existing IDs and OAuth configuration preserved. Gateway refresh initially
omitted new output schemas; a second refresh updated those two records. The actual
ContextForge model-facing serializer now advertises all 36 output schemas, and
its invocation path returned structured results for both tools on both routers.
A new interactive OAuth-consent round trip was not performed; the integration was
not recreated. ChatGPT may require Refresh tools on the existing app snapshot.

Image: `firewalla-mcp:inventory-v1`
Image ID: `sha256:3821d94f9ca3b3af90e91b155c16c6ab96a4f1df7e1c1d0a5af9dac7cbb6df6d`
Source archive SHA256: `2891075643bca8478c44463623de655eae373072cae614afc32c494d22ff5ed5`
Local validation: 425 tests passed. No GitHub publication was attempted.
