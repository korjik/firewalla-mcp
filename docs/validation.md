# Validation and release evidence

## Current reference deployment

`capture-v1` was built and deployed on an amd64 NAS. It exposes47 tools:36 read/inspection, seven VPN methods and four capture methods. Gold Plus/x86_64 and Gold SE/aarch64 both passed actual MCP/internal OpenSSH health reads. Strict known-host checks remain enabled.

Verified: authenticated Streamable HTTP initialize/list/call; matching MCP gateway tool schemas/associations; unchanged existing gateway/OAuth identity; rejected missing/bad bearer and invalid Origin; rejected unknown apply/capture plans and capture limits. Actual-image network-none fake-capture timeout/cancellation checks verified child cleanup. No real capture, probe or VPN/network mutation was used for deployment acceptance.

The last deployed capture release had629 passing local tests. Subsequent local PR preparation is a separate candidate and must report its final count/build checks in PR evidence, not imply deployment. ARM container execution remains untested.

## Write evidence

- Temporary kernel route/filter/DNAT: mocked and isolated disposable-container tests, including /32/default/named-table state normalization and stale rollback.
- Persistent rules/device/app/DNS: realistic normalization, duplicate reactivation, tri-state and malformed-input contracts; five additional installed dependencies matched on both routers. Ad Block/Safe Search/Unbound and rule/DNS guards now include those pins. DoH/NTP remain blocked; no live mutation/enforcement validation.
- VPN lifecycle/switch: installed relevant source contracts and read-only guard checks, mocks for stop intent, state drift and replay; no real mutation during deployment validation.
- Inactive import: synthetic transaction/recovery tests and a separately authorized one-off three-profile operation. This does not establish all reusable MCP import cases or administrative stop intent.
- Persistent VPN forwarding/mixed plans: source-pinned native contract, mock asynchronous/partial/state-transition tests; not deployed, no live NAT enforcement or restart/reboot proof.

## Explicit gaps

No full app parity, real capture acceptance, general live-write enforcement, automatic compound rollback, global effective-policy evaluator, arbitrary permanent route manager or comprehensive long-term traffic history. A stored policy, cached link state or successful API acknowledgment does not prove device traffic behavior. Do not run live tests without exact scope authorization.

## Reproduce locally

Run pytest, generated catalog freshness, compileall, Docker build, stdio/HTTP smoke and isolated kernel checks listed in CI. Container smoke uses empty boxes and does not authenticate to appliances. Keep credentials out of tests and CI. Production read checks should return only bounded selected fields, never raw VPN/config/Redis dumps.

## Publication candidate checks

The policy/control compatibility candidate passed 656 tests, generated-catalog
freshness, compileall and diff checks. Its Docker image passed stdio, authenticated
HTTP and curl protocol checks with 36 default read-only tools and rejected
unauthenticated requests. Isolated kernel /24, /32, default and named-table
conflict/apply/rollback checks passed. A targeted scan found no known private
network identifiers or credential patterns; source fixtures remain synthetic.
This candidate has not been deployed. Real capture and new managed-policy/network
write enforcement remain untested on appliances.
