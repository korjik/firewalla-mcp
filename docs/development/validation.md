# Reproducible validation

Run from the repository root with Python 3.11+:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python scripts/generate_catalog.py --check
python3 -m compileall -q src scripts
```

Build and test an isolated container without router credentials:

```sh
docker build -t firewalla-mcp:test .
.venv/bin/python tests/container_smoke.py firewalla-mcp:test
.venv/bin/python tests/http_container_smoke.py firewalla-mcp:test
.venv/bin/python scripts/curl_smoke.py firewalla-mcp:test
```

CI also builds `Dockerfile.legacy` and runs disposable kernel tests using `tests/Dockerfile.kernel` in a network-isolated container with only `NET_ADMIN` added. Inspect the workflow before running privileged test containers; never run kernel tests on a router or share its network namespace. They test temporary rules/routes, not persistent Firewalla enforcement.

## Evidence levels

- Unit/contract tests use synthetic SSH, policies, files, flows and failure injection. They establish validation, redaction, state transitions and error handling—not current appliance behavior.
- Container protocol tests exercise initialize/list/call, default catalog isolation, bearer/Host/Origin rejection and timeout cleanup. They do not log into a router or certify an OAuth gateway.
- Bounded live reads establish specific SSH/parser behavior on the tested appliance revision; model/architecture evidence is maintained in [support](../features.md).
- A live write, capture or restart-persistence test needs its own exact scope, confirmation, recovery plan and evidence. Installation acceptance does not authorize one. No blanket live-write certification is claimed.

For changed tool descriptions/signatures, regenerate `docs/tool-reference.md`, inspect the diff and verify backend **and gateway** schemas after any separately authorized deployment. Validate Markdown links/anchors, JSON examples and CLI flags. Scan staged files for secrets, real network identifiers and stale support claims. Report the exact tested commit/image and distinguish local checks from CI and live deployment.
