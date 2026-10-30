# Contributing

Start with the [support matrix](docs/features.md), [approval model](docs/approvals.md) and [security boundaries](SECURITY.md). Keep changes scoped and document unsupported firmware or incomplete observations explicitly.

Run the [validation checks](docs/development/validation.md) before submitting a pull request. Regenerate the tool reference when schemas or model-facing instructions change. Add meaningful tests for malformed input, redaction, deadlines, drift, replay and partial outcomes where relevant. A mock success does not establish live appliance compatibility.

Contributor references:

- [Firmware contracts](docs/development/firmware-contracts.md): source guards and compatibility reasoning.
- [Import transaction design](docs/development/import-design.md): router-local credentials, recovery and concurrency limits.
- [SSH feature roadmap](docs/development/ssh-parity-roadmap.md): useful remaining gaps without cloud dependencies.
- [Related projects and licensing](docs/development/related-projects.md): references and reuse constraints.

`scripts/live_probe.py` and `scripts/vpn_import_preflight.py` are bounded contributor diagnostics, not installation steps. `scripts/firemain_import_observer.cjs` is an uninstalled in-process observation prototype; never load side-effecting router modules just to obtain state. `scripts/one_shot_import_gate.py` is a narrowly scoped administrative template, not a general write grant. `scripts/vpn_import_sandbox.py` demonstrates synthetic transactions in a temporary directory; its internal journal markers do not implement independent human approval.

Never commit private keys, real VPN profiles, packet captures, actual device history or deployment-specific identities. No package or PR change authorizes live router mutations, capture, credential provisioning or deployment. Do not import vendor source without reviewing its license; see [related projects](docs/development/related-projects.md).
