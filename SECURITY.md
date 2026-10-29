# Security model

Read-only means no persistent device changes are implemented. DNS and TCP probes generate bounded network traffic. SSH authentication itself can create normal system logs. Never grant a model unrestricted SSH shell access through this server.

- The public MCP catalog is explicit and typed. No tool accepts shell commands, Redis keys, paths, executable names, scripts, or arbitrary command flags.
- SSH hosts are literal IP addresses from administrator-owned configuration. Users select labels only. TCP probes are confined to configured CIDRs. DNS queries are validated labels and may use the configured system resolver.
- OpenSSH runs without user SSH configuration (`-F /dev/null`), agent forwarding/identity agents, password prompts or forwarding. Host-key verification is mandatory against a mounted known-hosts file. Unknown and changed keys fail.
- A fixed dependency-free Python helper is sent in the SSH command and executed in memory. It invokes commands as argument arrays without a shell. The transport shell receives only `shlex`-quoted helper source and JSON. No helper files or packages are installed on the appliance.
- Each remote subprocess is capped at 5 seconds and 128 KiB. TCP uses 4 seconds. The remote helper has a 20-second outer timeout; the local transport has a 25-second timeout, output cap and four-operation concurrency limit. Over-limit results fail closed; parsers do not interpret partial JSON. Sequential diagnosis can take longer than an individual command.
- stderr is discarded. Exceptions do not include raw output. Redis data is projected on the router before transport: a device read requests only `ipv4Addr`; forwarding config returns only typed protocol, ports, destination and enabled state. Unknown properties, descriptions, keys and credentials are omitted. No full hashes, key scans, VPN configuration files or logs are exposed.
- Diagnostic metadata (addresses, MACs, interface/ipset names and rule counters) can still be sensitive and will reach the connected MCP client/model. Use trusted clients, minimize retention, and avoid sharing results publicly. Remote text is data, not instructions. Projection is not a guarantee against a malicious router deliberately encoding secrets in allowed metadata fields.
- IPv4 firewall listings omit arbitrary rule comments/log prefixes and return numeric counters and basic matches only. They are not a full policy evaluator. Missing utilities, permissions, unfamiliar schemas or excessive output produce `unsupported`, never a fabricated result.
- `pi` and its key may permit administration outside this application. A compromised MCP host/key can bypass application restrictions. A restricted-account/forced-command deployment needs separate careful design and is not installed here.
- Only stdio is supported. Docker has no published ports, runs nonroot without capabilities, and mounts config/credentials read-only. Do not put an unauthenticated stdio-to-HTTP gateway on a network.

Not implemented: persistent mutations, rule changes, VPN switching, port assignment changes, packet capture, package installation, service restart, scheduled tasks, or internal HTTP API enablement. Packet metadata capture is deferred until an explicit opt-in, bounded, payload-free adapter can be independently validated. Do not substitute raw tcpdump output.

Report vulnerabilities privately through the repository owner's GitHub contact before posting operational details. Never include private keys, tokens, router IPs or raw traffic in a public issue.
