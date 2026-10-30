"""Emit a read-only helper validation command for an existing trusted SSH channel."""
import pathlib
import shlex
source = (pathlib.Path(__file__).resolve().parents[1] / "src/firewalla_mcp/remote.py").read_text()
source = source[:source.index('if __name__ == "__main__":')]
# Omit mutation function definitions from this read-only connector probe.
start = source.index('def write_spec(')
end = source.index('def dispatch(', start)
source = source[:start] + source[end:]
source = source.replace('    if op == "write":\n        return write_operation(args)\n', '')
source += '''
checks = [("capabilities", {}), ("health", {})]
checks += [("network", {"kind": kind}) for kind in ("interfaces", "addresses", "routes", "rules", "neighbors")]
checks += [("mappings", {}), ("firewall", {"table": "filter"}), ("firewall", {"table": "nat"}), ("ipsets", {}), ("connections", {})]
checks += [("services", {}), ("inventory", {"cursor":"0"}), ("vpn_interfaces", {}), ("traffic", {}), ("alarm_count", {"seconds":3600}), ("dns_config", {}), ("conntrack", {"address":"127.0.0.1"})]
checks += [("alarm_summaries", {"limit":3}), ("policy_summaries", {"limit":3}), ("flow_sample", {"limit":10})]
print(json.dumps([{"operation": op, "arguments": args, "status": execute(op, args)["status"]} for op, args in checks]))
'''
print(shlex.join(["timeout", "45", "python3", "-c", source]))
