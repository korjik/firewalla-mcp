"""Emit a read-only helper validation command for an existing trusted SSH channel."""
import pathlib
import shlex
source = (pathlib.Path(__file__).resolve().parents[1] / "src/firewalla_mcp/remote.py").read_text()
source = source[:source.index('if __name__ == "__main__":')]
source += '''
checks = [("capabilities", {}), ("health", {})]
checks += [("network", {"kind": kind}) for kind in ("interfaces", "addresses", "routes", "rules", "neighbors")]
checks += [("mappings", {}), ("firewall", {"table": "filter"}), ("firewall", {"table": "nat"}), ("ipsets", {}), ("connections", {})]
checks += [("services", {}), ("inventory", {"cursor":"0"}), ("vpn_interfaces", {}), ("traffic", {}), ("alarm_count", {"seconds":3600}), ("dns_config", {}), ("conntrack", {"address":"127.0.0.1"})]
print(json.dumps([{"operation": op, "arguments": args, "status": execute(op, args)["status"]} for op, args in checks]))
'''
print(shlex.join(["timeout", "45", "python3", "-c", source]))
