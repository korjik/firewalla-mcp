"""Run only in a disposable Docker --network none namespace with NET_ADMIN.

Tests native-builder constraints, not appliance traversal or service reachability.
No host networking, interfaces or router access are required.
"""
import subprocess


def run(args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if success:
        assert result.returncode == 0, (args, result.stderr)
    else:
        assert result.returncode != 0, args
    return result


for binary in ('iptables', 'ip6tables'):
    run([binary, '-N', 'MCP_V6_CONTRACT'])
for protocol in ('tcp', 'udp'):
    rule = ['-A', 'MCP_V6_CONTRACT', '-p', protocol, '-m', 'conntrack',
            '--ctorigdst', '2001:db8::2', '--ctorigdstport', '443',
            '--ctdir', 'ORIGINAL', '-j', 'ACCEPT']
    result = run(['iptables', *rule], success=False)
    assert 'address' in result.stderr.lower() or 'host' in result.stderr.lower(), result.stderr
    run(['ip6tables', *rule])
# Family-isolated source sets can support the distinct device-wide alternative.
run(['ipset', 'create', 'mcp_sources4', 'hash:net', 'family', 'inet'])
run(['ipset', 'create', 'mcp_sources6', 'hash:net', 'family', 'inet6'])
run(['ipset', 'add', 'mcp_sources6', '2001:db8:100::/48'])
run(['ipset', 'test', 'mcp_sources6', '2001:db8:100::1'])
run(['ipset', 'test', 'mcp_sources6', '2001:db8:200::1'], success=False)
run(['ipset', 'test', 'mcp_sources4', '192.0.2.1'], success=False)
for binary, source in [('iptables', 'mcp_sources4'), ('ip6tables', 'mcp_sources6')]:
    for protocol in ('tcp', 'udp'):
        run([binary, '-A', 'MCP_V6_CONTRACT', '-p', protocol, '-m', 'set',
             '--match-set', source, 'src', '--dport', '443', '-j', 'ACCEPT'])
print('PASS: IPv6 exact destination rejected by IPv4 native rule; TCP/UDP source-family isolation and scoped set membership verified. No packet-path proof.')
