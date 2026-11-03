"""Actual packet/counter test in disposable --network none Docker only.

Requires NET_ADMIN, iptables/ip6tables, ipset. Never run on an appliance.
The rules mirror the positive source-set family constraint, not Firewalla's
entire MARK/routing pipeline. That larger enforcement path remains separately
verified by the future native adapter.
"""
import socket
import subprocess

def run(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=5)
    if result.returncode:raise RuntimeError(result.stderr.strip())
    return result.stdout

run('ip','link','set','lo','up')
for family in ('inet','inet6'):
    run('ipset','create','source_'+family,'hash:net','family',family)
run('ipset','add','source_inet','0.0.0.0/1')
run('ipset','add','source_inet','128.0.0.0/1')
servers=[]
try:
    for af,address,exe,source in ((socket.AF_INET,'127.0.0.1','iptables','source_inet'),
                                (socket.AF_INET6,'::1','ip6tables','source_inet6')):
        server=socket.socket(af,socket.SOCK_STREAM)
        if af==socket.AF_INET6:server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        server.bind((address,0));server.listen(1);servers.append(server)
        port=server.getsockname()[1]
        run(exe,'-N','MCP_SCOPE')
        run(exe,'-A','INPUT','-p','tcp','--dport',str(port),'-j','MCP_SCOPE')
        run(exe,'-A','MCP_SCOPE','-p','tcp','-m','set','--match-set',source,'src',
            '-m','conntrack','--ctorigdstport',str(port),'-j','ACCEPT')
        run(exe,'-A','MCP_SCOPE','-j','DROP')
        client=socket.socket(af,socket.SOCK_STREAM);client.settimeout(.25)
        try:
            client.connect((address,port));connected=True
        except TimeoutError:connected=False
        finally:client.close()
        rows=[line.split() for line in run(exe,'-nvxL','MCP_SCOPE').splitlines() if 'ACCEPT' in line or 'DROP' in line]
        counts={row[2]:int(row[0]) for row in rows}
        if af==socket.AF_INET:
            assert connected and counts['ACCEPT']>0 and counts['DROP']==0
        else:
            assert not connected and counts['ACCEPT']==0 and counts['DROP']>0
    assert 'add source_inet6' not in run('ipset','save','source_inet6')
    print('PASS: IPv4 TCP matched; real IPv6 SYN reached DROP, never the positive empty-source-set allowance')
finally:
    for server in servers:server.close()
