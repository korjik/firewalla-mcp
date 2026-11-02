"""Real TCP/UDP source-family checks inside disposable --network none Docker.

NET_ADMIN is required. Never run on a router. This isolates the source-set
constraint; it is not Firewalla's full WAN/device/MARK/routing pipeline.
"""
import socket
import subprocess


def run(*args):
    r=subprocess.run(args,capture_output=True,text=True,timeout=5)
    if r.returncode:raise RuntimeError(r.stderr.strip())
    return r.stdout


run('ip','link','set','lo','up')
for family in ('inet','inet6'):
    run('ipset','create','mcp_source_'+family,'hash:net','family',family)
run('ipset','add','mcp_source_inet6','::1/128')
for proto,kind in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
    for af,address,exe,family in [(socket.AF_INET,'127.0.0.1','iptables','inet'),(socket.AF_INET6,'::1','ip6tables','inet6')]:
        server=socket.socket(af,kind);server.settimeout(.25)
        if af==socket.AF_INET6:server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        server.bind((address,0));port=server.getsockname()[1]
        if proto=='tcp':server.listen(4)
        chain='MCP_V6_'+proto.upper()
        run(exe,'-N',chain)
        run(exe,'-A','INPUT','-p',proto,'--dport',str(port),'-j',chain)
        run(exe,'-A',chain,'-p',proto,'-m','set','--match-set','mcp_source_'+family,'src','--dport',str(port),'-j','ACCEPT')
        run(exe,'-A',chain,'-j','DROP')
        def attempt(expected):
            run(exe,'-Z',chain)
            client=socket.socket(af,kind);client.settimeout(.25);received=False
            try:
                if proto=='tcp':
                    client.connect((address,port));accepted,_=server.accept();accepted.close();received=True
                else:
                    client.sendto(b'synthetic',(address,port));received=server.recvfrom(32)[0]==b'synthetic'
            except TimeoutError:pass
            finally:client.close()
            rows=[r.split() for r in run(exe,'-nvxL',chain).splitlines() if 'ACCEPT' in r or 'DROP' in r]
            counters={r[2]:int(r[0]) for r in rows}
            assert received is expected,(proto,family,counters,received)
            assert counters['ACCEPT' if expected else 'DROP']>0,(proto,family,counters)
            assert counters['DROP' if expected else 'ACCEPT']==0,(proto,family,counters)
        attempt(af==socket.AF_INET6)
        if af==socket.AF_INET6:
            run('ipset','flush','mcp_source_inet6');run('ipset','add','mcp_source_inet6','2001:db8:100::/48')
            attempt(False)
            run('ipset','flush','mcp_source_inet6');run('ipset','add','mcp_source_inet6','::1/128')
        server.close()
assert 'add mcp_source_inet ' not in run('ipset','save','mcp_source_inet')
print('PASS: real TCP and UDP IPv6 allowed only for selected source; IPv4 and excluded IPv6 sources dropped. No appliance/full-path proof.')
