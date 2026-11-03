"""Isolated family-contract rejection proof. Never run on a router.

Run inside the disposable kernel test image with --network none, cap-drop ALL,
and only NET_ADMIN. This records an unsupported candidate, not a live fix.
"""
import subprocess
control=subprocess.run(['ip6tables','-t','filter','-A','INPUT','-p','tcp','-m','conntrack',
                        '--ctorigdst','2001:db8::2','--ctorigdstport','443','-j','ACCEPT'],
                       capture_output=True,text=True,timeout=5)
assert control.returncode==0, 'IPv6 conntrack control failed; cannot attribute rejection to address family'
r=subprocess.run(['ip6tables','-t','filter','-A','INPUT','-p','tcp','-m','conntrack',
                  '--ctorigdst','198.51.100.2','--ctorigdstport','443','-j','ACCEPT'],
                 capture_output=True,text=True,timeout=5)
assert r.returncode!=0, 'Re-evaluate native family contract: candidate unexpectedly accepted'
assert 'Address family' in r.stderr or 'host/network' in r.stderr
print('IPv4 original-destination emitted as IPv6 rule is rejected; native writer remains blocked')
