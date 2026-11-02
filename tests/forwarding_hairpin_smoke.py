"""Disposable network-none kernel test; never run on a router or Docker host."""
import subprocess
from firewalla_mcp.forward_dependencies import hairpin_evidence,require_mapping_removal

def run(args):return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=5)
for chain in ('FW_POSTROUTING_PORT_FORWARD','FW_POSTROUTING_HAIRPIN'):
    run(['iptables','-t','nat','-N',chain])
def args(port):return ['-d','192.0.2.20/32','-p','tcp','--dport',str(port),'-j','FW_POSTROUTING_HAIRPIN']
for port in (443,19132):run(['iptables','-t','nat','-A','FW_POSTROUTING_PORT_FORWARD']+args(port))
m={'_type':'port_forward','active':True,'description':'mcp:'+'a'*32,'dport':'443','enabled':True,'protocol':'tcp','state':True,'toIP':'192.0.2.20','toMac':'02:00:00:00:00:01','toPort':'443','wanUUID':'11111111-1111-4111-8111-111111111111'}
def root_run(argv):return run(argv[2:] if argv[:2]==['sudo','-n'] else argv)
assert hairpin_evidence(root_run,m)
shared={**m,'description':'mcp:'+'b'*32,'wanUUID':'22222222-2222-4222-8222-222222222222'}
try:require_mapping_removal(m,[m,shared])
except ValueError:pass
else:raise AssertionError('shared resource deletion permitted')
assert hairpin_evidence(root_run,m)
require_mapping_removal(m,[m])
run(['iptables','-t','nat','-D','FW_POSTROUTING_PORT_FORWARD']+args(443))
assert not hairpin_evidence(root_run,m)
assert hairpin_evidence(root_run,{**m,'toPort':'19132'})
print('PASS: native-shaped kernel hairpin evidence/removal; unrelated port preserved; cross-WAN sharing rejected without deletion')
