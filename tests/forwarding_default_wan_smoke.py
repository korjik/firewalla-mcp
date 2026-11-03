"""Disposable network-none kernel namespace only; never run on an appliance."""
import subprocess
from firewalla_mcp import remote
from firewalla_mcp.forward_default_wan import default_evidence
from firewalla_mcp.forward_dependencies import hairpin_evidence


def run(args):
    if args[:2]==['sudo','-n']:args=args[2:]
    if args[0]=='iptables':args=['iptables-legacy',*args[1:]]
    result=subprocess.run(args,capture_output=True,text=True,timeout=5)
    if result.returncode:raise RuntimeError(result.stderr.strip())
    return result.stdout


wan='11111111-1111-4111-8111-111111111111'
other='33333333-3333-4333-8333-333333333333'
sets={'c_ip_'+wan[:13]+'_set':['198.51.100.2'],'c_ip_'+other[:13]+'_set':['203.0.113.2']}
networks=[{'uuid':u,'type':'wan'} for u in (wan,other)]
remote.run=run
remote.interface_forward_environment=lambda spec:{'networks':networks,'sets':sets,'addresses':sets['c_ip_'+spec['interface_uuid'][:13]+'_set']}
for name,addresses in sets.items():
    run(['ipset','create',name,'hash:ip'])
    for address in addresses:run(['ipset','add',name,address])
for chain in ['FW_PREROUTING_EXT_IP','FW_PRERT_PORT_FORWARD','FW_POSTROUTING_PORT_FORWARD','FW_POSTROUTING_HAIRPIN']:
    run(['iptables','-t','nat','-N',chain])
for addresses in sets.values():
    for address in addresses:run(['iptables','-t','nat','-A','FW_PREROUTING_EXT_IP','-d',address,'-j','FW_PRERT_PORT_FORWARD'])
spec={'kind':'managed_interface_forward','interface_uuid':wan,'destination_ip':'192.0.2.20','external_port':80,'destination_port':80,'protocol':'tcp'}
old={'protocol':'tcp','dport':'80','toPort':'80','toIP':'192.0.2.20'}
rule=['FW_PRERT_PORT_FORWARD','-p','tcp','--dport','80','-j','DNAT','--to-destination','192.0.2.20:80']
hairpin=['FW_POSTROUTING_PORT_FORWARD','-p','tcp','-d','192.0.2.20','--dport','80','-j','FW_POSTROUTING_HAIRPIN']
run(['iptables','-t','nat','-A',*rule]);run(['iptables','-t','nat','-A',*hairpin])
assert default_evidence(spec,old)['nat_rule_observed'] and hairpin_evidence(run,old)
run(['iptables','-t','nat','-D',*rule]);run(['iptables','-t','nat','-D',*hairpin])
assert not default_evidence(spec,old)['nat_rule_observed'] and not hairpin_evidence(run,old)
new={**old,'wanUUID':wan,'toPort':'8080'}
run(['iptables','-t','nat','-A','FW_PRERT_PORT_FORWARD','-p','tcp','--dport','80','-m','set','--match-set','c_ip_'+wan[:13]+'_set','dst','-j','DNAT','--to-destination','192.0.2.20:8080'])
run(['iptables','-t','nat','-A','FW_POSTROUTING_PORT_FORWARD','-p','tcp','-d','192.0.2.20','--dport','8080','-j','FW_POSTROUTING_HAIRPIN'])
assert remote.forward_kernel_evidence({**spec,'destination_port':8080})['nat_rule_observed']
assert not default_evidence(spec,old)['nat_rule_observed'] and not hairpin_evidence(run,old)
assert hairpin_evidence(run,new)
assert not remote.interface_nat_guard(spec,False,sets,[new])[0]
print('PASS: actual iptables/ipset default-WAN removal, selected-WAN replacement and independent hairpin proofs; network-none, no traffic')
