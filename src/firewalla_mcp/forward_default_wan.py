"""Pinned native default-WAN proof; never substitute a WAN in stored selectors."""
import shlex
from . import remote


def exact_default_nat(tokens,mapping):
    """Accept exactly one native, unrestricted WAN-chain DNAT rule shape."""
    if len(tokens)%2:return False
    pairs=list(zip(tokens[::2],tokens[1::2]));values=dict(pairs)
    if len(values)!=len(pairs):return False
    expected={'-A':'FW_PRERT_PORT_FORWARD','-p':mapping['protocol'],
              '--dport':str(mapping['dport']),'-j':'DNAT',
              '--to-destination':mapping['toIP']+':'+str(mapping['toPort'])}
    if '-m' in values:expected['-m']=mapping['protocol']
    return values==expected


def exact_lifecycle_nat(tokens,mapping):
    if 'wanUUID' in mapping:
        tokens=list(tokens)
        clause=['--match-set','c_ip_'+mapping['wanUUID'][:13]+'_set','dst']
        if tokens.count('--match-set')!=1:return False
        index=tokens.index('--match-set')
        if tokens[index:index+3]!=clause:return False
        del tokens[index:index+3]
        pairs=[tokens[i:i+2] for i in range(0,len(tokens),2)]
        if pairs.count(['-m','set'])!=1:return False
        pairs.remove(['-m','set']);tokens=[x for pair in pairs for x in pair]
    return exact_default_nat(tokens,mapping)


def default_inventory(mapping,mappings,removing):
    """Restoring default scope must be collision-free across every WAN."""
    for other in mappings:
        if removing and other==mapping:continue
        if other.get('protocol') not in ('tcp','udp',None,''):raise ValueError('Unknown mapping protocol')
        if other.get('protocol') not in (None,'',mapping['protocol']):continue
        lo,hi=remote.forward_port_range(other['dport']) if other.get('dport') else (1,65535)
        if lo<=int(mapping['dport'])<=hi:raise ValueError('Default WAN mapping overlap')


def default_evidence(spec,mapping):
    environment=remote.interface_forward_environment(spec)
    wans=[n for n in environment['networks'] if n['type']=='wan']
    if not 1<=len(wans)<=16:raise ValueError('Complete bounded WAN inventory required')
    ingress=True
    for wan in wans:
        evidence=remote.forward_kernel_evidence({**spec,'interface_uuid':wan['uuid']})
        ingress=ingress and evidence['vpn_ingress_link_observed']
    lines=remote.run(['sudo','-n','iptables','-t','nat','-S','FW_PRERT_PORT_FORWARD']).splitlines()
    if len(lines)>1024:raise ValueError('Default WAN NAT evidence bound')
    count=sum(exact_default_nat(shlex.split(line),mapping) for line in lines)
    if count>1:raise ValueError('Duplicate default WAN NAT rules')
    if count:
        conflict,_=remote.interface_nat_guard(spec,False,None,[mapping])
        if conflict:raise ValueError('Default WAN kernel overlap')
    return {'nat_rule_observed':count==1,'vpn_ingress_link_observed':ingress,
            'interface_scope':'Native default WAN chain without destination-set restriction; includes hairpin',
            'external_reachability':'not tested'}
