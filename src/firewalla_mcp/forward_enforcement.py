"""Strict proof of native per-policy rule shape and IPv4-only source sets.

This does not prove traversal, global precedence, service or external reachability.
Unexpected clauses, extra rules or non-empty IPv6 sources fail closed.
"""
import ipaddress
import re
import shlex


def ipset_entries(raw,name,family,kind):
    if not isinstance(raw,str) or len(raw)>16384:raise ValueError('ipset bound')
    rows=[shlex.split(line) for line in raw.splitlines() if line]
    if not rows or rows[0][:3]!=['create',name,kind]:raise ValueError('ipset identity')
    header=rows[0][3:]
    if kind=='hash:net' and ('family' not in header or header[header.index('family')+1]!=family):raise ValueError('ipset family')
    entries=[]
    for row in rows[1:]:
        if len(row)!=3 or row[:2]!=['add',name]:raise ValueError('unknown ipset entry')
        entries.append(row[2])
    return entries


def canonical_rule(line):
    t=shlex.split(line);out={'sets':[],'modules':[]}
    widths={'-A':1,'-p':1,'-m':1,'--match-set':2,'--ctorigdstport':1,'--ctdir':1,'--comment':1,'-j':1,'--set-xmark':1}
    i=0
    while i<len(t):
        flag=t[i];n=widths.get(flag)
        if n is None or i+n>=len(t):raise ValueError('unsupported enforcement clause')
        values=t[i+1:i+1+n];i+=n+1
        if flag=='--match-set':out['sets'].append(tuple(values))
        elif flag=='-m':out['modules'].append(values[0])
        else:
            if flag in out:raise ValueError('duplicate enforcement clause')
            out[flag]=values[0]
    if not set(out['modules'])<={'tcp','udp','set','conntrack','comment'}:raise ValueError('unexpected enforcement module')
    out.pop('modules');out['sets']=sorted(out['sets'])
    if '--set-xmark' in out:
        mark,mask=out['--set-xmark'].split('/')
        out['--set-xmark']=(int(mark,0),int(mask,0))
    return out


def verify_policy(value,pid,rules4,rules6,sets,enabled):
    if not isinstance(pid,str) or not re.fullmatch('[0-9]{1,5}',pid) or not 0<int(pid)<=65535:raise ValueError('native mark range')
    if any(not isinstance(lines,list) or len(lines)>4096 for lines in (rules4,rules6)):raise ValueError('rule bound')
    selected=[]
    for family,lines in ((4,rules4),(6,rules6)):
        rows=[]
        for line in lines:
            tokens=shlex.split(line)
            if any(tokens[i:i+2]==['--comment','rule_'+pid] for i in range(len(tokens)-1)):
                rows.append(canonical_rule(line))
        selected.append((family,rows))
    if not enabled:return all(not rows for _,rows in selected)
    source='c_bd_'+pid+'_set';local='c_bp_'+pid+'_local_port'
    network=ipaddress.IPv4Network(value['target'])
    expected_sources={str(network)} if network.prefixlen else {'0.0.0.0/1','128.0.0.0/1'}
    if {str(ipaddress.IPv4Network(v,strict=False)) for v in ipset_entries(sets[source],source,'inet','hash:net')}!=expected_sources:return False
    if ipset_entries(sets[source+'6'],source+'6','inet6','hash:net'):return False
    if ipset_entries(sets[local],local,None,'bitmap:port')!=[value['localPort']]:return False
    device='c_'+value['scope'][0]+'_set';wan='c_oif_'+value['owanUUID'][:13]+'_set'
    for family,rows in selected:
        expected=[]
        for direction in ('ORIGINAL','REPLY'):
            remote_side,local_side=('src','dst') if direction=='ORIGINAL' else ('dst','src')
            expected.append({'-A':'FW_FIREWALL_DEV_ALLOW_LO','-p':value['protocol'],
                'sets':sorted([(source+('6' if family==6 else ''),remote_side),(wan,remote_side+','+remote_side),(device,local_side),(local,local_side)]),
                '--ctorigdstport':value['origDport'],'--ctdir':direction,'--comment':'rule_'+pid,
                '-j':'MARK','--set-xmark':(int(pid),65535)})
        if len(rows)!=2 or any(row not in rows for row in expected):return False
    return True
