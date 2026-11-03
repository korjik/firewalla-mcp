"""Native legacy device inbound-allow proof; deliberately dual-stack semantics."""
import re
import shlex
from .forward_enforcement import canonical_rule,ipset_entries


def legacy_rule(line):
    tokens=shlex.split(line);out=[];i=0
    if any(tokens[n]=='--match-set' and tokens[n+1].startswith('!') for n in range(len(tokens)-1)):
        raise ValueError('Reserved internal set marker')
    while i<len(tokens):
        if tokens[i]=='!':
            if tokens[i+1:i+3]!=['--match-set','monitored_net_set'] or i+3>=len(tokens):
                raise ValueError('Unsupported rule negation')
            out+=['--match-set','!monitored_net_set',tokens[i+3]];i+=4
        else:out.append(tokens[i]);i+=1
    return canonical_rule(shlex.join(out))


def verify_legacy_allow(value,pid,rules4,rules6,sets,enabled):
    if not re.fullmatch(r'[0-9]{1,5}',pid) or not 0<int(pid)<=65535:raise ValueError('Policy mark')
    local='c_bp_'+pid+'_local_port';device='c_'+value['scope'][0]+'_set'
    if enabled and ipset_entries(sets[local],local,None,'bitmap:port')!=[value['localPort']]:return False
    for lines in (rules4,rules6):
        if not isinstance(lines,list) or len(lines)>4096:raise ValueError('Rule bound')
        rows=[]
        for line in lines:
            tokens=shlex.split(line)
            if any(tokens[i:i+2]==['--comment','rule_'+pid] for i in range(len(tokens)-1)):rows.append(legacy_rule(line))
        if not enabled:
            if rows:return False
            continue
        expected=[]
        for direction in ('ORIGINAL','REPLY'):
            remote,near=('src','dst') if direction=='ORIGINAL' else ('dst','src')
            expected.append({'-A':'FW_FIREWALL_DEV_ALLOW_LO','-p':value['protocol'],
                'sets':sorted([('!monitored_net_set',remote+','+remote),(device,near),(local,near)]),
                '--ctdir':direction,'--comment':'rule_'+pid,'-j':'MARK','--set-xmark':(int(pid),65535)})
        if len(rows)!=2 or any(r not in rows for r in expected):return False
    return True
