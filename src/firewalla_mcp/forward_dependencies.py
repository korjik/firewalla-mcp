"""Conservative relationships from bounded, sanitized policy projections.

This evaluates relationships, not effective firewall precedence or permission.
Unresolved inheritance/unknown selectors prevent an absence or deletion claim.
"""
import json
import re


def ports(value):
    if value in (None,'',False):return [(1,65535)]
    if not isinstance(value,str):raise ValueError('port selector type')
    parts=value.split(',')
    if not 1<=len(parts)<=15:raise ValueError('port selector bound')
    result=[]
    for p in parts:
        if not re.fullmatch(r'[0-9]{1,5}(?:[-:][0-9]{1,5})?',p):raise ValueError('port selector')
        pair=re.split('[-:]',p);lo=int(pair[0]);hi=int(pair[-1])
        if not 1<=lo<=hi<=65535:raise ValueError('port range')
        result.append((lo,hi))
    return result


def array(value):
    if value in (None,'',False):return []
    if isinstance(value,str):value=json.loads(value)
    if not isinstance(value,list) or len(value)>64 or any(not isinstance(x,str) for x in value):raise ValueError('scope array')
    return value


def dependencies(mapping, policies, *, inventory_complete, group_tags=None, network_tags=None):
    if not isinstance(policies,list) or len(policies)>512:raise ValueError('bounded policy inventory required')
    if type(inventory_complete) is not bool:raise ValueError('explicit completeness required')
    mac=mapping['toMac'].upper();number=int(mapping['toPort']);external=int(mapping['dport'])
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',mac) or not 1<=number<=65535 or not 1<=external<=65535:raise ValueError('mapping selector')
    related=[];unknown=[];seen=set()
    for p in policies:
        pid=p.get('pid')
        if not isinstance(pid,str) or not re.fullmatch(r'[0-9]{1,20}',pid) or pid in seen:raise ValueError('policy identity')
        seen.add(pid)
        try:
            if p.get('identity_complete') is not True:raise ValueError('incomplete identity')
            direction=p.get('direction') or 'bidirection'
            if direction=='outbound':continue
            if direction not in ('inbound','bidirection'):raise ValueError('direction')
            protocol=p.get('protocol')
            if protocol and protocol not in ('tcp','udp'):raise ValueError('protocol')
            if protocol and protocol!=mapping['protocol']:continue
            if not any(lo<=number<=hi for lo,hi in ports(p.get('localPort'))):continue
            if not any(lo<=external<=hi for lo,hi in ports(p.get('origDport'))):continue
            scope=array(p.get('scope'));tags=array(p.get('tag'))
            if p.get('guids') or p.get('parentRgId') or p.get('targetRgId') or p.get('affectedPids'):raise ValueError('indirect rule dependency')
            target=str(p.get('target') or '').upper()
            literal_mac = p.get('type') in ('mac','internet') and bool(re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',target))
            if p.get('type') in ('mac','internet') and not literal_mac and target not in ('','TAG'):
                raise ValueError('unknown Internet target')
            # Resolve combinations before any disjoint-scope shortcut. Native
            # literal MAC targets override scope, but tag combinations remain
            # conservative until their complete semantics are represented.
            if tags and (scope or literal_mac):raise ValueError('combined scope')
            if literal_mac:
                if target!=mac:continue
                relationship='device'
            elif scope:
                if mac not in [v.upper() for v in scope]:continue
                relationship='device_scope'
            elif tags:
                if group_tags is None or network_tags is None:raise ValueError('unresolved inherited scope')
                if not set(tags)&(set(group_tags)|set(network_tags)):continue
                relationship='inherited'
            else:relationship='global'
            if p.get('owanUUID') and p['owanUUID']!=mapping.get('wanUUID'):continue
            related.append({'pid':pid,'relationship':relationship,'action':p.get('action','block'),
                            'disabled':p.get('disabled') in ('1',1,True),
                            'shared':relationship in ('inherited','global') or len(scope)>1,
                            'removal_authorized':False})
        except (ValueError,TypeError,json.JSONDecodeError):unknown.append(pid)
    return {'complete':inventory_complete and not unknown,'referring_policy_ids':[p['pid'] for p in related],
            'shared':any(p['shared'] for p in related),'relationships':related,'unresolved_policy_ids':unknown,
            'effective_permission':'not_evaluated','absence_proven':inventory_complete and not related and not unknown}


def mapping_removal_dependencies(mapping, mappings):
    """Structural effects of pinned PortForward.find/removePort/enforceIptables.

    Firewall policy applicability is deliberately not deletion ownership. Native
    removal touches NAT and its destination/protocol/port hairpin entry only.
    Unknown selectors fail closed, including on inactive rows (native find does
    not filter their state). Shared hairpin resources are never auto-compensated.
    """
    from ipaddress import IPv4Address
    from .writes import digest
    if not isinstance(mappings,list) or not 1<=len(mappings)<=256:raise ValueError('Complete mapping inventory required')
    # Only the exact typed selector used by forward_value is supported. Never
    # emulate arbitrary wildcard deletion or coerce booleans/numeric selectors.
    required={'_type','active','description','dport','enabled','protocol','state','toIP','toMac','toPort','wanUUID'}
    if set(mapping)-{'_type'}!=required-{'_type'} or mapping.get('_type','port_forward')!='port_forward' or mapping['protocol']!='tcp':raise ValueError('Exact native removal selector required')
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',mapping['wanUUID']):raise ValueError('Exact WAN required')
    if any(mapping[k] is not True for k in ('active','enabled','state')):raise ValueError('Active exact mapping required')
    target=str(IPv4Address(mapping['toIP']))
    def port(v):
        if isinstance(v,bool) or not isinstance(v,(str,int)) or not re.fullmatch(r'[0-9]{1,5}',str(v)):raise ValueError('Exact port required')
        n=int(v)
        if not 1<=n<=65535:raise ValueError('Exact port required')
        return n
    external,internal=port(mapping['dport']),port(mapping['toPort'])
    matches=[];shared=[];unresolved=[]
    for row in mappings:
        ident=digest(row)
        try:
            if not isinstance(row,dict):raise ValueError('Mapping shape')
            # The native selector compares a concrete toIP, ignoring toMac and
            # description. It also accepts numeric/string port equivalence.
            address=str(IPv4Address(row['toIP']))
            protocol=row.get('protocol')
            if protocol not in (None,'','tcp','udp'):raise ValueError('Protocol selector')
            kind=row.get('_type') or 'port_forward'
            if kind not in ('port_forward','dmz_host'):raise ValueError('Mapping kind')
            if address!=target or protocol=='udp' or kind=='dmz_host':continue
            # Same-address potentially relevant records must have bounded known
            # semantics. Auto-firewall/ts are metadata of preserved app mappings;
            # they never authorize policy deletion.
            if set(row)-required-{'applyToAll','extIP','autoFirewall','ts','toGuid'}:raise ValueError('Unknown structural field')
            if row.get('toGuid'):raise ValueError('Unresolved identity destination')
            ranges=ports(str(row['toPort']) if type(row.get('toPort')) is int else row.get('toPort'))
            overlap=any(lo<=internal<=hi for lo,hi in ranges)
            if row!=mapping and overlap:shared.append(ident)
            if (row.get('wanUUID')==mapping['wanUUID'] and row.get('applyToAll') is None and row.get('extIP') is None
                    and protocol=='tcp' and port(row.get('dport'))==external and port(row.get('toPort'))==internal):
                matches.append(ident)
        except (ValueError,TypeError,KeyError):unresolved.append(ident)
    return {'complete':not unresolved,'native_match_count':len(matches),
            'selected_match':matches==[digest(mapping)],'shared_hairpin_ids':shared,
            'unresolved_mapping_ids':unresolved,'policy_effect':'all nonselected policies preserved; applicability is not a structural reference'}


def require_mapping_removal(mapping,mappings):
    report=mapping_removal_dependencies(mapping,mappings)
    if not report['complete']:raise ValueError('Unresolved structural mapping evidence')
    if not report['selected_match'] or report['native_match_count']!=1:raise ValueError('Native removal selector matches absent or additional mappings')
    if report['shared_hairpin_ids']:raise ValueError('Shared hairpin resource; preserve mappings')
    return report


def hairpin_evidence(run,mapping):
    """Strict bounded native hairpin shape; ambiguous/duplicate rules block writes."""
    import shlex
    from ipaddress import IPv4Network
    wanted=(mapping['protocol'],str(IPv4Network(mapping['toIP']+'/32')),int(mapping['toPort']))
    matches=0
    raw=run(['sudo','-n','iptables','-t','nat','-S','FW_POSTROUTING_PORT_FORWARD'])
    lines=raw.splitlines()
    if len(lines)>1024:raise ValueError('Hairpin evidence bound')
    for line in lines:
        tokens=shlex.split(line)
        if tokens==['-N','FW_POSTROUTING_PORT_FORWARD']:continue
        # Native install_iptables_setup.sh installs this unconditional tail
        # dispatch. Exact mapping removal does not own or delete that chain.
        if tokens==['-A','FW_POSTROUTING_PORT_FORWARD','-j','FW_POSTROUTING_DMZ_HOST']:continue
        if len(tokens)%2:raise ValueError('Unknown hairpin rule shape')
        pairs=list(zip(tokens[::2],tokens[1::2]));d=dict(pairs)
        if len(d)!=len(pairs) or set(d)-{'-A','-d','-p','-m','--dport','-j'}:raise ValueError('Unknown hairpin rule selectors')
        if d.get('-A')!='FW_POSTROUTING_PORT_FORWARD' or d.get('-j')!='FW_POSTROUTING_HAIRPIN':raise ValueError('Unknown hairpin rule target')
        if d.get('-p') not in (None,'tcp','udp') or d.get('-m') not in (None,d.get('-p')):raise ValueError('Hairpin protocol')
        network=IPv4Network(d['-d'],strict=False)
        if d.get('-p')=='udp' or not IPv4Network(wanted[1]).subnet_of(network):continue
        ranges=ports(d.get('--dport'))
        if not any(lo<=wanted[2]<=hi for lo,hi in ranges):continue
        if d.get('-p')!=wanted[0] or str(network)!=wanted[1] or ranges!=[(wanted[2],wanted[2])]:raise ValueError('Overlapping ambiguous hairpin rule')
        matches+=1
    if matches>1:raise ValueError('Duplicate native hairpin rules')
    return matches==1
