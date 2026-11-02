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
