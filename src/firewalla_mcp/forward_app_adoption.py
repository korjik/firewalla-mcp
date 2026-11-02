"""Exact app-object selection primitives. No execution or implicit ownership.

These validators prepare an explicit adoption contract; a live coordinator must
still bind the complete snapshot, source guards, journal and host confirmation.
"""
import copy
import json
import re
from .forward_dependencies import array, require_mapping_removal
from .forward_policy import PROJECTION_FIELDS, IDENTITY_FIELDS
from .writes import digest


def legacy_allow(row):
    if not isinstance(row,dict) or row.get('identity_complete') is not True or row.get('legacy_identity'):
        raise ValueError('Complete policy semantics required')
    if not re.fullmatch(r'[0-9]{1,5}',str(row.get('pid',''))) or not 0<int(row['pid'])<=65535:
        raise ValueError('Exact policy ID required')
    if not re.fullmatch(r'[a-f0-9]{40}',row.get('full_fingerprint','')) or not row.get('timestamp'):
        raise ValueError('Policy fingerprint and birth required')
    if row.get('unknown_fields'):raise ValueError('Unreviewed policy fields')
    birth=row.get('timestamp')
    if type(birth) not in (str,int,float) or not re.fullmatch(r'[0-9]{1,16}(?:\.[0-9]{1,9})?',str(birth)) or float(birth)<=0:
        raise ValueError('Numeric policy birth required')
    disabled=row.get('disabled')
    if not (disabled is None or type(disabled) is bool or type(disabled) is int and disabled in (0,1) or type(disabled) is str and disabled in ('','0','1')):
        raise ValueError('Unknown policy disabled state')
    if set(row)-set(PROJECTION_FIELDS)-{'identity_complete','full_fingerprint','legacy_identity','unknown_fields'}:
        raise ValueError('Unknown policy projection')
    scope=array(row.get('scope'))
    if len(scope)!=1 or not re.fullmatch(r'(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}',scope[0]):
        raise ValueError('Single explicit device scope required')
    if any(row.get(k)!=v for k,v in {'type':'mac','target':'TAG','action':'allow','direction':'inbound'}.items()):
        raise ValueError('Only explicit app inbound allows are eligible')
    if row.get('protocol') not in ('tcp','udp') or not re.fullmatch(r'[0-9]{1,5}',str(row.get('localPort',''))) or not 1<=int(row['localPort'])<=65535:
        raise ValueError('Exact TCP/UDP local port required')
    primary={'type','target','action','direction','scope','localPort','protocol'}
    for k in set(IDENTITY_FIELDS)-primary:
        v=row.get(k)
        if k=='seq' and v in (3,'3'):continue
        if k in ('upnp','dnsmasq_only','trust','ipOnly','flowIsolation','useBf'):
            empty=v is None or v is False or v=='' or v=='false'
        elif k in ('tag','targets','guids','affectedPids'):
            empty=v is None or v=='' or v=='[]' or type(v) is list and not v
        else:
            empty=v is None or type(v) is str and v==''
        if not empty:raise ValueError('Unsupported policy selector: '+k)
    if any(row.get(k) not in (None,False,'') for k in ('duration','idleTs')):
        raise ValueError('Timed policy unsupported')
    value={k:copy.deepcopy(row[k]) for k in primary if k!='scope'}
    value['scope']=[scope[0].upper()];value['localPort']=str(int(row['localPort']))
    if row.get('description') not in (None,''):
        if not isinstance(row['description'],str) or len(row['description'])>256:raise ValueError('Description bound')
        value['description']=row['description']
    if row.get('purpose') not in (None,''):
        if row['purpose']!='port_forwarding':raise ValueError('Unreviewed policy purpose')
        value['purpose']=row['purpose']
    if row.get('updatedTime') not in (None,''):
        updated=row['updatedTime']
        if type(updated) not in (str,int,float) or not re.fullmatch(r'[0-9]{1,16}(?:\.[0-9]{1,9})?',str(updated)) or float(updated)<=0:raise ValueError('Policy update metadata')
        value['updatedTime']=updated
    return value


def select_app_objects(mappings,policies,mapping_selections,policy_selections):
    """Read-only exact selection, never broad 'all rules' or port-only deletion.

    Policy selections bind PID, birth and full semantic hash. Mapping selections
    bind full stored JSON. Matching selectors identify relationships, not consent.
    """
    if not isinstance(mappings,list) or len(mappings)>256 or not isinstance(policies,list) or len(policies)>512:
        raise ValueError('Complete bounded inventory required')
    if not 1<=len(mapping_selections)<=8 or len(policy_selections)>8:raise ValueError('Adoption bounds')
    chosen=[];seen=set()
    for sel in mapping_selections:
        if set(sel)!={'fingerprint'} or not re.fullmatch('[a-f0-9]{64}',sel['fingerprint']) or sel['fingerprint'] in seen:raise ValueError('Exact unique mapping selection')
        seen.add(sel['fingerprint']);matches=[m for m in mappings if digest(m)==sel['fingerprint']]
        if len(matches)!=1:raise ValueError('Mapping identity drift')
        m=matches[0];proof=require_mapping_removal(m,mappings)
        if not isinstance(m.get('description'),str) or len(m['description'])>256:raise ValueError('Mapping label bound')
        if not re.fullmatch(r'(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}',m.get('toMac','')):raise ValueError('Mapping device identity')
        chosen.append({'kind':'mapping','key':'mapping:'+digest(m),'value':copy.deepcopy(m),'fingerprint':digest(m),'structural':proof})
    selected=[];seen=set()
    for sel in policy_selections:
        if set(sel)!={'id','birth','fingerprint'} or sel['id'] in seen:raise ValueError('Exact unique policy selection')
        seen.add(sel['id']);matches=[p for p in policies if p.get('pid')==sel['id']]
        if len(matches)!=1:raise ValueError('Policy identity drift')
        p=matches[0]
        if str(p.get('timestamp'))!=sel['birth'] or p.get('full_fingerprint')!=sel['fingerprint']:raise ValueError('Policy changed')
        v=legacy_allow(p)
        related=[m for m in mappings if m.get('toMac','').upper()==v['scope'][0] and m.get('protocol')==v['protocol'] and str(m.get('toPort'))==v['localPort']]
        if len(related)!=1 or digest(related[0]) not in {r['fingerprint'] for r in chosen}:raise ValueError('Shared or unselected mapping association')
        for other in policies:
            refs=array(other.get('affectedPids'))
            if sel['id'] in refs:raise ValueError('Referenced policy must be preserved')
            if other.get('parentRgId') or other.get('targetRgId'):raise ValueError('Unresolved rule-group references')
        selected.append({'kind':'allow_policy','key':'policy:'+sel['id'],'value':v,'instance':{'id':sel['id'],'birth':sel['birth']},
                         'fingerprint':sel['fingerprint'],'enabled':p.get('disabled') not in ('1',1,True),
                         'disclosure':'Existing device allow can cover direct IPv4/IPv6 and non-DNAT traffic; deletion removes that permission too.'})
    return {'mappings':chosen,'policies':selected,'automatic_policy_selection':False,
            'preserved_mapping_count':len(mappings)-len(chosen),'preserved_policy_count':len(policies)-len(selected),
            'execution_enabled':False,'reason':'Requires integrated guarded adoption executor; this is a selection validator only.'}


def merge_adoptions(records):
    result={'mappings':[],'policies':[],'policy_instances':[]};pids={}
    if len(records)>64:raise ValueError('Adoption history bound')
    for record in records:
        if set(record)-{'policy_instances'}!={'mappings','policies'}:raise ValueError('Adoption shape')
        for instance in record.get('policy_instances',[]):
            if set(instance)!={'key','id','birth'} or not re.fullmatch(r'policy:app:[0-9]{1,5}',instance['key']) or not re.fullmatch(r'[0-9]{1,5}',instance['id']) or not isinstance(instance['birth'],str) or not 0<len(instance['birth'])<=80:raise ValueError('Allocated policy identity')
            if instance not in result['policy_instances']:result['policy_instances'].append(copy.deepcopy(instance))
        for m in record['mappings']:
            if m not in result['mappings']:result['mappings'].append(copy.deepcopy(m))
        for p in record['policies']:
            legacy_allow(p)
            if p['pid'] in pids and pids[p['pid']]!=p:raise ValueError('Conflicting policy adoption history')
            if p['pid'] not in pids:result['policies'].append(copy.deepcopy(p));pids[p['pid']]=p
    if len(result['mappings'])>8 or len(result['policies'])>8 or len(result['policy_instances'])>32:raise ValueError('Adoption target bound')
    return result


def load_adoptions(directory,box,binding):
    from .forward_journal import ForwardJournal
    journals=ForwardJournal(directory);paths=list(journals.root.root().glob('*.journal'))
    if len(paths)>512:raise ValueError('Recovery inventory bound')
    records=[]
    for path in paths:
        with journals.locked(path.stem,create=False) as session:
            if not session.events:continue
            plan=session.events[0]['data'].get('plan',{})
            if plan.get('box')!=box or 'app_adoptions' not in plan:continue
            if not any(e['data'].get('event')=='dispatch' for e in session.events):continue
            if plan.get('binding')!=binding or digest({k:v for k,v in plan.items() if k!='digest'})!=plan.get('digest'):raise ValueError('Adoption provenance changed')
            record=copy.deepcopy(plan['app_adoptions']);record.setdefault('policy_instances',[])
            for event in session.events:
                data=event['data']
                if data.get('event')=='verified' and data.get('instance'):
                    key=plan['steps'][data['index']]['key']
                    if key.startswith('policy:app:'):record['policy_instances'].append({'key':key,**data['instance']})
            records.append(record)
    return merge_adoptions(records)
