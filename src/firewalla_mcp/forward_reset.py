"""Bounded reset planning across explicit devices on one WAN; no live calls here."""
import copy
from .forward_transaction import build_plan,transition
from .forward_lifecycle import preview as additions
from .forward_dependencies import require_mapping_removal,array
from .forward_provenance import merge_receipts
from .writes import digest


async def reset_plan(adapter,box,binding,mapping_keys,policy_keys,actions,*,all_mappings):
    if type(all_mappings) is not bool or len(mapping_keys)>8 or len(policy_keys)>8 or not mapping_keys:
        raise ValueError('Explicit bounded reset selection required')
    if len(set(mapping_keys+policy_keys))!=len(mapping_keys+policy_keys):raise ValueError('Duplicate selection')
    initial=await adapter.snapshot();state=copy.deepcopy(initial);steps=[];disclosures=[]
    maps=[r['value'] for r in initial['objects'].values() if r['kind']=='mapping']
    if all_mappings and set(mapping_keys)!={k for k,r in initial['objects'].items() if r['kind']=='mapping'}:
        raise ValueError('Additional mappings discovered; fresh exact selection required')
    selected_pids={initial['objects'][k]['instance']['id'] for k in policy_keys}
    for p in adapter.policies:
        if set(array(p.get('affectedPids')))&selected_pids or p.get('parentRgId') or p.get('targetRgId'):
            raise ValueError('Referenced/group policies must be preserved')
    for key in policy_keys:
        row=state['objects'][key]
        if row['kind']!='allow_policy' or adapter.policy_value(row['value'])!=row['value']:raise ValueError('Exact supported allowance required')
        value=row['value'];scope=value.get('scope')
        if not isinstance(scope,list) or len(scope)!=1:raise ValueError('Single-device allow required')
        related=[k for k,r in initial['objects'].items() if r['kind']=='mapping' and r['value'].get('toMac','').upper()==scope[0].upper() and r['value'].get('protocol')==value.get('protocol') and str(r['value'].get('toPort'))==str(value.get('localPort'))]
        if len(related)!=1 or related[0] not in mapping_keys:raise ValueError('Shared or unselected allow association')
        disabled={**row,'enabled':False}
        if row['enabled']:steps.append({'operation':'disable','key':key,'before':row,'after':disabled})
        steps.append({'operation':'remove','key':key,'before':disabled,'after':None})
    for step in steps:state=transition(state,step)
    for key in mapping_keys:
        row=state['objects'][key]
        if row['kind']!='mapping':raise ValueError('Exact NAT selection required')
        spec=adapter.mapping_spec(row['value']);proof=require_mapping_removal(row['value'],maps)
        disclosures.append({'remove_mapping':key,'device':spec['device'],'destination':spec['destination_ip'],'protocol':spec['protocol'],
                            'external_port':spec['external_port'],'destination_port':spec['destination_port'],'structural':proof})
        step={'operation':'remove','key':key,'before':row,'after':None};steps.append(step);state=transition(state,step)
    class Projected:
        template=adapter.template
        policies=[p for p in adapter.policies if p['pid'] not in selected_pids]
        async def snapshot(self):return copy.deepcopy(state)
        def mapping_spec(self,value):return adapter.mapping_spec(value)
        def policy_value(self,value):return adapter.policy_value(value)
    names={}
    stripped=[]
    for action in actions:
        if set(action)!={'protocol','external_port','destination_port','source_network','display_name'}:raise ValueError('Explicit recreation fields')
        import re
        name=action['display_name']
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}',name) or name!=name.strip():raise ValueError('Display name')
        names[(action['protocol'],action['external_port'])]=name
        stripped.append({k:v for k,v in action.items() if k!='display_name'})
    created=await additions(Projected(),box,binding,stripped,[]) if actions else {'steps':[]}
    receipts=copy.deepcopy(getattr(adapter,'receipts',[]))
    for step in created.get('steps',[]):
        if step['after']['kind']=='mapping':
            original=copy.deepcopy(step['after']['value']);value=copy.deepcopy(original)
            value['description']=names[(value['protocol'],int(value['dport']))]
            # Recreating the same owned HTTP tuple/name retains its logical
            # identity, avoiding label-based adoption of a different object.
            prior=[(k,r) for k,r in initial['objects'].items() if k in mapping_keys and r['kind']=='mapping' and {f:x for f,x in r['value'].items() if f not in ('description','_type')}=={f:x for f,x in value.items() if f not in ('description','_type')}]
            if prior and prior[0][0].startswith('mapping:mcp:'):
                if len(prior)!=1:raise ValueError('Ambiguous recreation identity')
                step['key']=prior[0][0]
                old=prior[0][1]['value']
                existing=next((r for r in receipts if r['key']==step['key']),None)
                anchor=existing['anchor'] if existing else old
                receipts.append({'key':step['key'],'anchor':anchor,'variants':[anchor,old,value]})
            else:
                receipts.append({'key':step['key'],'anchor':original,'variants':[original,value]})
            step['after']['value']=value
        steps.append(step)
    plan=build_plan(box,binding,initial,steps,scope='native_forwarding_reset')
    plan['metadata_receipts']=merge_receipts(receipts)
    plan['disclosures']=disclosures+created.get('disclosures',[])+[{'reset':'Selected NAT and explicit allow policies only; all other policies preserved',
      'interruption':'Services unavailable during removal/recreation; partial expiry or failure can prolong outage',
      'atomic':False,'max_steps':32,'legacy_allow_family':'Selected legacy Internet allows may cover both IPv4 and IPv6; recreation preserves their exact reviewed semantics only during recovery',
      'new_forward_family':'IPv4 DNAT only; no NAT66 or implicit IPv6 exposure'}]
    plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'})
    return plan
