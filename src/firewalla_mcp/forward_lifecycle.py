"""Candidate complete forwarding preview planner; no writes during planning.

Only the authenticated host-confirmed integration may execute returned plans.
This module is not registered until the transport and deployment gates are ready.
"""
import copy
import secrets
from .forward_policy import native_allow,scope_disclosure,reject_duplicate
from .forward_dependencies import dependencies, require_mapping_removal
from .forward_reconcile import adopt_mapping_removal
from .forward_transaction import build_plan
from .writes import digest
from . import remote


async def preview(adapter,box,binding,actions,removals=()):
    if not isinstance(actions,list) or len(actions)>4 or not isinstance(removals,(list,tuple)) or len(removals)>8 or not actions and not removals:
        raise ValueError('Bounded nonempty lifecycle required')
    initial=await adapter.snapshot();state=copy.deepcopy(initial);steps=[];seen=set();disclosures=[]
    selected={}
    for item in removals:
        if not isinstance(item,dict) or set(item)!={'key','fingerprint'} or item['key'] in selected:raise ValueError('Exact removal selection required')
        row=initial['objects'].get(item['key'])
        if row is None or digest(row)!=item['fingerprint']:raise ValueError('Removal identity changed')
        if not item['key'].startswith(('mapping:mcp:','policy:mcp:')):raise ValueError('Unsupported ownership; unrelated object preserved')
        selected[item['key']]=row
    removed_pids={row['instance']['id'] for key,row in selected.items() if key.startswith('policy:')}
    # Disable/delete explicitly selected, strictly typed MCP companion policies.
    for key,row in selected.items():
        if row['kind']!='allow_policy':continue
        if adapter.policy_value(row['value'])!=row['value']:raise ValueError('Unsupported policy removal')
        pid=row['instance']['id']
        for policy in adapter.policies:
            if policy['pid'] in removed_pids:continue
            # Any indirect reference is unresolved until a dedicated complete
            # rule-group/reference collector proves it independent.
            if any(policy.get(f) not in (None,False,'','[]') for f in ('affectedPids','parentRgId','targetRgId')):
                raise ValueError('Unresolved policy reference; preserve existing policy')
        disabled={**row,'enabled':False}
        if row['enabled']:steps.append({'operation':'disable','key':key,'before':row,'after':disabled})
        steps.append({'operation':'remove','key':key,'before':disabled,'after':None})
        del state['objects'][key]
    for key,row in selected.items():
        if row['kind']!='mapping':continue
        spec=adapter.mapping_spec(row['value'])
        maps=[r['value'] for r in initial['objects'].values() if r['kind']=='mapping']
        deps=require_mapping_removal(row['value'],maps)
        applicability=dependencies(row['value'],[p for p in adapter.policies if p['pid'] not in removed_pids],inventory_complete=True)
        disclosures.append({'removal_key':key,'structural_evidence':deps,'preserved_policy_applicability':applicability,
                            'policy_warning':'Applicability is not deletion ownership or effective permission. Nonselected policies remain unchanged.'})
        selection={'device':spec['device'],'destination':spec['destination_ip'],'interface_uuid':spec['interface_uuid'],
                   'protocol':spec['protocol'],'external_port':spec['external_port'],'destination_port':spec['destination_port'],
                   'expected_fingerprint':digest(row['value'])}
        receipt_bound=any(r['key']==key and row['value'] in r['variants'] for r in getattr(adapter,'receipts',[]))
        if not receipt_bound:adopt_mapping_removal([r['value'] for r in initial['objects'].values() if r['kind']=='mapping'],selection,deps)
        steps.append({'operation':'remove','key':key,'before':row,'after':None});del state['objects'][key]
    disabled_steps=[];mapping_steps=[];enable_steps=[]
    for action in actions:
        if not isinstance(action,dict) or set(action)!={'protocol','external_port','destination_port','source_network'}:raise ValueError('Explicit action/source fields required')
        key=(action['protocol'],action['external_port'])
        if key in seen:raise ValueError('Duplicate forwarding action')
        seen.add(key)
        spec={**adapter.template,'protocol':action['protocol'],'external_port':action['external_port'],
              'destination_port':action['destination_port'],'owner_token':secrets.token_hex(16)}
        remote.validate_managed(spec)
        value=native_allow(spec['device'],spec['interface_uuid'],action['source_network'],action['protocol'],action['external_port'],action['destination_port'],secrets.token_hex(16))
        disclosures.append(scope_disclosure(value))
        existing_allow=[r for key,r in state['objects'].items() if key.startswith('policy:mcp:') and r['enabled']
                        and {k:v for k,v in r['value'].items() if k!='description'}=={k:v for k,v in value.items() if k!='description'}]
        if len(existing_allow)>1:raise ValueError('Ambiguous equivalent allowance')
        if not existing_allow:
            reject_duplicate([p for p in adapter.policies if p['pid'] not in removed_pids],value)
            policy={'kind':'allow_policy','value':value,'enabled':False};policykey='policy:'+value['description']
            disabled_steps.append({'operation':'create_disabled','key':policykey,'before':None,'after':policy})
            enable_steps.append({'operation':'enable','key':policykey,'before':policy,'after':{**policy,'enabled':True}})
        matches=[]
        for current in state['objects'].values():
            if current['kind']!='mapping':continue
            r=current['value']
            relevant=bool(r.get('applyToAll')) or r.get('wanUUID') in (None,'',spec['interface_uuid']) or r.get('_type')=='dmz_host'
            if not relevant or r.get('protocol') not in (None,'',spec['protocol']):continue
            lo,hi=remote.forward_port_range(r['dport']) if r.get('dport') else (1,65535)
            if lo<=spec['external_port']<=hi:matches.append(r)
        if matches:
            if len(matches)!=1 or not remote.forward_equivalent(matches[0],spec):raise ValueError('Conflicting preserved mapping')
        else:
            mapping={'kind':'mapping','value':{**remote.forward_value(spec),'active':True},'enabled':True}
            mapping_steps.append({'operation':'create','key':'mapping:'+mapping['value']['description'],'before':None,'after':mapping})
    steps+=disabled_steps+mapping_steps+enable_steps
    if not steps:return {'status':'no_change'}
    plan=build_plan(box,binding,initial,steps)
    # Disclosures are part of the immutable digest, not an unsigned UI hint.
    plan['disclosures']=disclosures;plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'})
    return plan
