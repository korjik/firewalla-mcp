"""Exact app-adoption native adapter, enabled only by the coordinator opt-in."""
import copy
import time
import asyncio
from . import remote
from .forward_native import NativeForwardAdapter
from .forward_provenance import ReceiptNativeAdapter
from .forward_app_adoption import legacy_allow
from .forward_app_enforcement import verify_legacy_allow
from .forward_dependencies import require_mapping_removal,hairpin_evidence
from .forward_policy import reject_duplicate
from .forward_transaction import transition,bind_created_instance
from .writes import digest


class AppForwardAdapter(ReceiptNativeAdapter):
    def __init__(self,revision,template,receipts,adoptions):
        super().__init__(revision,template,receipts)
        if not isinstance(adoptions,dict) or set(adoptions)-{'policy_instances'}!={'mappings','policies'} or len(adoptions['mappings'])>8 or len(adoptions['policies'])>8:
            raise ValueError('Bounded exact adoption records required')
        self.app_maps=copy.deepcopy(adoptions['mappings']);self.app_policies=copy.deepcopy(adoptions['policies'])
        self.app_values={}
        from .forward_app_adoption import merge_adoptions
        self.policy_instances=merge_adoptions([adoptions])['policy_instances']
        for row in self.app_policies:
            key='policy:app:'+row['pid']
            if key in self.app_values:raise ValueError('Duplicate adopted policy')
            self.app_values[key]=legacy_allow(row)
        if len({digest(m) for m in self.app_maps})!=len(self.app_maps):raise ValueError('Duplicate adopted mapping')
        for m in self.app_maps:
            require_mapping_removal(m,self.app_maps)
            self.mapping_spec(m)
        for v in self.app_values.values():
            matches=[m for m in self.app_maps if m['toMac'].upper()==v['scope'][0] and m['protocol']==v['protocol'] and str(m['toPort'])==v['localPort']]
            if len(matches)!=1:raise ValueError('Policy requires one explicitly adopted mapping')

    def mapping_spec(self,value):
        if hasattr(self,'app_maps') and value in self.app_maps:
            spec={**self.template,'device':value['toMac'].upper(),'destination_ip':value['toIP'],
                  'interface_uuid':value['wanUUID'],'protocol':value['protocol'],
                  'external_port':int(value['dport']),'destination_port':int(value['toPort'])}
            remote.validate_managed(spec)
            if spec['interface_uuid']!=self.template['interface_uuid']:raise ValueError('One selected WAN required')
            return spec
        return super().mapping_spec(value)

    def policy_value(self,value):
        if value in getattr(self,'app_values',{}).values():return copy.deepcopy(value)
        return super().policy_value(value)

    async def snapshot(self):
        state=await super().snapshot()
        env={}
        for m in self.app_maps:
            spec=self.mapping_spec(m);target=(spec['device'],spec['destination_ip'])
            if str(target) not in env:env[str(target)]=remote.forward_snapshot(spec)['environment_fingerprint']
        state['environment']['adopted_targets']=env
        for key,value in self.app_values.items():
            original=next(p for p in self.app_policies if key=='policy:app:'+p['pid'])
            candidates=[]
            for p in self.policies:
                try:normalized=legacy_allow(p)
                except (ValueError,KeyError,TypeError):normalized=None
                if p['pid']==original['pid'] and (str(p.get('timestamp'))!=str(original['timestamp']) or normalized!=value):
                    raise ValueError('Adopted policy identity changed')
                allowed=(p['pid']==original['pid'] and str(p.get('timestamp'))==str(original['timestamp'])) or {'key':key,'id':p['pid'],'birth':str(p.get('timestamp'))} in self.policy_instances
                if normalized==value and allowed:candidates.append(p)
            if len(candidates)>1:raise ValueError('Ambiguous adopted policy semantics')
            if candidates:
                p=candidates[0];old='policy:'+p['pid']
                if old not in state['objects']:raise ValueError('Unexpected adopted policy ownership')
                del state['objects'][old]
                state['objects'][key]={'kind':'allow_policy','value':copy.deepcopy(value),
                  'enabled':p.get('disabled') not in ('1',1,True),
                  'instance':{'id':p['pid'],'birth':str(p['timestamp'])}}
        return state

    def legacy_proof(self,row):
        pid=row['instance']['id'];sets={}
        if row['enabled']:
            name='c_bp_'+pid+'_local_port';sets[name]=remote.run(['sudo','-n','ipset','save',name])
        rules=[remote.run(['sudo','-n',exe,'-t','filter','-S']).splitlines() for exe in ('iptables','ip6tables')]
        return verify_legacy_allow(row['value'],pid,*rules,sets,row['enabled'])

    async def verify(self,state,removed=()):
        legacy=[r for r in removed if r['key'] in self.app_values]
        if not await super().verify(state,[r for r in removed if r not in legacy]):return False
        for key,row in state['objects'].items():
            if key in self.app_values and not self.legacy_proof(row):return False
            if row['kind']=='mapping' and row['value'] in self.app_maps:
                evidence=remote.forward_kernel_evidence(self.mapping_spec(row['value']))
                if not evidence['nat_rule_observed'] or not evidence['vpn_ingress_link_observed'] or not hairpin_evidence(remote.run,row['value']):return False
        for item in legacy:
            pid=item['before']['instance']['id']
            if any(r.get('instance',{}).get('id')==pid for r in state['objects'].values()):return False
            if not self.legacy_proof({**item['before'],'enabled':False}):return False
        return True

    async def mutate(self,step,expected,expires_at):
        if step['key'] not in self.app_values:return await super().mutate(step,expected,expires_at)
        self.guard();before=await self.snapshot()
        if digest(before)!=expected:raise ValueError('State drift')
        projected=transition(before,step);value=(step['after'] or step['before'])['value']
        if value!=self.app_values[step['key']]:raise ValueError('Adopted policy scope changed')
        op=step['operation'];pid=None
        # No indirect references may be affected by a policy removal.
        from .forward_dependencies import array
        for p in self.policies:
            if p.get('parentRgId') or p.get('targetRgId'):raise ValueError('Unresolved group references')
            if step['before'] and before['objects'][step['key']]['instance']['id'] in array(p.get('affectedPids')):raise ValueError('Referenced policy')
        if op in ('restore','create_disabled'):
            if step['after']['enabled']:raise ValueError('Restore disabled only')
            reject_duplicate(self.policies,value)
            command='policy:create';payload={**value,'disabled':'1'}
        elif op in ('disable','enable','remove'):
            command='policy:'+{'disable':'disable','enable':'enable','remove':'delete'}[op]
            payload={'policyID':before['objects'][step['key']]['instance']['id']}
        else:raise ValueError('Adopted policy operation')
        if not time.time()<min(expires_at,self.template['maintenance_until'])<=time.time()+600:raise ValueError('Maintenance expired')
        result=remote.management_request('cmd',command,'0.0.0.0',payload,command=='policy:create')
        if command=='policy:create':
            pid=result
            if pid in {p['pid'] for p in self.policies}:raise ValueError('Native create reused existing identity')
        end=min(time.monotonic()+4,time.monotonic()+max(0,expires_at-time.time()))
        while time.monotonic()<end:
            await asyncio.sleep(.2)
            if pid:
                # Accept only the ID actually allocated by this exact native
                # create response, never an arbitrary semantically equal row.
                from .forward_policy import read_projection
                allocated=[p for p in read_projection(remote.run) if p['pid']==pid]
                if len(allocated)==1 and legacy_allow(allocated[0])==value:
                    instance={'key':step['key'],'id':pid,'birth':str(allocated[0]['timestamp'])}
                    if instance not in self.policy_instances:self.policy_instances.append(instance)
            after=await self.snapshot()
            try:bind_created_instance(before,projected,after,step)
            except ValueError:continue
            if pid and after['objects'].get(step['key'],{}).get('instance',{}).get('id')!=pid:continue
            removed=[{'key':step['key'],'before':step['before']}] if op=='remove' else []
            if await self.verify(after,removed):
                result={'verified':True}
                if pid:result['allocated_instance']={'key':step['key'],**after['objects'][step['key']]['instance']}
                return result
        return {'verified':False}
