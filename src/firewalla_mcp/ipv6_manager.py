"""Host-confirmed IPv6 policy lifecycle coordinator; transport injected by host.

Uses the shared private forwarding journal and durable single-use claims. No NAT
objects, IPv4 target address, implicit label adoption, or external issuer step.
"""
import copy
import secrets
import time

from .forward_journal import ForwardJournal
from .forward_transaction import ForwardTransaction, build_plan, transition
from .forward_dependencies import array
from .forward_policy import reject_duplicate
from .ipv6_adapter import template_checked, instance_checked
from .ipv6_policy import native_allow, validate, scope_disclosure
from .writes import digest


class IPv6Manager:
    def __init__(self,writes,adapter_factory):
        self.writes=writes;self.config=writes.config;self.adapter_factory=adapter_factory;self.plans={}
        self.enabled()

    def enabled(self):
        self.writes.enabled()
        if not getattr(self.config,'ipv6_policy_enabled',False):raise ValueError('IPv6 policy lifecycle disabled')
        if not self.config.forwarding_recovery_directory:raise ValueError('Private recovery directory required')
        ForwardJournal(self.config.forwarding_recovery_directory).root.root()

    def binding(self,box):
        return digest({'write_binding':self.writes.site_binding(box),'recovery_directory':self.config.forwarding_recovery_directory,
                       'ipv6_policy_enabled':getattr(self.config,'ipv6_policy_enabled',False),'contract':'ipv6_policy_only_v1'})

    def template(self,box,device,interface_uuid,maintenance_until):
        self.enabled();box=self.config.resolve(box)
        if box not in self.config.sites:raise ValueError('Unknown box')
        if type(maintenance_until) is not int or not time.time()<maintenance_until<=time.time()+300:raise ValueError('Fresh maintenance window within five minutes required')
        return box,template_checked({'kind':'ipv6_device_policy','device':device.upper(),'interface_uuid':interface_uuid,'maintenance_until':maintenance_until})

    def owned(self,box,template):
        journals=ForwardJournal(self.config.forwarding_recovery_directory);paths=list(journals.root.root().glob('*.journal'))
        if len(paths)>512:raise ValueError('Journal inventory bound')
        result=[]
        for path in paths:
            with journals.locked(path.stem,create=False) as session:
                if not session.events:continue
                plan=session.events[0]['data'].get('plan',{})
                if plan.get('box')!=box or plan.get('operation_scope')!='ipv6_policy_only':continue
                if plan.get('binding')!=self.binding(box) or digest({k:v for k,v in plan.items() if k!='digest'})!=plan.get('digest'):raise ValueError('Ownership provenance changed')
                old=template_checked(plan['template'])
                if old['device']!=template['device'] or old['interface_uuid']!=template['interface_uuid']:continue
                for event in session.events:
                    data=event['data']
                    if data.get('event')!='verified' or not data.get('instance'):continue
                    step=plan['steps'][data['index']]
                    if step['after'] is None:continue
                    record={'key':step['key'],'value':validate(step['after']['value']),'instance':instance_checked(data['instance'])}
                    if record not in result:result.append(record)
        if len(result)>256:raise ValueError('Ownership history bound')
        return result

    def adapter(self,box,template):
        return self.adapter_factory(self.config.sites[box].model_copy(deep=True),template,self.owned(box,template))

    def transaction(self,box,template):
        def claim(plan):
            self.writes.consume_approval(plan);self.writes.audit(plan['plan_id'],'host_requested_ipv6_policy',box)
        return ForwardTransaction(self.config.forwarding_recovery_directory,self.adapter(box,template),claim)

    def remember(self,plan,template,disclosures):
        now=time.time();self.plans={k:v for k,v in self.plans.items() if v['expires_at']>now}
        if len(self.plans)>=64:raise ValueError('IPv6 plan capacity')
        plan=copy.deepcopy(plan);plan['operation_scope']='ipv6_policy_only';plan['template']=copy.deepcopy(template)
        plan['disclosures']=copy.deepcopy(disclosures);plan['expires_at']=min(plan['expires_at'],template['maintenance_until'])
        plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'});self.plans[plan['plan_id']]=plan
        return copy.deepcopy(plan)

    async def inspect(self,box,device,interface_uuid,maintenance_until):
        box,template=self.template(box,device,interface_uuid,maintenance_until)
        async with self.writes.locks[box]:
            state=await self.adapter(box,template).snapshot()
            return {'owned_policies':[{'key':k,'fingerprint':digest(r),**r} for k,r in state['objects'].items() if k.startswith('policy:ipv6:')],
                    'total_policy_count':len(state['objects']),'environment':state['environment'],
                    'scope':'device-wide IPv6, including future addresses; no NAT', 'external_reachability':'unverified'}

    async def preview(self,box,device,interface_uuid,actions,removals,maintenance_until):
        box,template=self.template(box,device,interface_uuid,maintenance_until)
        if not isinstance(actions,list) or not isinstance(removals,list) or len(actions)>4 or len(removals)>4 or not actions and not removals:raise ValueError('One to four creates/removals required')
        async with self.writes.locks[box]:
            adapter=self.adapter(box,template);initial=await adapter.snapshot();state=copy.deepcopy(initial);steps=[];disclosures=[];selected=set()
            for selection in removals:
                if set(selection)!={'key','fingerprint'}:raise ValueError('Exact removal selection')
                key=selection['key'];row=state['objects'].get(key)
                if not key.startswith('policy:ipv6:') or key in selected or row is None or digest(row)!=selection['fingerprint']:raise ValueError('Owned removal identity changed')
                selected.add(key);pid=instance_checked(row['instance'])['id'];validate(row['value'])
                for p in adapter.policies:
                    if p.get('parentRgId') or p.get('targetRgId') or pid in array(p.get('affectedPids')):raise ValueError('Referenced or unresolved policy')
                disclosures.append({'operation':'remove',**scope_disclosure(row['value'])})
                if row['enabled']:
                    step={'operation':'disable','key':key,'before':row,'after':{**row,'enabled':False}};steps.append(step);state=transition(state,step);row=state['objects'][key]
                step={'operation':'remove','key':key,'before':row,'after':None};steps.append(step);state=transition(state,step)
            values=[]
            for action in actions:
                if set(action)!={'source_network','protocol','port'}:raise ValueError('Explicit IPv6 scope required')
                value=native_allow(template['device'],template['interface_uuid'],action['source_network'],action['protocol'],action['port'],secrets.token_hex(16))
                # Conservative: even a same-plan removal is not duplicate consent.
                reject_duplicate(adapter.policies,value)
                for prior in values:reject_duplicate([{**prior,'identity_complete':True}],value)
                values.append(value);key='policy:ipv6:'+value['description'][4:];row={'kind':'allow_policy','value':value,'enabled':False}
                for step in ({'operation':'create_disabled','key':key,'before':None,'after':row},
                             {'operation':'enable','key':key,'before':row,'after':{**row,'enabled':True}}):
                    steps.append(step);state=transition(state,step)
                disclosures.append({'operation':'create',**scope_disclosure(value)})
            plan=build_plan(box,self.binding(box),initial,steps,scope='native_ipv6_policy')
            return self.remember(plan,template,disclosures)

    async def apply(self,ident):
        self.enabled()
        if ident not in self.plans:raise ValueError('Unknown plan; preview recovery after restart')
        plan=copy.deepcopy(self.plans[ident]);box=plan['box'];template_checked(plan['template'])
        if plan.get('operation_scope')!='ipv6_policy_only':raise ValueError('IPv6 plan scope')
        async with self.writes.locks[box]:
            result=await self.transaction(box,plan['template']).execute(plan,self.binding(box))
            self.writes.audit(ident,result['outcome'],box);return result

    async def recover(self,ident,rollback,maintenance_until):
        self.enabled()
        if type(rollback) is not bool:raise ValueError('Explicit recovery direction')
        journal=ForwardJournal(self.config.forwarding_recovery_directory)
        with journal.locked(ident,create=False) as session:
            if not session.events:raise ValueError('Unknown transaction')
            old=copy.deepcopy(session.events[0]['data']['plan'])
        if old.get('operation_scope')!='ipv6_policy_only':raise ValueError('Not an IPv6 policy transaction')
        box,template=self.template(old['box'],old['template']['device'],old['template']['interface_uuid'],maintenance_until)
        if old['binding']!=self.binding(box):raise ValueError('Configuration changed')
        async with self.writes.locks[box]:
            plan=await self.transaction(box,template).recovery_preview(ident,self.binding(box),rollback=rollback)
            if plan.get('status')=='no_change':return plan
            return self.remember(plan,template,old.get('disclosures',[]))
