"""Opt-in MCP coordinator for native forwarding lifecycle plans."""
import copy
import secrets
import time
from .forward_transport import LifecycleSSH
from .forward_transaction import ForwardTransaction
from .forward_lifecycle import preview
from .forward_journal import ForwardJournal
from .writes import digest

class ForwardManager:
    def __init__(self,writes,adapter_factory=LifecycleSSH):
        self.writes=writes;self.config=writes.config;self.adapter_factory=adapter_factory;self.plans={}
        self.enabled()
    def enabled(self):
        self.writes.enabled()
        if not self.config.forwarding_lifecycle_enabled:raise ValueError('Forwarding lifecycle disabled')
        if not self.config.forwarding_recovery_directory:raise ValueError('Persistent recovery storage required')
        ForwardJournal(self.config.forwarding_recovery_directory).root.root()
    def binding(self,box):
        return digest({'write_binding':self.writes.site_binding(box),'recovery_directory':self.config.forwarding_recovery_directory,
                       'lifecycle_enabled':self.config.forwarding_lifecycle_enabled})
    def template(self,box,device,destination,interface,maintenance_until):
        self.enabled();box=self.config.resolve(box)
        if type(maintenance_until) is not int or not time.time()<maintenance_until<=time.time()+600:raise ValueError('Explicit maintenance window within ten minutes required')
        spec={'kind':'managed_interface_forward','device':device.upper(),'destination_ip':destination,'interface_uuid':interface,
              'protocol':'tcp','external_port':1,'destination_port':1,'owner_token':secrets.token_hex(16),'maintenance_until':maintenance_until}
        self.writes.validate(box,spec)
        return box,spec
    def remember(self,plan,template,disclosures=None):
        now=time.time();self.plans={k:v for k,v in self.plans.items() if v['expires_at']>now}
        if len(self.plans)>=64:raise ValueError('Lifecycle plan capacity')
        plan=copy.deepcopy(plan);plan['template']=copy.deepcopy(template)
        plan['expires_at']=min(plan['expires_at'],template['maintenance_until'])
        if disclosures is not None:plan['disclosures']=copy.deepcopy(disclosures)
        plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'})
        self.plans[plan['plan_id']]=plan
        return copy.deepcopy(plan)
    async def inspect(self,box,device,destination,interface,maintenance_until):
        box,spec=self.template(box,device,destination,interface,maintenance_until)
        async with self.writes.locks[box]:
            adapter=self.adapter_factory(self.config.sites[box].model_copy(deep=True),spec)
            state=await adapter.snapshot()
            return {'objects':[{'key':key,'fingerprint':digest(row),**row} for key,row in state['objects'].items()],
                    'environment_fingerprint':digest(state['environment']),
                    'warning':'Inventory is not ownership proof or effective reachability. Exact removal selections require a fresh confirmed plan.'}
    async def preview(self,box,device,destination,interface,actions,removals,maintenance_until):
        box,spec=self.template(box,device,destination,interface,maintenance_until)
        binding=self.binding(box)
        async with self.writes.locks[box]:
            adapter=self.adapter_factory(self.config.sites[box].model_copy(deep=True),spec)
            plan=await preview(adapter,box,binding,actions,removals)
            if binding!=self.binding(box):raise ValueError('Configuration changed during preview')
            if plan.get('status')=='no_change':return plan
            return self.remember(plan,spec)
    def transaction(self,box,template):
        adapter=self.adapter_factory(self.config.sites[box].model_copy(deep=True),template)
        def claim(plan):
            self.writes.consume_approval(plan)
            self.writes.audit(plan['plan_id'],'host_requested_forward_lifecycle',box)
        return ForwardTransaction(self.config.forwarding_recovery_directory,adapter,claim)
    async def apply(self,ident):
        self.enabled()
        if ident not in self.plans:raise ValueError('Unknown lifecycle plan; preview recovery after a restart')
        plan=copy.deepcopy(self.plans[ident]);box=plan['box']
        self.writes.validate(box,plan['template'])
        async with self.writes.locks[box]:
            result=await self.transaction(box,plan['template']).execute(plan,self.binding(box))
            self.writes.audit(ident,result['outcome'],box)
            return result
    async def recover(self,ident,rollback,maintenance_until):
        self.enabled()
        journal=ForwardJournal(self.config.forwarding_recovery_directory)
        with journal.locked(ident,create=False) as session:
            if not session.events:raise ValueError('Unknown lifecycle transaction')
            old=copy.deepcopy(session.events[0]['data']['plan'])
        box=old['box'];template=old['template']
        if self.binding(box)!=old['binding']:raise ValueError('Configuration changed; recovery requires reviewed migration')
        if type(maintenance_until) is not int or not time.time()<maintenance_until<=time.time()+600:raise ValueError('Fresh maintenance window required')
        template['maintenance_until']=maintenance_until
        self.writes.validate(box,template)
        async with self.writes.locks[box]:
            plan=await self.transaction(box,template).recovery_preview(ident,self.binding(box),rollback=rollback)
            if plan.get('status')=='no_change':return plan
            return self.remember(plan,template,old.get('disclosures',[]))
