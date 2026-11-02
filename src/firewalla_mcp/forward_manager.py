"""Opt-in MCP coordinator for native forwarding lifecycle plans."""
import copy
import secrets
import time
from .forward_transport import LifecycleSSH
from .forward_transaction import ForwardTransaction
from .forward_lifecycle import preview
from .forward_journal import ForwardJournal
from .writes import digest
from .forward_provenance import load_receipts,merge_receipts,ReceiptNativeAdapter
from .forward_native import NativeForwardAdapter
from .forward_transaction import build_plan
from .forward_dependencies import require_mapping_removal

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
    def adapter(self,box,spec,extra=()):
        receipts=merge_receipts(load_receipts(self.config.forwarding_recovery_directory,box,self.binding(box))+list(extra))
        receipts=[r for r in receipts if all(r['anchor'].get(k)==spec[v] for k,v in [('toMac','device'),('toIP','destination_ip'),('wanUUID','interface_uuid')])]
        adapter=self.adapter_factory(self.config.sites[box].model_copy(deep=True),spec)
        if receipts:
            if isinstance(adapter,NativeForwardAdapter):adapter=ReceiptNativeAdapter(adapter.revision,spec,receipts)
            else:adapter.receipts=receipts
        return adapter
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
            adapter=self.adapter(box,spec)
            state=await adapter.snapshot()
            return {'objects':[{'key':key,'fingerprint':digest(row),**row} for key,row in state['objects'].items()],
                    'environment_fingerprint':digest(state['environment']),
                    'warning':'Inventory is not ownership proof or effective reachability. Exact removal selections require a fresh confirmed plan.'}
    async def preview(self,box,device,destination,interface,actions,removals,maintenance_until):
        box,spec=self.template(box,device,destination,interface,maintenance_until)
        binding=self.binding(box)
        async with self.writes.locks[box]:
            adapter=self.adapter(box,spec)
            plan=await preview(adapter,box,binding,actions,removals)
            if binding!=self.binding(box):raise ValueError('Configuration changed during preview')
            if plan.get('status')=='no_change':return plan
            receipts=copy.deepcopy(getattr(adapter,'receipts',[]))
            for receipt in receipts:
                removed=any(s['key']==receipt['key'] and s['operation']=='remove' for s in plan['steps'])
                for step in plan['steps']:
                    if step['operation']!='create' or step['after']['kind']!='mapping':continue
                    value=step['after']['value'];anchor=receipt['anchor']
                    if {k:v for k,v in value.items() if k not in ('description','_type')}=={k:v for k,v in anchor.items() if k not in ('description','_type')}:
                        if not removed:raise ValueError('Historical mapping tuple requires same-plan exact replacement; separate reuse unsupported')
                        receipt.setdefault('successors',[]).append(value)
            if receipts:plan['metadata_receipts']=merge_receipts(receipts)
            return self.remember(plan,spec)
    def transaction(self,box,template,receipts=()):
        adapter=self.adapter(box,template,receipts)
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
            result=await self.transaction(box,plan['template'],plan.get('metadata_receipts',[])).execute(plan,self.binding(box))
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
            plan=await self.transaction(box,template,old.get('metadata_receipts',[])).recovery_preview(ident,self.binding(box),rollback=rollback)
            if plan.get('status')=='no_change':return plan
            if old.get('metadata_receipts'):plan['metadata_receipts']=old['metadata_receipts']
            return self.remember(plan,template,old.get('disclosures',[]))

    async def preview_metadata(self,box,device,destination,interface,changes,maintenance_until):
        box,spec=self.template(box,device,destination,interface,maintenance_until)
        if not isinstance(changes,list) or not 1<=len(changes)<=2:raise ValueError('One or two exact metadata changes')
        async with self.writes.locks[box]:
            adapter=self.adapter(box,spec);initial=await adapter.snapshot();steps=[];receipts=list(getattr(adapter,'receipts',[]));seen=set();disclosures=[]
            maps=[r['value'] for r in initial['objects'].values() if r['kind']=='mapping']
            for change in changes:
                if set(change)!={'key','fingerprint','display_name','remove_default_type'} or type(change['remove_default_type']) is not bool:raise ValueError('Explicit metadata fields required')
                key=change['key'];row=initial['objects'].get(key)
                if key in seen or row is None or row['kind']!='mapping' or digest(row)!=change['fingerprint']:raise ValueError('Exact metadata selection changed')
                seen.add(key);selected=adapter.mapping_spec(row['value'])
                if selected['protocol']!='tcp' or selected['external_port'] not in (80,443) or selected['destination_port']!=selected['external_port']:raise ValueError('HTTP/HTTPS metadata only')
                require_mapping_removal(row['value'],maps)
                value=copy.deepcopy(row['value']);name=change['display_name']
                if not isinstance(name,str):raise ValueError('Explicit display name')
                value['description']=name
                if change['remove_default_type']:value.pop('_type',None)
                if value==row['value']:raise ValueError('No metadata change')
                if any(r!=row['value'] and r.get('description')==name for r in maps):raise ValueError('Ambiguous display name')
                prior=next((r for r in receipts if r['key']==key),None)
                anchor=prior['anchor'] if prior else row['value']
                receipts=merge_receipts(receipts+[{'key':key,'anchor':anchor,'variants':[anchor,row['value'],value]}])
                after={**row,'value':value}
                steps.extend([{'operation':'remove','key':key,'before':row,'after':None},{'operation':'create','key':key,'before':None,'after':after}])
                disclosures.append({'key':key,'display_name_before':row['value']['description'],'display_name_after':name,'remove_default_type':change['remove_default_type'],'interruption':'Native remove/recreate; may remain interrupted on failure','policy_changes':False})
            checked=self.adapter(box,spec,receipts)
            if await checked.snapshot()!=initial or not await checked.verify(initial):raise ValueError('Metadata baseline or enforcement changed')
            plan=build_plan(box,self.binding(box),initial,steps);plan['metadata_receipts']=receipts
            return self.remember(plan,spec,disclosures)
