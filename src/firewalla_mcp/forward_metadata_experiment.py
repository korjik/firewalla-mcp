"""Unregistered TCP80 metadata experiment; no CLI, MCP tool, or deployed gate.

Uses the existing journal/host-claim transaction core. Only a previously bound
mapping may change between explicit and implicit native port_forward type.
No direct Redis writes, policy mutations, automatic retries or auto-restoration.
"""
import asyncio
import copy
import time

from . import forward_native as native
from .forward_transaction import build_plan, transition
from .writes import digest


class MetadataExperimentAdapter(native.NativeForwardAdapter):
    def __init__(self, revision, template, original):
        super().__init__(revision, template)
        spec=super().mapping_spec(original)
        if original.get('_type')!='port_forward':raise ValueError('Explicit type required for experiment')
        if spec['protocol']!='tcp' or spec['external_port']!=80 or spec['destination_port']!=80:
            raise ValueError('Experiment is TCP80 to TCP80 only')
        if spec!=template:raise ValueError('Exact template binding required')
        self.original=copy.deepcopy(original)
        self.variant={k:v for k,v in original.items() if k!='_type'}
        self.key='mapping:'+original['description']

    def mapping_spec(self, value):
        if value.get('description')==self.original['description']:
            if value not in (self.original,self.variant):raise ValueError('Experiment metadata drift')
            return super().mapping_spec({**value,'_type':'port_forward'})
        return super().mapping_spec(value)

    def structural(self,value,maps):
        # Native find treats missing type and explicit port_forward identically.
        # Normalize only this exact selected row for the existing strict proof.
        self.mapping_spec(value)
        normalized={**value,'_type':'port_forward'}
        candidates=[normalized if row==value else row for row in maps]
        return native.require_mapping_removal(normalized,candidates)

    async def verify(self,state,removed=()):
        remaining=[]
        for item in removed:
            current=state['objects'].get(item['key'])
            if item['key']==self.key and current is not None:
                before=item['before']
                if (before['kind']!='mapping' or current['kind']!='mapping'
                        or before['enabled'] is not True or current['enabled'] is not True
                        or before['value'] not in (self.original,self.variant)
                        or current['value'] not in (self.original,self.variant)):
                    return False
                # Exact same native identity restored in its other metadata form;
                # normal positive kernel proof below replaces the absence proof.
                continue
            remaining.append(item)
        return await super().verify(state,removed=remaining)

    async def preview(self,box,binding):
        state=await self.snapshot();row=state['objects'].get(self.key)
        expected={'kind':'mapping','value':self.original,'enabled':True}
        if row!=expected:raise ValueError('Original experiment identity changed')
        self.structural(self.original,[v['value'] for v in state['objects'].values() if v['kind']=='mapping'])
        if not await self.verify(state):raise ValueError('Initial enforcement not verified')
        after={**expected,'value':self.variant}
        return build_plan(box,binding,state,[
            {'operation':'remove','key':self.key,'before':expected,'after':None},
            {'operation':'create','key':self.key,'before':None,'after':after}])

    async def mutate(self,step,expected,expires_at):
        self.guard()
        before=await self.snapshot()
        if digest(before)!=expected:raise ValueError('State drift')
        if step['key']!=self.key or step['operation'] not in ('remove','create','restore'):
            raise ValueError('Experiment permits selected mapping only')
        row=step['before'] if step['operation']=='remove' else step['after']
        if row is None or row['kind']!='mapping' or row['enabled'] is not True:
            raise ValueError('Experiment mapping state')
        value=row['value']
        if value not in (self.original,self.variant):raise ValueError('Experiment metadata drift')
        spec=self.mapping_spec(value)
        projected=transition(before,step)
        snapshot=native.remote.forward_snapshot(spec)
        removing=step['operation']=='remove'
        if removing:
            self.structural(value,snapshot['maps'])
            owned=[r for r in snapshot['maps'] if r.get('description') in (self.original['description'],self.variant['description'])]
            if owned!=[value] or len(snapshot['collisions'])!=1:
                raise ValueError('Mapping identity drift')
            evidence=native.remote.forward_kernel_evidence(spec)
            if not evidence['nat_rule_observed'] or not evidence['vpn_ingress_link_observed']:
                raise ValueError('Initial NAT enforcement missing')
            if not native.hairpin_evidence(native.remote.run,value):raise ValueError('Hairpin missing')
        elif snapshot['collisions'] or snapshot['owned']:
            raise ValueError('Mapping conflict')
        payload=copy.deepcopy(value);payload['state']=not removing
        now=time.time()
        if not now<min(expires_at,self.template['maintenance_until'])<=now+600:
            raise ValueError('Maintenance/approval expired')
        native.remote.management_request('set','policy','0.0.0.0',{'portforward':payload})
        end=time.monotonic()+min(4,max(0,expires_at-time.time()))
        while time.monotonic()<end:
            await asyncio.sleep(.2)
            after=await self.snapshot()
            if after!=projected:continue
            if removing and (native.remote.forward_kernel_evidence(spec)['nat_rule_observed']
                             or native.hairpin_evidence(native.remote.run,value)):continue
            if await self.verify(after):return {'verified':True}
        return {'verified':False}
