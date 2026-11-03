"""Unregistered receipt-bound mapping-name candidate; never infer ownership by name.

An authenticated coordinator must persist/claim the exact transaction before
dispatch. Original and replacement objects, box binding, and logical identity
remain in its private journal; the display label carries no ownership authority.
"""
import copy
import re
from . import forward_native as native
from .forward_metadata_experiment import MetadataExperimentAdapter
from .forward_transaction import build_plan
from .writes import digest


class DisplayNameAdapter(MetadataExperimentAdapter):
    def __init__(self,revision,template,original,display_name):
        native.NativeForwardAdapter.__init__(self,revision,template)
        spec=native.NativeForwardAdapter.mapping_spec(self,original)
        if spec!=template or spec['protocol']!='tcp' or spec['external_port'] not in (80,443) or spec['destination_port']!=spec['external_port']:
            raise ValueError('Exact HTTP/HTTPS mapping required')
        if not isinstance(display_name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}',display_name) or display_name!=display_name.strip() or display_name.startswith('mcp:'):
            raise ValueError('Bounded plain display name required')
        self.original=copy.deepcopy(original)
        self.variant={**original,'description':display_name}
        self.key='mapping:'+original['description']

    def mapping_spec(self,value):
        if value.get('description') in (self.original['description'],self.variant['description']):
            if value not in (self.original,self.variant):raise ValueError('Receipt-bound mapping drift')
            return native.NativeForwardAdapter.mapping_spec(self,{**value,'description':self.original['description']})
        return native.NativeForwardAdapter.mapping_spec(self,value)

    async def snapshot(self):
        state=await native.NativeForwardAdapter.snapshot(self)
        matches=[k for k,r in state['objects'].items() if r['kind']=='mapping' and r['value'].get('description')==self.variant['description']]
        if matches:
            if len(matches)!=1 or self.key in state['objects']:raise ValueError('Ambiguous display-name binding')
            key=matches[0];row=state['objects'][key]
            if row['value']!=self.variant:raise ValueError('Receipt-bound named object changed')
            state['objects'][self.key]=state['objects'].pop(key)
        return state

    async def preview(self,box,binding):
        plan=await super().preview(box,binding)
        # This is included in the immutable plan journal BEFORE any write.
        plan['metadata_receipt']={'version':1,'logical_key':self.key,
            'original':copy.deepcopy(self.original),'replacement':copy.deepcopy(self.variant),
            'revision':self.revision,'template':copy.deepcopy(self.template),
            'ownership':'exact private journal binding; display name is not authority'}
        plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'})
        return plan

    @classmethod
    def from_journal(cls,journals,ident,binding):
        seen=set()
        for _ in range(8):
            if ident in seen:raise ValueError('Provenance cycle')
            seen.add(ident)
            with journals.locked(ident,create=False) as session:
                if not session.events:raise ValueError('Missing durable provenance')
                plan=copy.deepcopy(session.events[0]['data']['plan'])
            if plan['binding']!=binding or digest({k:v for k,v in plan.items() if k!='digest'})!=plan['digest']:
                raise ValueError('Provenance binding changed')
            if 'metadata_receipt' in plan:break
            ident=plan.get('recovery_of')
            if not ident:raise ValueError('Missing durable provenance')
        else:raise ValueError('Provenance depth')
        r=plan['metadata_receipt']
        if r['version']!=1:raise ValueError('Provenance version')
        adapter=cls(r['revision'],r['template'],r['original'],r['replacement']['description'])
        if adapter.variant!=r['replacement'] or adapter.key!=r['logical_key']:raise ValueError('Provenance scope changed')
        return adapter
