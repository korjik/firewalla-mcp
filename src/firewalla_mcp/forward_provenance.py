"""Private journal-derived mapping identity; labels never grant ownership."""
import copy
import re
from .forward_native import NativeForwardAdapter
from .forward_journal import ForwardJournal
from .writes import digest


def merge_receipts(receipts):
    if not isinstance(receipts,list) or len(receipts)>64:raise ValueError('Receipt bound')
    merged={}
    for r in receipts:
        if set(r)-{'successors'}!={'key','anchor','variants'} or not isinstance(r['variants'],list) or not 1<=len(r['variants'])<=8:
            raise ValueError('Receipt shape')
        anchor=r['anchor'];key=r['key']
        if key!='mapping:'+anchor.get('description','') or not re.fullmatch('mapping:mcp:[a-f0-9]{32}',key):raise ValueError('Receipt identity')
        base={k:v for k,v in anchor.items() if k not in ('description','_type')}
        if anchor.get('_type','port_forward')!='port_forward':raise ValueError('Receipt type')
        for v in r['variants']:
            if {k:x for k,x in v.items() if k not in ('description','_type')}!=base or v.get('_type','port_forward')!='port_forward':raise ValueError('Receipt scope changed')
            name=v.get('description')
            if name!=anchor['description'] and (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}',name) or name!=name.strip()):raise ValueError('Display name')
        if anchor not in r['variants']:raise ValueError('Receipt anchor missing')
        successors=r.get('successors',[])
        if not isinstance(successors,list) or len(successors)>8:raise ValueError('Successor bound')
        for v in successors:
            if {k:x for k,x in v.items() if k not in ('description','_type')}!=base or v.get('_type','port_forward')!='port_forward' or not re.fullmatch('mcp:[a-f0-9]{32}',v.get('description','')) or v['description']==anchor['description']:
                raise ValueError('Exact successor scope required')
        old=merged.setdefault(key,copy.deepcopy(r))
        if old['anchor']!=anchor:raise ValueError('Conflicting provenance')
        for v in r['variants']:
            if v not in old['variants']:old['variants'].append(copy.deepcopy(v))
        if len(old['variants'])>8:raise ValueError('Receipt history bound')
        for v in successors:
            if v not in old.setdefault('successors',[]):old['successors'].append(copy.deepcopy(v))
        if len(old.get('successors',[]))>8:raise ValueError('Successor history bound')
    values=list(merged.values())
    for index,r in enumerate(values):
        if any(v in other["variants"] for other in values[index+1:] for v in r["variants"]):
            raise ValueError("Ambiguous historical display identity")
    return values


def load_receipts(directory,box,binding):
    journals=ForwardJournal(directory);root=journals.root.root()
    paths=list(root.glob('*.journal'))
    if len(paths)>512:raise ValueError('Recovery inventory bound')
    receipts=[]
    for path in paths:
        with journals.locked(path.stem,create=False) as session:
            if not session.events:continue
            plan=session.events[0]['data'].get('plan',{})
            if plan.get('box')!=box or 'metadata_receipts' not in plan:continue
            if not any(e['data'].get('event')=='dispatch' for e in session.events):continue
            if plan.get('binding')!=binding or digest({k:v for k,v in plan.items() if k!='digest'})!=plan.get('digest'):
                raise ValueError('Stored mapping provenance binding changed')
            receipts.extend(plan['metadata_receipts'])
    return merge_receipts(receipts)


class ReceiptNativeAdapter(NativeForwardAdapter):
    def __init__(self,revision,template,receipts):
        super().__init__(revision,template)
        self.receipts=merge_receipts(receipts)
        # Reject forged/unsupported anchor shape before inspecting or mutating.
        for r in self.receipts:super().mapping_spec(r['anchor'])

    def successor_value(self,receipt,value,seen=()):
        if receipt['key'] in seen or len(seen)>=64:raise ValueError('Successor provenance cycle/depth')
        if value in receipt.get('successors',[]):return True
        for other in self.receipts:
            if other['anchor'] in receipt.get('successors',[]):
                if value in other['variants'] or self.successor_value(other,value,seen+(receipt['key'],)):return True
        return False

    def mapping_spec(self,value):
        matches=[r for r in self.receipts if value in r['variants']]
        if len(matches)>1:raise ValueError('Ambiguous receipt')
        if matches:return super().mapping_spec({**value,'description':matches[0]['anchor']['description']})
        return super().mapping_spec(value)

    async def snapshot(self):
        state=await super().snapshot()
        for r in self.receipts:
            matches=[k for k,v in state['objects'].items() if v['kind']=='mapping' and v['value'] in r['variants']]
            # A label reused on a different tuple is not adopted. A changed
            # exact native tuple is blocked rather than silently losing provenance.
            anchor=r['anchor']
            relevant=[v['value'] for v in state['objects'].values() if v['kind']=='mapping' and all(v['value'].get(k)==anchor.get(k) for k in ('wanUUID','protocol','dport','toIP','toPort'))]
            if len(relevant)==1 and self.successor_value(r,relevant[0]):continue
            if relevant and (len(matches)!=1 or len(relevant)!=1):raise ValueError('Receipt-bound mapping changed or ambiguous')
            if matches:
                key=matches[0]
                if key!=r['key']:
                    if r['key'] in state['objects']:raise ValueError('Receipt key conflict')
                    state['objects'][r['key']]=state['objects'].pop(key)
        return state

    async def verify(self,state,removed=()):
        remaining=[]
        for item in removed:
            current=state['objects'].get(item['key'])
            allowed=[r for r in self.receipts if r['key']==item['key']]
            if current and allowed and current['kind']=='mapping' and item['before']['kind']=='mapping' and current['enabled'] is True and item['before']['enabled'] is True and current['value'] in allowed[0]['variants'] and item['before']['value'] in allowed[0]['variants']:
                continue
            remaining.append(item)
        return await super().verify(state,removed=remaining)
