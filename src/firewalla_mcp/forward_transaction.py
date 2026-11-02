"""Bounded forwarding execution/recovery core, not an MCP or router adapter.

Adapter snapshots are complete canonical objects plus enforcement evidence.
No caller-supplied consent boolean: a host-confirmed plan must pass the caller's
existing authenticated WriteManager checks and durable single-use claim.
"""
import copy
import secrets
import time
from .writes import digest
from .forward_journal import ForwardJournal

OPS={'create_disabled','create','enable','disable','remove','restore'}


def checked_state(state):
    if not isinstance(state,dict) or set(state)!={'objects','environment'} or not isinstance(state['objects'],dict):
        raise ValueError('Complete canonical snapshot required')
    if len(state['objects'])>768:raise ValueError('Inventory bound')
    for key,row in state['objects'].items():
        if not isinstance(key,str) or not isinstance(row,dict) or set(row)-{'kind','value','enabled','instance'} or not {'kind','value','enabled'}<=set(row) or row['kind'] not in ('mapping','allow_policy') or type(row['enabled']) is not bool or not isinstance(row['value'],dict):
            raise ValueError('Canonical object shape')
    return copy.deepcopy(state)


def transition(state,step):
    result=checked_state(state)
    if not isinstance(step,dict) or set(step)!={'operation','key','before','after'} or step['operation'] not in OPS or not isinstance(step['key'],str):
        raise ValueError('Step shape')
    key=step['key'];before=step['before'];after=step['after'];op=step['operation']
    existing=result['objects'].get(key)
    if existing!=before:
        # Only an allocated instance on the same exact logical object may be
        # carried through later steps. Execution separately binds the complete
        # previous observed state, preventing replacement between steps.
        if existing is None or before is None or 'instance' in before or {k:v for k,v in existing.items() if k!='instance'}!=before:
            raise ValueError('Step precondition drift')
        before=copy.deepcopy(existing)
        if after is not None:after={**after,'instance':existing['instance']}

    if before is None and after is None:raise ValueError('Empty step')
    if op in ('create','create_disabled'):
        if before is not None or after is None:raise ValueError('Create identity')
        if op=='create_disabled' and (after['kind']!='allow_policy' or after['enabled']):raise ValueError('Disabled creation required')
        if op=='create' and after['kind']!='mapping':raise ValueError('Policy cannot be created enabled')
    elif op in ('enable','disable'):
        if before is None or after is None or before['kind']!='allow_policy' or {**before,'enabled':op=='enable'}!=after or before==after:
            raise ValueError('Activation scope changed')
    elif op=='remove':
        if before is None or after is not None:raise ValueError('Removal identity')
        if before['kind']=='allow_policy' and before['enabled']:raise ValueError('Disable policy before removal')
    elif op=='restore':
        # Restore may only reconstruct exact absent disabled policy or mapping.
        if before is not None or after is None or (after['kind']=='allow_policy' and after['enabled']):raise ValueError('Unsafe restoration')
    if after is None:del result['objects'][key]
    else:result['objects'][key]=copy.deepcopy(after)
    return checked_state(result)


def bind_created_instance(before,projected,observed,step):
    """Accept only native metadata allocated for this one newly created object."""
    if observed==projected:return observed
    if step['operation'] not in ('create_disabled','create','restore') or step['before'] is not None:
        raise ValueError('Unexpected post-state')
    key=step['key'];row=observed['objects'].get(key,{})
    instance=row.get('instance')
    if not isinstance(instance,dict) or set(instance)!={'id','birth'} or not all(isinstance(v,str) and 0<len(v)<=80 for v in instance.values()):
        raise ValueError('Native allocation identity missing')
    if any(r.get('instance',{}).get('id')==instance['id'] for r in before['objects'].values()):
        raise ValueError('Native allocation returned existing identity')
    candidate=copy.deepcopy(projected)
    candidate['objects'][key]['instance']=copy.deepcopy(instance)
    if candidate!=observed:raise ValueError('Unexpected fields or concurrent state change')
    return observed


def build_plan(box,binding,initial,steps,*,recovery_of=None,now=None,scope="native_forwarding_only"):
    if scope not in ("native_forwarding_only","native_forwarding_reset","native_ipv6_policy"):raise ValueError("Plan scope")
    bound=32 if scope=="native_forwarding_reset" else 16
    now=time.time() if now is None else now
    if not isinstance(steps,list) or not 1<=len(steps)<=bound:raise ValueError('Bounded steps required')
    state=checked_state(initial)
    for step in steps:state=transition(state,step)
    plan={'plan_id':secrets.token_hex(16),'box':box,'binding':binding,'initial':copy.deepcopy(initial),
          'steps':copy.deepcopy(steps),'expires_at':now+(600 if scope=='native_forwarding_reset' else 300),'recovery_of':recovery_of,
          'atomic':False,'confirmation':'trusted_mcp_host','scope':scope}
    plan['digest']=digest(plan)
    return plan


def verify_plan(plan,binding,now):
    if digest({k:v for k,v in plan.items() if k!='digest'})!=plan['digest'] or binding!=plan['binding']:
        raise ValueError('Plan or configuration changed')
    if now>=plan['expires_at']:raise ValueError('Plan expired')
    if plan['confirmation']!='trusted_mcp_host':raise ValueError('Confirmation mode')
    state=checked_state(plan['initial'])
    if plan['scope'] not in ('native_forwarding_only','native_forwarding_reset','native_ipv6_policy'):raise ValueError('Plan scope')
    if not 1<=len(plan['steps'])<=(32 if plan['scope']=='native_forwarding_reset' else 16):raise ValueError('Step bound')
    for step in plan['steps']:state=transition(state,step)


def active_absences(plan,state):
    result=[]
    for item in plan.get('removed_requirements',[]):
        current=state['objects'].get(item['key'])
        # A deliberately restored identical mapping now has its own positive
        # proof. Old policy IDs remain absent even when a new ID is restored.
        if item['before']['kind']=='mapping' and current==item['before']:continue
        result.append(item)
    return result


class ForwardTransaction:
    def __init__(self,directory,adapter,claim,clock=time.time):
        self.journals=ForwardJournal(directory);self.adapter=adapter;self.claim=claim;self.clock=clock

    async def execute(self,plan,binding):
        verify_plan(plan,binding,self.clock())
        execution_proofs={'removed_requirements':copy.deepcopy(plan.get('removed_requirements',[]))}
        with self.journals.locked(digest({'box_lock':plan['box']})[:32]), self.journals.locked(plan['plan_id']) as journal:
            if journal.events:raise ValueError('Consumed or interrupted transaction; obtain recovery preview')
            state=checked_state(await self.adapter.snapshot())
            if state!=plan['initial']:raise ValueError('Initial state changed')
            requirements=active_absences(execution_proofs,state)
            if requirements and not await self.adapter.verify(state,removed=requirements):raise ValueError('Recovery absence proof changed')
            # Journal persistence precedes the single-use claim and all mutations.
            journal.append({'event':'plan','plan':plan})
            self.claim(plan)
            if plan['recovery_of']:
                with self.journals.locked(plan['recovery_of']) as parent:
                    if any(e['data']['event']=='recovery_claimed' for e in parent.events):
                        raise ValueError('Recovery already claimed; inspect its child transaction')
                    parent.append({'event':'recovery_claimed','child':plan['plan_id']})
            for index,step in enumerate(plan['steps']):
                if self.clock()>=plan['expires_at']:
                    journal.append({'event':'stopped','reason':'expired','next':index})
                    return {'outcome':'partial_expired','completed':index,'transaction_id':plan['plan_id']}
                current=checked_state(await self.adapter.snapshot())
                if current!=state:
                    journal.append({'event':'stopped','reason':'drift','next':index})
                    return {'outcome':'stale','completed':index,'transaction_id':plan['plan_id']}
                requirements=active_absences(execution_proofs,current)
                if requirements and not await self.adapter.verify(current,removed=requirements):
                    journal.append({'event':'stopped','reason':'absence_proof_changed','next':index})
                    return {'outcome':'stale','completed':index,'transaction_id':plan['plan_id']}
                projected=transition(state,step)
                journal.append({'event':'dispatch','index':index,'before':digest(state),'after':digest(projected)})
                # No automatic retry. Adapter also checks expiry immediately before
                # dispatch and verifies exact native identities and enforcement.
                try:
                    if self.clock()>=plan['expires_at']:
                        journal.append({'event':'not_dispatched','reason':'expired_before_dispatch','index':index})
                        return {'outcome':'partial_expired','completed':index,'transaction_id':plan['plan_id']}
                    result=await self.adapter.mutate(copy.deepcopy(step),digest(state),plan['expires_at'])
                    observed=checked_state(await self.adapter.snapshot())
                except Exception:
                    journal.append({'event':'uncertain','index':index})
                    return {'outcome':'uncertain','completed':index,'transaction_id':plan['plan_id']}
                try:observed=bind_created_instance(state,projected,observed,step)
                except ValueError:result={'verified':False}
                if step['after'] is None:
                    execution_proofs['removed_requirements'].append({'key':step['key'],'before':copy.deepcopy(state['objects'][step['key']])})
                requirements=active_absences(execution_proofs,observed)
                if requirements and not await self.adapter.verify(observed,removed=requirements):result={'verified':False}
                if result.get('verified') is not True:
                    journal.append({'event':'uncertain','index':index})
                    return {'outcome':'uncertain','completed':index,'transaction_id':plan['plan_id']}
                journal.append({'event':'verified','index':index,'state':digest(observed),
                                'instance':observed['objects'].get(step['key'],{}).get('instance')})
                state=observed
            journal.append({'event':'complete','state':digest(state)})
            return {'outcome':'applied','completed':len(plan['steps']),'transaction_id':plan['plan_id'],
                    'external_reachability':'unverified'}

    async def recovery_preview(self,ident,binding,*,rollback=False):
        with self.journals.locked(ident,create=False) as journal:
            if not journal.events:raise ValueError('Unknown transaction')
            if any(e['data']['event']=='recovery_claimed' for e in journal.events):
                raise ValueError('Recovery already claimed; inspect its child transaction')
            original=journal.events[0]['data']['plan']
            if original['binding']!=binding or digest({k:v for k,v in original.items() if k!='digest'})!=original['digest']:
                raise ValueError('Recovery binding mismatch')
            current=checked_state(await self.adapter.snapshot())
            states=[checked_state(original['initial'])]
            verified_states={e['data']['index']:e['data'] for e in journal.events if e['data']['event']=='verified'}
            for index,step in enumerate(original['steps']):
                projected=transition(states[-1],step)
                if index in verified_states:
                    record=verified_states[index]
                    observed=copy.deepcopy(projected)
                    if record['instance'] is not None and step['after'] is not None:
                        observed['objects'][step['key']]['instance']=record['instance']
                    projected=bind_created_instance(states[-1],projected,observed,step)
                    if digest(projected)!=record['state']:raise ValueError('Journal state verification mismatch')
                states.append(projected)
            verified=[e['data']['index']+1 for e in journal.events if e['data']['event']=='verified']
            done=max(verified,default=0)
            not_sent={e['data']['index'] for e in journal.events if e['data']['event']=='not_dispatched'}
            dispatched=[e['data']['index'] for e in journal.events if e['data']['event']=='dispatch' and e['data']['index'] not in not_sent]
            # Only the last dispatch may be uncertain; never infer progress over
            # unsubmitted steps just because an external writer produced it.
            possible={done}
            if dispatched and max(dispatched)==done:possible.add(done+1)
            if done+1 in possible:
                try:states[done+1]=bind_created_instance(states[done],states[done+1],current,original['steps'][done])
                except ValueError:pass
            matches=[n for n in possible if states[n]==current]
            if len(matches)!=1:raise ValueError('Ambiguous or changed state; recovery requires inspection')
            n=matches[0]
            if dispatched and max(dispatched)==done and n==done:
                raise ValueError('Uncertain dispatch still at prior state; enforcement absence cannot prove the native queue will not execute later. Inspect queue/outcome before a new independent plan.')
            removed=[{'key':step['key'],'before':states[index]['objects'][step['key']]}
                     for index,step in enumerate(original['steps'][:n])
                     if step['after'] is None and step['key'] not in current['objects']]
            removed=original.get('removed_requirements',[])+removed
            removed=[v for i,v in enumerate(removed) if v not in removed[:i]]
            proof_plan={'removed_requirements':removed}
            if not await self.adapter.verify(states[n],removed=active_absences(proof_plan,states[n])):
                raise ValueError('Interrupted step enforcement unproven')
            if rollback:
                steps=[];state=current
                for old in reversed(original['steps'][:n]):
                    key=old['key'];before=state['objects'].get(key);after=old['before']
                    if after is not None and before is not None and 'instance' in before:after={**after,'instance':before['instance']}
                    if before is None:
                        op='restore'
                    elif after is None:
                        op='remove'
                    else:op='enable' if after['enabled'] else 'disable'
                    step={'operation':op,'key':key,'before':before,'after':after}
                    state=transition(state,step);steps.append(step)
                # Remove disabled companion policies before their NAT entries;
                # restore NAT before re-enabling any restored allowance.
                def order(step):
                    kind=(step['before'] or step['after'])['kind']
                    if step['operation']=='disable':return 0
                    if step['operation']=='remove':return 1 if kind=='allow_policy' else 2
                    if step['operation']=='restore':return 3 if kind=='mapping' else 4
                    return 5
                steps.sort(key=order)
                restored={s['key'] for s in steps if s['operation']=='restore'}
                for step in steps:
                    if step['key'] in restored:
                        for field in ('before','after'):
                            if step[field] is not None:step[field]={k:v for k,v in step[field].items() if k!='instance'}
            else:steps=original['steps'][n:]
            if not steps:return {'status':'no_change','transaction_id':ident,'completed':n}
            plan=build_plan(original['box'],binding,current,steps,recovery_of=ident,now=self.clock(),scope=original['scope'])
            plan['removed_requirements']=removed
            plan['digest']=digest({k:v for k,v in plan.items() if k!='digest'})
            return plan
