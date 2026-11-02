import copy
import pytest
from firewalla_mcp.forward_transaction import ForwardTransaction,build_plan,transition
from firewalla_mcp.writes import digest

INITIAL={'objects':{},'environment':{'source_contract':'reviewed'}}
POLICY={'kind':'allow_policy','value':{'source':'203.0.113.0/24','port':443},'enabled':False}
MAPPING={'kind':'mapping','value':{'destination':'192.0.2.2','port':443},'enabled':True}
STEPS=[{'operation':'create_disabled','key':'policy','before':None,'after':POLICY},
       {'operation':'create','key':'mapping','before':None,'after':MAPPING},
       {'operation':'enable','key':'policy','before':POLICY,'after':{**POLICY,'enabled':True}}]

class Adapter:
    def __init__(self):self.state=copy.deepcopy(INITIAL);self.calls=[];self.fail=None;self.proven=True
    async def snapshot(self):return copy.deepcopy(self.state)
    async def mutate(self,step,expected,expiry):
        assert expected==digest(self.state)
        self.calls.append(step)
        if self.fail=='before':raise OSError('connection lost')
        self.state=transition(self.state,step)
        if self.fail=='after':raise OSError('response lost')
        return {'verified':self.proven}
    async def verify(self,state,removed=()):return self.proven and state==self.state

@pytest.fixture
def setup(tmp_path):
    path=tmp_path/'journal';path.mkdir(mode=0o700)
    adapter=Adapter();claimed=set()
    def claim(plan):
        if plan['plan_id'] in claimed:raise ValueError('replay')
        claimed.add(plan['plan_id'])
    tx=ForwardTransaction(str(path),adapter,claim)
    plan=build_plan('router-a','binding',INITIAL,STEPS)
    return tx,adapter,plan,claim

async def test_ordered_complete_and_restart_rollback(setup):
    tx,a,p,claim=setup
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
    fresh=ForwardTransaction(tx.journals.root.directory,a,claim)
    rollback=await fresh.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert [s['operation'] for s in rollback['steps']]==['disable','remove','remove']
    assert (await fresh.execute(rollback,'binding'))['outcome']=='applied'
    assert a.state==INITIAL

@pytest.mark.parametrize('failure,remaining',[('after',2)])
async def test_interrupted_requires_fresh_confirmation_and_recovers_exact_outcome(setup,failure,remaining):
    tx,a,p,_=setup;a.fail=failure
    assert (await tx.execute(p,'binding'))['outcome']=='uncertain'
    assert len(a.calls)==1
    with pytest.raises(ValueError):await tx.execute(p,'binding')
    fresh=await tx.recovery_preview(p['plan_id'],'binding')
    assert fresh['plan_id']!=p['plan_id'] and len(fresh['steps'])==remaining
    a.fail=None
    assert (await tx.execute(fresh,'binding'))['outcome']=='applied'

async def test_unknown_enforcement_cannot_resume(setup):
    tx,a,p,_=setup;a.fail='after';a.proven=False
    await tx.execute(p,'binding')
    with pytest.raises(ValueError,match='enforcement'):await tx.recovery_preview(p['plan_id'],'binding')

async def test_unrelated_drift_prevents_recovery(setup):
    tx,a,p,_=setup;await tx.execute(p,'binding')
    a.state['objects']['unrelated']=MAPPING
    with pytest.raises(ValueError,match='changed'):await tx.recovery_preview(p['plan_id'],'binding',rollback=True)

async def test_tamper_expiry_binding_and_replay(setup):
    tx,a,p,_=setup
    altered=copy.deepcopy(p);altered['steps'][1]['after']['value']['port']=80
    for plan,binding in [(altered,'binding'),(p,'other')]:
        with pytest.raises(ValueError):await tx.execute(plan,binding)
    tx.clock=lambda:p['expires_at']
    with pytest.raises(ValueError,match='expired'):await tx.execute(p,'binding')
    assert a.calls==[]

async def test_expiry_after_first_step_preserves_disabled_policy(setup):
    tx,a,p,_=setup
    tx.clock=lambda: p['expires_at'] if a.calls else p['expires_at']-1
    r=await tx.execute(p,'binding')
    assert r['outcome']=='partial_expired' and len(a.calls)==1
    assert a.state['objects']['policy']['enabled'] is False

async def test_no_automatic_retry_after_ambiguous_transport_failure(setup):
    tx,a,p,_=setup;a.fail='after'
    await tx.execute(p,'binding')
    a.state['environment']['source_contract']='changed'
    with pytest.raises(ValueError):await tx.recovery_preview(p['plan_id'],'binding')
    assert len(a.calls)==1

async def test_torn_journal_fails_closed(setup):
    tx,a,p,_=setup;await tx.execute(p,'binding')
    path=tx.journals.root.path(p['plan_id']).with_suffix('.journal')
    with path.open('ab') as f:f.write(b'{')
    with pytest.raises(ValueError,match='interrupted'):await tx.recovery_preview(p['plan_id'],'binding')

async def test_undispatched_external_equivalent_cannot_be_adopted(setup):
    tx,a,p,_=setup;a.fail='before';await tx.execute(p,'binding')
    for step in STEPS:a.state=transition(a.state,step)
    with pytest.raises(ValueError):await tx.recovery_preview(p['plan_id'],'binding')

async def test_multiple_preview_recovery_only_one_execution(setup):
    tx,a,p,_=setup;a.fail='after';await tx.execute(p,'binding')
    first=await tx.recovery_preview(p['plan_id'],'binding')
    second=await tx.recovery_preview(p['plan_id'],'binding')
    a.fail=None
    assert (await tx.execute(first,'binding'))['outcome']=='applied'
    with pytest.raises(ValueError):await tx.execute(second,'binding')
    with pytest.raises(ValueError,match='already claimed'):await tx.recovery_preview(p['plan_id'],'binding')

async def test_same_box_concurrent_journal_lock_rejected(setup):
    tx,a,p,_=setup
    with tx.journals.locked(digest({'box_lock':p['box']})[:32]):
        with pytest.raises(BlockingIOError):await tx.execute(p,'binding')
    assert not a.calls

async def test_uncertain_before_state_requires_enforcement_proof(setup):
    tx,a,p,_=setup;a.fail='before';a.proven=False
    await tx.execute(p,'binding')
    with pytest.raises(ValueError,match='native queue'):await tx.recovery_preview(p['plan_id'],'binding')

async def test_snapshot_delay_cannot_dispatch_after_expiry(setup):
    tx,a,p,_=setup
    now=[p['expires_at']-1];tx.clock=lambda:now[0]
    original=a.snapshot;count=[0]
    async def delayed():
        count[0]+=1
        if count[0]==2:now[0]=p['expires_at']
        return await original()
    a.snapshot=delayed
    assert (await tx.execute(p,'binding'))['outcome']=='partial_expired'
    assert a.calls==[]

async def test_native_allocated_identity_persists_across_restart_rollback(setup):
    tx,a,p,claim=setup
    original=a.mutate
    async def allocated(step,expected,expiry):
        result=await original(step,expected,expiry)
        if step['operation']=='create_disabled':
            a.state['objects'][step['key']]['instance']={'id':'123','birth':'1700000000'}
        return result
    a.mutate=allocated
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
    fresh=ForwardTransaction(tx.journals.root.directory,a,claim)
    plan=await fresh.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert plan['initial']['objects']['policy']['instance']['id']=='123'
    assert (await fresh.execute(plan,'binding'))['outcome']=='applied'

async def test_replaced_native_identity_blocks_recovery_even_same_policy(setup):
    tx,a,p,_=setup
    original=a.mutate
    async def allocated(step,expected,expiry):
        result=await original(step,expected,expiry)
        if step['operation']=='create_disabled':a.state['objects'][step['key']]['instance']={'id':'123','birth':'1'}
        return result
    a.mutate=allocated
    await tx.execute(p,'binding')
    a.state['objects']['policy']['instance']={'id':'124','birth':'2'}
    with pytest.raises(ValueError,match='changed'):await tx.recovery_preview(p['plan_id'],'binding',rollback=True)

async def test_recovery_absence_proof_rechecked_after_preview(setup):
    tx,a,p,_=setup
    await tx.execute(p,'binding')
    # Delete all objects through a confirmed rollback, then preview restoration.
    deletion=await tx.recovery_preview(p['plan_id'],'binding',rollback=True)
    await tx.execute(deletion,'binding')
    restore=await tx.recovery_preview(deletion['plan_id'],'binding',rollback=True)
    assert restore['removed_requirements']
    calls=len(a.calls);a.proven=False
    with pytest.raises(ValueError,match='absence proof'):await tx.execute(restore,'binding')
    assert len(a.calls)==calls

async def test_current_plan_accumulates_removed_identity_proofs(setup):
    tx,a,_,_=setup
    a.state={'objects':{'a':copy.deepcopy(POLICY),'b':copy.deepcopy(POLICY)},'environment':{}}
    p=build_plan('router-a','binding',a.state,[{'operation':'remove','key':key,'before':POLICY,'after':None} for key in ('a','b')])
    async def proof(state,removed=()):
        # An orphan for A appears while B is being deleted. The stored state
        # remains correct, and B's own absence proof would pass.
        return not (len(a.calls)==2 and any(r['key']=='a' for r in removed))
    a.verify=proof
    result=await tx.execute(p,'binding')
    assert result['outcome']=='uncertain'
    with tx.journals.locked(p['plan_id']) as journal:
        assert not any(e['data']['event']=='complete' for e in journal.events)
