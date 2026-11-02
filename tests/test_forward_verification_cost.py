"""Bound repeated kernel table reads without reusing evidence across passes."""
import copy
import pytest
from test_forward_native import native_fixture, steps_for
from test_forward_app_adapter import adopted
from firewalla_mcp import forward_native as native
from firewalla_mcp.forward_transaction import build_plan

async def test_native_tables_once_per_pass_and_refresh_on_next(native_fixture,monkeypatch):
    adapter,tx,spec,store=native_fixture
    value=steps_for(spec)[0]['after']['value']
    store['policies']=[{**value,'description':'mcp:'+c*32,'pid':str(i),'timestamp':'1',
        'disabled':'1','identity_complete':True,'full_fingerprint':c*40} for i,c in [(1,'a'),(2,'b')]]
    state=await adapter.snapshot();calls=[];version=['clean']
    def run(args):
        calls.append(tuple(args));return version[0]
    monkeypatch.setattr(native.remote,'run',run)
    monkeypatch.setattr(native,'verify_policy',lambda value,pid,v4,v6,sets,enabled: v4==v6==['clean'])
    assert await adapter.verify(state)
    assert len(calls)==2  # both families, not two reads per policy
    version[0]='changed'
    assert not await adapter.verify(state)
    assert len(calls)==4  # no evidence reused after the previous pass

async def test_legacy_active_and_removed_share_only_this_pass(adopted,monkeypatch):
    a,tx,store=adopted;state=await a.snapshot();calls=[];proofs=[]
    extra=copy.deepcopy(state['objects']['policy:app:98']);extra['instance']['id']='99'
    a.app_values['policy:app:99']=extra['value']
    a.app_policies.append({**copy.deepcopy(a.app_policies[0]),'pid':'99'})
    # Snapshot stays real for the surviving row. Removed identity is absent.
    monkeypatch.setattr(native.remote,'run',lambda args:calls.append(tuple(args)) or 'rules')
    monkeypatch.setattr(a,'legacy_proof',lambda row,rules:proofs.append((row['instance']['id'],row['enabled'],rules)) or True)
    removed=[{'key':'policy:app:99','before':extra}]
    assert await a.verify(state,removed)
    assert len(calls)==2
    assert [(p[0],p[1]) for p in proofs]==[('98',True),('99',False)]
    assert await a.verify(state,removed)
    assert len(calls)==4

async def test_slow_step_never_extends_confirmed_execution_deadline(native_fixture):
    adapter,tx,spec,store=native_fixture
    initial=await adapter.snapshot();plan=build_plan('router-a','binding',initial,steps_for(spec),now=100)
    now=[101]
    # Avoid native wall-clock deadline: the test exercises coordinator timing.
    async def mutate(step,expected,expiry):
        store['policies']=[{**step['after']['value'],'pid':'123','timestamp':'1',
            'disabled':'1','identity_complete':True,'full_fingerprint':'a'*40}]
        now[0]=plan['expires_at'];return {'verified':True}
    adapter.mutate=mutate;tx.clock=lambda:now[0]
    result=await tx.execute(plan,'binding')
    assert result['outcome']=='partial_expired' and result['completed']==1
    assert store['maps']==[]
    assert store['policies'][0]['disabled']=='1'
