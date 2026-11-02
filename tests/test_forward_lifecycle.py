import copy
import pytest
from firewalla_mcp.forward_lifecycle import preview
from firewalla_mcp.writes import digest
from test_forward_native import native_fixture

ACTIONS=[{'protocol':'tcp','external_port':p,'destination_port':p,'source_network':'203.0.113.0/24'} for p in (80,443)]

async def test_two_port_full_lifecycle_and_restart_rollback(native_fixture):
    adapter,tx,spec,store=native_fixture
    plan=await preview(adapter,'router-a','binding',ACTIONS)
    assert len(plan['steps'])==6
    assert [s['operation'] for s in plan['steps']]==['create_disabled']*2+['create']*2+['enable']*2
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    rollback=await tx.recovery_preview(plan['plan_id'],'binding',rollback=True)
    assert (await tx.execute(rollback,'binding'))['outcome']=='applied'
    assert not store['maps'] and not store['policies']

async def test_existing_nat_preserved_while_allow_added(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value({**spec,'external_port':443,'destination_port':443}),'active':True}
    store['maps']=[existing]
    plan=await preview(adapter,'router-a','binding',[ACTIONS[1]])
    assert [s['operation'] for s in plan['steps']]==['create_disabled','enable']
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    assert store['maps']==[existing]

async def test_exact_legacy_removal_then_replacement(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value({**spec,'external_port':443,'destination_port':443}),'active':True}
    store['maps']=[existing]
    state=await adapter.snapshot();key='mapping:'+existing['description']
    plan=await preview(adapter,'router-a','binding',[ACTIONS[1]],[{'key':key,'fingerprint':digest(state['objects'][key])}])
    assert plan['steps'][0]['operation']=='remove'
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    assert store['maps'][0]['description']!=existing['description']

async def test_selected_drift_cannot_remove(native_fixture):
    adapter,tx,spec,store=native_fixture
    with pytest.raises(ValueError,match='changed'):
        await preview(adapter,'router-a','binding',[],[{'key':'mapping:mcp:'+'a'*32,'fingerprint':'f'*64}])
    assert store['calls']==[]

async def test_unknown_policy_dependency_preserves_mapping(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value(spec),'active':True};store['maps']=[existing]
    store['policies']=[{'pid':'999','timestamp':'1','identity_complete':False,'full_fingerprint':'b'*40}]
    state=await adapter.snapshot();key='mapping:'+existing['description']
    with pytest.raises(ValueError,match='dependencies'):
        await preview(adapter,'router-a','binding',[],[{'key':key,'fingerprint':digest(state['objects'][key])}])
    assert store['calls']==[]

async def test_delete_then_restart_restore_binds_new_policy_id(native_fixture):
    adapter,tx,spec,store=native_fixture
    created=await preview(adapter,'router-a','binding',[ACTIONS[1]])
    assert (await tx.execute(created,'binding'))['outcome']=='applied'
    old_id=store['policies'][0]['pid']
    state=await adapter.snapshot()
    removal=[{'key':key,'fingerprint':digest(row)} for key,row in state['objects'].items()]
    deleted=await preview(adapter,'router-a','binding',[],removal)
    assert (await tx.execute(deleted,'binding'))['outcome']=='applied'
    from firewalla_mcp.forward_transaction import ForwardTransaction
    restarted=ForwardTransaction(tx.journals.root.directory,adapter,lambda p:None)
    restore=await restarted.recovery_preview(deleted['plan_id'],'binding',rollback=True)
    result=await restarted.execute(restore,'binding')
    assert result['outcome']=='applied',result
    assert store['policies'][0]['pid']!=old_id and store['policies'][0]['disabled']=='0'

async def test_exact_enabled_complete_set_is_no_change(native_fixture):
    adapter,tx,spec,store=native_fixture
    plan=await preview(adapter,'router-a','binding',[ACTIONS[1]])
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    calls=len(store['calls'])
    assert (await preview(adapter,'router-a','binding',[ACTIONS[1]]))['status']=='no_change'
    assert len(store['calls'])==calls
