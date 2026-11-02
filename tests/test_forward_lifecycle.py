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

async def test_unknown_policy_metadata_is_preserved_not_nat_ownership(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value(spec),'active':True};store['maps']=[existing]
    store['policies']=[{'pid':'999','timestamp':'1','identity_complete':False,'full_fingerprint':'b'*40}]
    state=await adapter.snapshot();key='mapping:'+existing['description']
    plan=await preview(adapter,'router-a','binding',[],[{'key':key,'fingerprint':digest(state['objects'][key])}])
    assert [s['key'] for s in plan['steps']]==[key]
    assert plan['disclosures'][0]['preserved_policy_applicability']['complete'] is False
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    assert len(store['policies'])==1 and not store['maps']

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

async def test_global_dns_block_and_outbound_metadata_preserved_during_replacement(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value({**spec,'external_port':443,'destination_port':443}),'active':True};store['maps']=[existing]
    policies=[{'pid':str(n),'timestamp':'1','identity_complete':complete,'full_fingerprint':str(n)*40,'type':kind,'action':action,'direction':direction,'target':target}
              for n,kind,action,direction,target,complete in [(1,'mac','block','inbound','TAG',True),(2,'dns','address','bidirection','example.org',True),(3,'category','allow','outbound','games',False)]]
    store['policies']=copy.deepcopy(policies)
    state=await adapter.snapshot();key='mapping:'+existing['description']
    plan=await preview(adapter,'router-a','binding',[ACTIONS[1]],[{'key':key,'fingerprint':digest(state['objects'][key])}])
    assert plan['disclosures'][0]['preserved_policy_applicability']['shared'] is True
    assert (await tx.execute(plan,'binding'))['outcome']=='applied'
    assert store['policies'][:3]==policies
    assert all(c[2].get('policyID') not in ('1','2','3') for c in store['calls'])

async def test_shared_resource_rejected_before_preview_or_dispatch(native_fixture):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    existing={**forward_value(spec),'active':True}
    store['maps']=[existing,{**existing,'dport':'8443','wanUUID':'22222222-2222-4222-8222-222222222222','description':'mcp:'+'f'*32}]
    state=await adapter.snapshot();key='mapping:'+existing['description'];step={'operation':'remove','key':key,'before':state['objects'][key],'after':None}
    with pytest.raises(ValueError,match='hairpin'):
        await preview(adapter,'router-a','binding',[],[{'key':key,'fingerprint':digest(state['objects'][key])}])
    import time
    with pytest.raises(ValueError,match='hairpin'):
        await adapter.mutate(step,digest(state),time.time()+100)
    assert store['calls']==[]

async def test_removed_mapping_orphan_hairpin_not_reported_complete(native_fixture,monkeypatch):
    adapter,tx,spec,store=native_fixture
    from firewalla_mcp.remote import forward_value
    from firewalla_mcp import forward_native
    old={'kind':'mapping','value':{**forward_value(spec),'active':True},'enabled':True}
    state=await adapter.snapshot()
    monkeypatch.setattr(forward_native,'hairpin_evidence',lambda *args:True)
    assert not await adapter.verify(state,removed=[{'key':'mapping:'+old['value']['description'],'before':old}])
