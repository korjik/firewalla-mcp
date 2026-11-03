import copy
import json
import time
import pytest
from firewalla_mcp import forward_native as native
from firewalla_mcp.forward_policy import native_allow
from firewalla_mcp.forward_transaction import ForwardTransaction,build_plan
from firewalla_mcp.writes import digest
from test_interface_forward import wan_spec

@pytest.fixture
def native_fixture(monkeypatch,tmp_path):
    spec=wan_spec();spec['maintenance_until']=int(time.time())+300
    store={'maps':[],'policies':[],'calls':[],'next_pid':123}
    monkeypatch.setattr(native.NativeForwardAdapter,'guard',lambda self:None)
    def snapshot(s):
        own=[r for r in store['maps'] if r['description']=='mcp:'+s['owner_token']]
        collisions=[r for r in store['maps'] if r['dport']==str(s['external_port'])]
        return {'maps':copy.deepcopy(store['maps']),'environment_fingerprint':'environment','owned':own,'collisions':collisions}
    monkeypatch.setattr(native.remote,'forward_snapshot',snapshot)
    monkeypatch.setattr(native,'read_projection',lambda run:copy.deepcopy(store['policies']))
    monkeypatch.setattr(native.remote,'forward_kernel_evidence',lambda s:{'nat_rule_observed':bool(snapshot(s)['owned']),'vpn_ingress_link_observed':True})
    monkeypatch.setattr(native.remote,'run',lambda args:'')
    monkeypatch.setattr(native,'verify_policy',lambda *args:True)
    monkeypatch.setattr(native,'hairpin_evidence',lambda run,value:any(r['toIP']==value['toIP'] and r['protocol']==value['protocol'] and r['toPort']==value['toPort'] for r in store['maps']))
    def management(command,item,target,value,*extra):
        store['calls'].append((command,item,copy.deepcopy(value)))
        if item=='portforward':raise AssertionError('wrong API')
        if item=='policy':
            v=value['portforward'];store['maps']=[r for r in store['maps'] if r['description']!=v['description']]
            if v['state']:store['maps'].append({**v,'active':True})
        elif item=='policy:create':
            pid=str(store['next_pid']);store['next_pid']+=1
            store['policies'].append({**value,'pid':pid,'timestamp':'1700000000','identity_complete':True,'full_fingerprint':'a'*40})
            return pid
        elif item in ('policy:enable','policy:disable'):
            next(p for p in store['policies'] if p['pid']==value['policyID'])['disabled']='0' if item.endswith('enable') else '1'
        elif item=='policy:delete':store['policies']=[p for p in store['policies'] if p['pid']!=value['policyID']]
        else:raise AssertionError(item)
    monkeypatch.setattr(native.remote,'management_request',management)
    adapter=native.NativeForwardAdapter(native.remote.VPN_MANAGEMENT_REVISIONS[0],spec)
    directory=tmp_path/'journal';directory.mkdir(mode=0o700)
    tx=ForwardTransaction(str(directory),adapter,lambda p:None)
    return adapter,tx,spec,store

def steps_for(spec):
    value=native_allow(spec['device'],spec['interface_uuid'],'203.0.113.0/24','tcp',spec['external_port'],spec['destination_port'],'b'*32)
    policy={'kind':'allow_policy','value':value,'enabled':False}
    mapping={'kind':'mapping','value':{**native.remote.forward_value(spec),'active':True},'enabled':True}
    return [{'operation':'create_disabled','key':'policy:'+value['description'],'before':None,'after':policy},
            {'operation':'create','key':'mapping:'+mapping['value']['description'],'before':None,'after':mapping},
            {'operation':'enable','key':'policy:'+value['description'],'before':policy,'after':{**policy,'enabled':True}}]

async def test_native_contract_create_order_and_restart_rollback(native_fixture):
    adapter,tx,spec,store=native_fixture
    initial=await adapter.snapshot()
    plan=build_plan('router-a','binding',initial,steps_for(spec))
    result=await tx.execute(plan,'binding')
    assert result['outcome']=='applied',result
    assert [c[1] for c in store['calls']]==['policy:create','policy','policy:enable']
    rollback=await tx.recovery_preview(plan['plan_id'],'binding',rollback=True)
    # Delete disabled companion policy before its NAT dependency.
    assert [s['operation'] for s in rollback['steps']]==['disable','remove','remove']
    assert rollback['steps'][1]['key'].startswith('policy:')
    assert (await tx.execute(rollback,'binding'))['outcome']=='applied'
    assert await adapter.snapshot()==initial

async def test_native_deadline_rechecked_before_management(native_fixture):
    adapter,tx,spec,store=native_fixture
    state=await adapter.snapshot()
    with pytest.raises(ValueError,match='expired'):
        await adapter.mutate(steps_for(spec)[0],digest(state),time.time()-1)
    assert not store['calls']

async def test_policy_unsupported_identity_cannot_dispatch(native_fixture):
    adapter,tx,spec,store=native_fixture
    state=await adapter.snapshot();step=steps_for(spec)[0]
    step['after']['value']['upnp']=True
    with pytest.raises(ValueError):await adapter.mutate(step,digest(state),time.time()+20)
    assert not store['calls']

async def test_incomplete_tagged_policy_is_opaque_not_editable(native_fixture):
    adapter,tx,spec,store=native_fixture
    value=steps_for(spec)[0]['after']['value']
    store['policies']=[{**value,'pid':'999','timestamp':'1','identity_complete':False,'full_fingerprint':'b'*40}]
    snapshot=await adapter.snapshot()
    assert 'policy:999' in snapshot['objects']
    assert 'policy:'+value['description'] not in snapshot['objects']
    assert snapshot['objects']['policy:999']['value']=={'policy_fingerprint':'b'*40}

async def test_recovery_absence_proof_checks_orphan_kernel_policy(native_fixture,monkeypatch):
    adapter,tx,spec,store=native_fixture
    value=steps_for(spec)[0]['after']['value']
    before={'kind':'allow_policy','value':value,'enabled':False,'instance':{'id':'123','birth':'1'}}
    state=await adapter.snapshot()
    monkeypatch.setattr(native,'verify_policy',lambda *args:False)
    assert not await adapter.verify(state,removed=[{'key':'policy:'+value['description'],'before':before}])

@pytest.mark.parametrize('metadata',[{'purpose':'port_forwarding'},{'purpose':'dmz'},{'updatedTime':'1700000001.1'}])
def test_managed_adapter_does_not_drop_new_app_metadata(metadata):
 from firewalla_mcp.forward_native import NativeForwardAdapter
 from firewalla_mcp.forward_policy import native_allow
 value=native_allow('02:00:00:00:00:01','11111111-1111-1111-1111-111111111111','0.0.0.0/0','tcp',443,443,'a'*32)
 adapter=object.__new__(NativeForwardAdapter);adapter.template={'device':value['scope'][0],'interface_uuid':value['owanUUID']}
 with pytest.raises(ValueError,match='metadata'):adapter.policy_value({**value,**metadata})
