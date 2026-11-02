import copy
import time
import pytest
from test_forward_native import native_fixture  # noqa: F401
from firewalla_mcp import forward_native as native
from firewalla_mcp.forward_metadata_experiment import MetadataExperimentAdapter
from firewalla_mcp.forward_transaction import ForwardTransaction,transition
from firewalla_mcp.writes import digest


@pytest.fixture
def experiment(native_fixture,monkeypatch,tmp_path):
    _,_,spec,store=native_fixture
    spec.update(protocol='tcp',external_port=80,destination_port=80)
    original={**native.remote.forward_value(spec),'active':True,'_type':'port_forward'}
    other={**original,'dport':'443','toPort':'443','description':'mcp:'+'c'*32}
    store['maps']=[copy.deepcopy(original),other]
    def request(command,item,target,payload,*extra):
        assert (command,item,target)==('set','policy','0.0.0.0')
        value=copy.deepcopy(payload['portforward']);store['calls'].append(value)
        # Pinned native find selectors: ignore description, default absent type.
        matches=[r for r in store['maps'] if all(r.get(k)==value.get(k) for k in
                 ('wanUUID','protocol','toIP','dport','toPort'))
                 and r.get('_type','port_forward')==value.get('_type','port_forward')]
        if value['state'] is False:
            store['maps']=[r for r in store['maps'] if r not in matches]
        elif matches and matches[0]['enabled']==value['enabled']:
            return  # Native enabled-to-enabled metadata update is ignored.
        else:
            store['maps']=[r for r in store['maps'] if r not in matches]
            store['maps'].append({**value,'active':True,'enabled':True,'state':True})
    monkeypatch.setattr(native.remote,'management_request',request)
    adapter=MetadataExperimentAdapter(native.remote.VPN_MANAGEMENT_REVISIONS[0],spec,original)
    directory=tmp_path/'experiment';directory.mkdir(mode=0o700)
    claims=[]
    tx=ForwardTransaction(str(directory),adapter,lambda p:claims.append(p['plan_id']))
    return adapter,tx,store,claims


async def test_native_enabled_metadata_update_is_noop(experiment):
    a,tx,s,_=experiment
    native.remote.management_request('set','policy','0.0.0.0',{'portforward':a.variant})
    assert s['maps'][0]==a.original


async def test_one_variable_change_restart_and_exact_restore(experiment):
    a,tx,s,claims=experiment;initial=await a.snapshot()
    p=await a.preview('router-a','binding')
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
    now=await a.snapshot();expected=copy.deepcopy(initial)
    del expected['objects'][a.key]['value']['_type']
    assert now==expected
    assert s['calls']==[{**a.original,'state':False},a.variant]
    restarted=ForwardTransaction(str(tx.journals.root.directory),a,lambda p:claims.append(p['plan_id']))
    r=await restarted.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert (await restarted.execute(r,'binding'))['outcome']=='applied'
    assert await a.snapshot()==initial
    assert s['calls'][2:]==[{**a.variant,'state':False},a.original]
    with pytest.raises(ValueError):await tx.execute(p,'binding')


async def test_partial_removed_restores_only_exact_absence(experiment,monkeypatch):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding')
    mutate=a.mutate
    async def interrupted(step,*args):
        if step['operation']=='create':raise RuntimeError('transport lost before outcome known')
        return await mutate(step,*args)
    monkeypatch.setattr(a,'mutate',interrupted)
    result=await tx.execute(p,'binding');assert result['outcome']=='uncertain'
    # An unverified dispatch must not be retried or restored blindly.
    with pytest.raises(ValueError,match='Uncertain dispatch'):await tx.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert len(s['calls'])==1


async def test_expiry_between_steps_has_guarded_restore(experiment,monkeypatch):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding')
    mutate=a.mutate
    async def expire(step,*args):
        result=await mutate(step,*args)
        tx.clock=lambda:p['expires_at']+1
        return result
    monkeypatch.setattr(a,'mutate',expire)
    result=await tx.execute(p,'binding');assert result['outcome']=='partial_expired'
    assert len(s['calls'])==1
    tx.clock=time.time;monkeypatch.setattr(a,'mutate',mutate)
    r=await tx.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert len(r['steps'])==1 and r['steps'][0]['operation']=='restore'
    assert (await tx.execute(r,'binding'))['outcome']=='applied'
    assert s['maps'][-1]==a.original


async def test_concurrent_unrelated_change_blocks_restore(experiment):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding')
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
    s['maps'][0]['description']='owner-edited'
    with pytest.raises(ValueError,match='changed state'):await tx.recovery_preview(p['plan_id'],'binding',rollback=True)


@pytest.mark.parametrize('field,value',[('autoFirewall',1),('ts',123),('toPort','81'),('_type','dmz_host'),('description','mcp:'+'d'*32)])
async def test_altered_metadata_rejected_before_dispatch(experiment,field,value):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding');step=copy.deepcopy(p['steps'][0]);step['before']['value'][field]=value
    with pytest.raises(ValueError):await a.mutate(step,digest(p['initial']),time.time()+60)
    assert not s['calls']


async def test_shared_hairpin_blocks_preview(experiment):
    a,tx,s,_=experiment
    s['maps'].append({**a.original,'wanUUID':'11111111-1111-4111-8111-111111111111','dport':'8080','description':'other'})
    with pytest.raises(ValueError,match='Shared hairpin'):await a.preview('router-a','binding')


async def test_expired_before_dispatch(experiment):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding')
    with pytest.raises(ValueError,match='expired'):await a.mutate(p['steps'][0],digest(p['initial']),time.time()-1)
    assert not s['calls']


@pytest.mark.parametrize('behavior',['reinserts_type','no_op'])
async def test_unexpected_recreation_stops_without_blind_restore(experiment,monkeypatch,behavior):
    a,tx,s,_=experiment;p=await a.preview('router-a','binding')
    request=native.remote.management_request
    def changed(command,item,target,payload,*extra):
        value=payload['portforward']
        if value['state'] and '_type' not in value:
            if behavior=='no_op':return
            payload={'portforward':{**value,'_type':'port_forward'}}
        return request(command,item,target,payload,*extra)
    monkeypatch.setattr(native.remote,'management_request',changed)
    assert (await tx.execute(p,'binding'))['outcome']=='uncertain'
    calls=copy.deepcopy(s['calls'])
    with pytest.raises(ValueError):await tx.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert s['calls']==calls
