import copy
import pytest
from test_forward_metadata_experiment import experiment, native_fixture
from firewalla_mcp.forward_display_names import DisplayNameAdapter
from firewalla_mcp.forward_transaction import ForwardTransaction
from firewalla_mcp import forward_native as native


@pytest.fixture(autouse=True)
def tuple_kernel(experiment,monkeypatch):
    _,_,store,_=experiment
    # Kernel NAT has no description/ownership marker; match its actual tuple.
    monkeypatch.setattr(native.remote,'forward_kernel_evidence',lambda spec:{
        'nat_rule_observed':any(r['toIP']==spec['destination_ip'] and r['protocol']==spec['protocol'] and r['dport']==str(spec['external_port']) and r['toPort']==str(spec['destination_port']) for r in store['maps']),
        'vpn_ingress_link_observed':True})


@pytest.mark.parametrize('typed',[False,True])
async def test_name_migration_durable_restart_restore(experiment,typed):
    a,tx,s,claims=experiment
    original=copy.deepcopy(a.original)
    if not typed:original.pop('_type');s['maps'][0].pop('_type')
    a=DisplayNameAdapter(a.revision,a.template,original,'Home Assistant HTTP')
    tx.adapter=a;initial=await a.snapshot()
    p=await a.preview('router-a','binding')
    assert p['metadata_receipt']['original']==original
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
    expected=copy.deepcopy(initial);expected['objects'][a.key]['value']['description']='Home Assistant HTTP'
    assert await a.snapshot()==expected
    fresh=DisplayNameAdapter.from_journal(tx.journals,p['plan_id'],'binding')
    restarted=ForwardTransaction(tx.journals.root.directory,fresh,lambda p:None)
    assert await fresh.snapshot()==expected
    r=await restarted.recovery_preview(p['plan_id'],'binding',rollback=True)
    assert (await restarted.execute(r,'binding'))['outcome']=='applied'
    assert await fresh.snapshot()==initial
    recovered=DisplayNameAdapter.from_journal(tx.journals,r['plan_id'],'binding')
    assert await recovered.snapshot()==initial


async def test_name_alone_cannot_adopt(experiment):
    a,tx,s,_=experiment
    adapter=DisplayNameAdapter(a.revision,a.template,a.original,'Home Assistant HTTP')
    s['maps'].append({**a.variant,'description':'Home Assistant HTTP','toIP':'192.0.2.99'})
    with pytest.raises(ValueError,match='Ambiguous'):await adapter.preview('router-a','binding')
    assert not s['calls']


async def test_named_receipt_changed_address_rejected(experiment):
    a,tx,s,_=experiment
    a=DisplayNameAdapter(a.revision,a.template,a.original,'Home Assistant HTTP');tx.adapter=a
    p=await a.preview('router-a','binding');assert (await tx.execute(p,'binding'))['outcome']=='applied'
    next(r for r in s['maps'] if r['description']=='Home Assistant HTTP')['toIP']='192.0.2.99'
    with pytest.raises(ValueError):await a.snapshot()
    with pytest.raises(ValueError):DisplayNameAdapter.from_journal(tx.journals,p['plan_id'],'other-box-binding')


@pytest.mark.parametrize('name',['','mcp:abc','x\ny','name;command','x'*65,' leading'])
def test_bad_display_names(experiment,name):
    a,_,_,_=experiment
    with pytest.raises(ValueError):DisplayNameAdapter(a.revision,a.template,a.original,name)


def test_future_native_mapping_omits_type_and_matches_legacy(experiment):
    a,_,_,_=experiment
    fresh=native.remote.forward_value(a.template)
    assert '_type' not in fresh
    assert native.remote.forward_matches({**fresh,'active':True},a.template)
    assert native.remote.forward_matches({**fresh,'active':True,'_type':'port_forward'},a.template)
    assert not native.remote.forward_matches({**fresh,'active':True,'_type':'dmz_host'},a.template)


async def test_provenance_durable_before_marker_removed(experiment,monkeypatch):
    a,tx,s,_=experiment
    a=DisplayNameAdapter(a.revision,a.template,a.original,'Home Assistant HTTP');tx.adapter=a
    p=await a.preview('router-a','binding');request=native.remote.management_request
    def recorded(*args,**kwargs):
        path=tx.journals.root.path(p['plan_id']).with_suffix('.journal')
        import json
        record=json.loads(path.read_text().splitlines()[0])['data']['plan']
        assert record['metadata_receipt']['original']==a.original
        assert record['metadata_receipt']['replacement']==a.variant
        return request(*args,**kwargs)
    monkeypatch.setattr(native.remote,'management_request',recorded)
    assert (await tx.execute(p,'binding'))['outcome']=='applied'
