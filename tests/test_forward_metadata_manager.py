import copy
import time
from pathlib import Path
import pytest
from test_forward_manager import coordinator,manager,native_fixture
from firewalla_mcp.forward_manager import ForwardManager
from firewalla_mcp import forward_native as native
from firewalla_mcp.forward_provenance import load_receipts
from firewalla_mcp.writes import digest

@pytest.fixture
def metadata(coordinator,monkeypatch):
    fm,spec,store=coordinator
    spec.update(protocol='tcp',external_port=80,destination_port=80)
    original={**native.remote.forward_value(spec),'active':True}
    https={**original,'dport':'443','toPort':'443','_type':'port_forward','description':'mcp:'+'b'*32}
    store['maps']=[original,https]
    monkeypatch.setattr(native.remote,'forward_kernel_evidence',lambda s:{'nat_rule_observed':any(r['toIP']==s['destination_ip'] and r['protocol']==s['protocol'] and r['dport']==str(s['external_port']) and r['toPort']==str(s['destination_port']) for r in store['maps']),'vpn_ingress_link_observed':True})
    return fm,spec,store

async def selection(fm,spec,*,https_type=False):
    args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
    view=await fm.inspect(*args,int(time.time())+300)
    changes=[{'key':r['key'],'fingerprint':r['fingerprint'],'display_name':'Home Assistant '+('HTTP' if r['value']['dport']=='80' else 'HTTPS'),
              'remove_default_type':https_type and r['value']['dport']=='443'} for r in view['objects'] if r['kind']=='mapping']
    return args,changes

@pytest.mark.parametrize('remove_type',[False,True])
async def test_normal_inspect_rename_restart_recovery(metadata,remove_type):
    fm,spec,s=metadata;initial=copy.deepcopy(s['maps']);args,changes=await selection(fm,spec,https_type=remove_type)
    p=await fm.preview_metadata(*args,changes,int(time.time())+300)
    assert len(p['steps'])==4
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    view=await fresh.inspect(*args,int(time.time())+300)
    rows=[r for r in view['objects'] if r['kind']=='mapping']
    assert {r['key'] for r in rows}=={r['key'] for r in changes}
    assert {r['value']['description'] for r in rows}=={'Home Assistant HTTP','Home Assistant HTTPS'}
    https=next(r['value'] for r in rows if r['value']['dport']=='443')
    assert ('_type' not in https)==remove_type
    receipts=load_receipts(fm.config.forwarding_recovery_directory,'router-a',fm.binding('router-a'))
    assert len(receipts)==2
    r=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert (await fresh.apply(r['plan_id']))['outcome']=='applied'
    assert sorted(s['maps'],key=lambda r:r['dport'])==sorted(initial,key=lambda r:r['dport'])
    with pytest.raises(ValueError):await fresh.apply(r['plan_id'])

async def test_normal_named_removal_uses_receipt_not_label(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300);assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fm=ForwardManager(fm.writes,fm.adapter_factory)
    view=await fm.inspect(*args,int(time.time())+300)
    selected=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    removal=[{k:selected[k] for k in ('key','fingerprint')}]
    plan=await fm.preview(*args,[],removal,int(time.time())+300)
    assert len(plan['steps'])==1 and plan['steps'][0]['key']==changes[0]['key']
    assert (await fm.apply(plan['plan_id']))['outcome']=='applied'
    restore=await fm.recover(plan['plan_id'],True,int(time.time())+300)
    assert (await fm.apply(restore['plan_id']))['outcome']=='applied'
    assert any(r['description']=='Home Assistant HTTP' for r in s['maps'])

async def test_rename_again_after_restart(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300);assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    _,changes=await selection(fresh,spec);changes[0]['display_name']='Automation HTTP'
    p=await fresh.preview_metadata(*args,[changes[0]],int(time.time())+300);assert (await fresh.apply(p['plan_id']))['outcome']=='applied'
    assert any(r['description']=='Automation HTTP' for r in s['maps'])

async def test_provenance_conflict_and_partial_stop(metadata,monkeypatch):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,changes,int(time.time())+300)
    fm.plans[p['plan_id']]['metadata_receipts'][0]['variants'][-1]['toIP']='192.0.2.99'
    with pytest.raises(ValueError):await fm.apply(p['plan_id'])
    assert not s['calls']

async def test_metadata_schema_explicit_type_optin(metadata):
    fm,spec,s=metadata
    from firewalla_mcp.server import build_server
    tool=next(t for t in await build_server(fm.config).list_tools() if t.name=='preview_forwarding_metadata')
    assert 'remove_default_type' in tool.inputSchema['$defs']['ForwardMetadataChange']['required']
    assert tool.annotations.readOnlyHint is True


async def test_receipt_detects_external_change_after_restart(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    next(r for r in s['maps'] if r['dport']=='80')['description']='owner edited'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    with pytest.raises(ValueError,match='changed or ambiguous'):await fresh.inspect(*args,int(time.time())+300)


async def test_metadata_partial_restart_restore(metadata,monkeypatch):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,changes,int(time.time())+300)
    original=fm.transaction
    def transaction(*args,**kwargs):
        tx=original(*args,**kwargs);mutate=tx.adapter.mutate
        async def interrupted(step,*args):
            result=await mutate(step,*args)
            tx.clock=lambda:p['expires_at']+1
            return result
        tx.adapter.mutate=interrupted
        return tx
    monkeypatch.setattr(fm,'transaction',transaction)
    assert (await fm.apply(p['plan_id']))['outcome']=='partial_expired'
    assert len(s['maps'])==1 and s['maps'][0]['dport']=='443'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    r=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert len(r['steps'])==1
    assert (await fresh.apply(r['plan_id']))['outcome']=='applied'
    assert len(s['maps'])==2 and all(r['description'].startswith('mcp:') for r in s['maps'])


async def test_helper_receipts_dispatch_contract(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    from firewalla_mcp.forward_dispatch import handle
    result=await handle({'operation':'snapshot','revision':fm.config.sites['router-a'].management_revision,
        'template':p['template'],'arguments':{'receipts':p['metadata_receipts']}})
    assert result['state']==p['initial']
    with pytest.raises(ValueError):
        await handle({'operation':'unknown','revision':fm.config.sites['router-a'].management_revision,
            'template':p['template'],'arguments':{'receipts':p['metadata_receipts']}})


async def test_named_removal_new_owner_replacement_restart(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fm=ForwardManager(fm.writes,fm.adapter_factory)
    view=await fm.inspect(*args,int(time.time())+300)
    selected=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    replacement=await fm.preview(*args,[{'protocol':'tcp','external_port':80,'destination_port':80,'source_network':'203.0.113.0/24'}],[{k:selected[k] for k in ('key','fingerprint')}],int(time.time())+300)
    assert replacement['metadata_receipts'][0]['successors']
    assert (await fm.apply(replacement['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    view=await fresh.inspect(*args,int(time.time())+300)
    current=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    assert current['key']!=selected['key']
    restore=await fresh.recover(replacement['plan_id'],True,int(time.time())+300)
    assert (await fresh.apply(restore['plan_id']))['outcome']=='applied'
    view=await fresh.inspect(*args,int(time.time())+300)
    assert any(r['key']==selected['key'] and r['value']['description']=='Home Assistant HTTP' for r in view['objects'])

async def test_successor_rename_after_restart(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    view=await fm.inspect(*args,int(time.time())+300)
    old=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    p=await fm.preview(*args,[{'protocol':'tcp','external_port':80,'destination_port':80,'source_network':'203.0.113.0/24'}],[{k:old[k] for k in ('key','fingerprint')}],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    _,changes=await selection(fresh,spec)
    change=next(c for c in changes if c['display_name']=='Home Assistant HTTP')
    change['display_name']='Replacement HTTP'
    rename=await fresh.preview_metadata(*args,[change],int(time.time())+300)
    assert (await fresh.apply(rename['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    view=await fresh.inspect(*args,int(time.time())+300)
    assert any(r['key']==change['key'] and r['value']['description']=='Replacement HTTP' for r in view['objects'])
    restore=await fresh.recover(rename['plan_id'],True,int(time.time())+300)
    assert (await fresh.apply(restore['plan_id']))['outcome']=='applied'

async def test_separate_deleted_tuple_reuse_rejected_before_mutation(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    view=await fm.inspect(*args,int(time.time())+300)
    old=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    p=await fm.preview(*args,[],[{k:old[k] for k in ('key','fingerprint')}],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    calls=copy.deepcopy(s['calls'])
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    with pytest.raises(ValueError,match='Historical mapping tuple'):
        await fresh.preview(*args,[{'protocol':'tcp','external_port':80,'destination_port':80,'source_network':'203.0.113.0/24'}],[],int(time.time())+300)
    assert s['calls']==calls

async def test_successor_cannot_reuse_historical_label(metadata):
    fm,spec,s=metadata;args,changes=await selection(fm,spec)
    p=await fm.preview_metadata(*args,[changes[0]],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    view=await fm.inspect(*args,int(time.time())+300)
    old=next(r for r in view['objects'] if r['kind']=='mapping' and r['value']['dport']=='80')
    p=await fm.preview(*args,[{'protocol':'tcp','external_port':80,'destination_port':80,'source_network':'203.0.113.0/24'}],[{k:old[k] for k in ('key','fingerprint')}],int(time.time())+300)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    _,changes=await selection(fresh,spec)
    calls=copy.deepcopy(s['calls'])
    with pytest.raises(ValueError,match='Ambiguous historical display identity'):
        await fresh.preview_metadata(*args,[next(c for c in changes if c['display_name']=='Home Assistant HTTP')],int(time.time())+300)
    assert s['calls']==calls
