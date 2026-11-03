"""Synthetic default-WAN migration; no appliance calls or credentials."""
import copy
import shlex
import json
import time
import pytest
from firewalla_mcp import remote
from firewalla_mcp.forward_default_wan import exact_default_nat
from firewalla_mcp.forward_dependencies import require_mapping_removal
from firewalla_mcp.forward_manager import ForwardManager
from firewalla_mcp.forward_app_adapter import AppForwardAdapter
from test_forward_reset_manager import reset_fixture,metadata,coordinator,manager,native_fixture
from test_forward_reconcile import legacy_mapping


REAL_SNAPSHOT=remote.forward_snapshot


def default_mapping():
    m=legacy_mapping();m.pop('wanUUID');return m


def line(m):
    return f"-A FW_PRERT_PORT_FORWARD -p {m['protocol']} -m {m['protocol']} --dport {m['dport']} -j DNAT --to-destination {m['toIP']}:{m['toPort']}"


def test_default_selector_is_opt_in_and_null_peer_is_ambiguous():
    m=default_mapping()
    with pytest.raises(ValueError):require_mapping_removal(m,[m])
    assert require_mapping_removal(m,[m],allow_default_wan=True)['selected_match']
    for peer in [{**m,'wanUUID':None},{**m,'description':'another'}, {**m,'dport':int(m['dport'])}]:
        with pytest.raises(ValueError):require_mapping_removal(m,[m,peer],allow_default_wan=True)


@pytest.mark.parametrize('extra',[{'wanUUID':None},{'wanUUID':''},{'wanUUID':False},{'wanUUID':'*'},
    {'applyToAll':False},{'extIP':None},{'_type':'dmz_host'},{'active':False},{'unknown':1}])
def test_scope_and_state_not_coerced(extra):
    m={**default_mapping(),**extra}
    with pytest.raises(ValueError):require_mapping_removal(m,[m],allow_default_wan=True)


@pytest.mark.parametrize('suffix',[' --match-set other dst',' -d 198.51.100.1',' !',' -j DNAT',' --comment x'])
def test_only_exact_unrestricted_nat_shape(suffix):
    m=default_mapping()
    assert exact_default_nat(shlex.split(line(m)),m)
    assert not exact_default_nat(shlex.split(line(m)+suffix),m)


@pytest.fixture
def migration(reset_fixture,monkeypatch):
    fm,spec,store=reset_fixture
    old=store['maps'][0];old.pop('wanUUID');old.update(description='App HTTP',autoFirewall=1,ts=1700000000)
    monkeypatch.setattr(remote,'forward_snapshot',REAL_SNAPSHOT)
    monkeypatch.setattr(remote,'interface_forward_environment',lambda spec:{'networks':[{'uuid':spec['interface_uuid'],'type':'wan'}],'sets':{'c_ip_'+spec['interface_uuid'][:13]+'_set':['198.51.100.2']},'addresses':['198.51.100.2'],'routing':[]})
    def run(args):
        if args[:4]==['redis-cli','--raw','GET','extension.portforward.config']:return json.dumps({'maps':store['maps']})
        if args[-1]=='ipv4Addr':return spec['destination_ip']
        if args[-1]=='vpnClient':return ''
        if args[:5]==['sudo','-n','iptables','-t','nat']:
            return '\n'.join(line(m)+((' -m set --match-set c_ip_'+m['wanUUID'][:13]+'_set dst') if 'wanUUID' in m else '') for m in store['maps'])
        return ''
    monkeypatch.setattr(remote,'run',run)
    return fm,spec,store


async def plan(migration,**updates):
    fm,spec,store=migration;args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
    inv=await fm.inspect_app_objects(*args,int(time.time())+300)
    m=next(r for r in inv['mappings'] if r['value']['description']=='App HTTP')
    fields=dict(mapping_selections=[{k:m[k] for k in ('key','fingerprint')}],policy_selections=[],
        actions=[{'protocol':'tcp','external_port':80,'destination_port':8080,'source_network':'0.0.0.0/0','display_name':'Selected WAN HTTP'}],
        all_mappings=False,maintenance_until=int(time.time())+300)
    fields.update(updates)
    return await fm.preview_app_reset(*args,**fields)


async def test_narrowing_preserves_https_and_policies_and_restart_restores(migration):
    fm,spec,store=migration;old=copy.deepcopy(store)
    p=await plan(migration)
    assert len(p['steps'])==4 and not store['calls']
    disclosure=p['disclosures'][-1]
    assert disclosure['scope_change']=='native_default_wans_to_selected_wan'
    assert disclosure['new_inbound_allow']['destination_port']==8080
    assert not p['app_adoptions']['policies']
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    assert all(m in store['maps'] for m in old['maps'][1:])
    assert all(p in store['policies'] for p in old['policies'])
    new=next(m for m in store['maps'] if m['dport']=='80')
    assert new['wanUUID']==spec['interface_uuid'] and new['toPort']=='8080'
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    recovery=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert not any(c[2].get('portforward',{}).get('state') and 'wanUUID' not in c[2]['portforward'] for c in store['calls'])
    assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
    assert sorted(store['maps'],key=str)==sorted(old['maps'],key=str)
    assert sorted(store['policies'],key=str)==sorted(old['policies'],key=str)
    with pytest.raises(ValueError):await fresh.apply(recovery['plan_id'])


@pytest.mark.parametrize('stop',[1,2,3])
async def test_partial_expiry_fresh_recovery(migration,monkeypatch,stop):
    fm,spec,store=migration;old=copy.deepcopy(store['maps']);p=await plan(migration)
    transaction=fm.transaction
    def interrupted(*a,**kw):
        tx=transaction(*a,**kw)
        tx.clock=lambda:p['expires_at']+1 if len(store['calls'])>=stop else p['expires_at']-1
        return tx
    monkeypatch.setattr(fm,'transaction',interrupted)
    result=await fm.apply(p['plan_id'])
    assert result['outcome']=='partial_expired' and result['completed']==stop
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    recovery=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
    assert sorted(store['maps'],key=str)==sorted(old,key=str)


async def test_drift_or_extra_scope_cannot_dispatch(migration):
    fm,spec,store=migration
    with pytest.raises(ValueError):await plan(migration,all_mappings=True)
    with pytest.raises(ValueError):await plan(migration,actions=[])
    p=await plan(migration);store['maps'][0]['autoFirewall']=0
    with pytest.raises(ValueError,match='Initial state changed'):await fm.apply(p['plan_id'])
    assert not store['calls']


async def test_orphan_default_rule_blocks_recovery(migration,monkeypatch):
    fm,spec,store=migration;old=copy.deepcopy(store['maps'][0]);p=await plan(migration)
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    run=remote.run
    monkeypatch.setattr(remote,'run',lambda args:line(old) if args[-1]=='FW_PRERT_PORT_FORWARD' else run(args))
    with pytest.raises(ValueError):await fm.recover(p['plan_id'],True,int(time.time())+300)


def test_nat_guard_ignores_only_one_exact_selected_default(monkeypatch):
    from test_interface_forward import wan_spec
    m=default_mapping();spec=wan_spec();spec.update(protocol=m['protocol'],external_port=int(m['dport']),destination_ip=m['toIP'],destination_port=int(m['toPort']))
    monkeypatch.setattr(remote,'run',lambda args:line(m))
    assert remote.interface_nat_guard(spec,False,None,[m])[0] is False
    assert remote.interface_nat_guard(spec,False,None,[])[0] is True
    monkeypatch.setattr(remote,'run',lambda args:line(m)+'\n'+line(m))
    with pytest.raises(remote.Unsupported):remote.interface_nat_guard(spec,False,None,[m])


async def test_other_wan_stored_overlap_blocks_before_plan(migration):
    fm,spec,store=migration
    store['maps'].append({**store['maps'][1],'wanUUID':'33333333-3333-4333-8333-333333333333','dport':'80','toPort':'9000','enabled':False,'description':'Other WAN HTTP'})
    with pytest.raises(ValueError,match='overlap'):await plan(migration)
    assert not fm.plans and not store['calls']


async def test_missing_or_duplicate_kernel_baseline_creates_no_plan(migration,monkeypatch):
    fm,spec,store=migration;run=remote.run
    for replacement in ['',line(store['maps'][0])+'\n'+line(store['maps'][0])]:
        monkeypatch.setattr(remote,'run',lambda args:replacement if args[-1]=='FW_PRERT_PORT_FORWARD' else run(args))
        with pytest.raises(ValueError):await plan(migration)
    assert not fm.plans and not store['calls']


def test_all_wan_ingress_and_duplicate_evidence_fail_closed(monkeypatch):
    from firewalla_mcp.forward_default_wan import default_evidence
    from test_interface_forward import wan_spec,WAN,OTHER
    spec=wan_spec();m=default_mapping()
    monkeypatch.setattr(remote,'interface_forward_environment',lambda s:{'networks':[{'type':'wan','uuid':WAN},{'type':'wan','uuid':OTHER}]})
    seen=[]
    def evidence(s):
        seen.append(s['interface_uuid']);return {'vpn_ingress_link_observed':s['interface_uuid']==WAN}
    monkeypatch.setattr(remote,'forward_kernel_evidence',evidence)
    monkeypatch.setattr(remote,'run',lambda args:line(m))
    assert not default_evidence(spec,m)['vpn_ingress_link_observed']
    assert seen==[WAN,OTHER]


async def test_uncertain_native_remove_is_observed_before_recovery(migration,monkeypatch):
    fm,spec,store=migration;old=copy.deepcopy(store['maps']);p=await plan(migration)
    original=remote.management_request
    def lost_reply(*args):
        original(*args)
        raise TimeoutError('synthetic reply lost after removal')
    monkeypatch.setattr(remote,'management_request',lost_reply)
    result=await fm.apply(p['plan_id'])
    assert result['outcome']=='uncertain' and result['completed']==0
    assert len(store['calls'])==1
    with pytest.raises(ValueError):await fm.apply(p['plan_id'])
    assert len(store['calls'])==1
    monkeypatch.setattr(remote,'management_request',original)
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    recovery=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert recovery['disclosures'][-1]['recovery_scope_change']=='restore_native_default_wans'
    assert len(store['calls'])==1
    assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
    assert sorted(store['maps'],key=str)==sorted(old,key=str)


def test_built_helper_contains_default_scope_proofs(tmp_path):
    import runpy,zipfile,subprocess,sys
    build=runpy.run_path('scripts/build_forward_helper.py')['build']
    archive=tmp_path/'helper.pyz';build(archive)
    with zipfile.ZipFile(archive) as z:
        assert 'firewalla_mcp/forward_default_wan.py' in z.namelist()
    code="import sys;sys.path.insert(0,sys.argv[1]);from firewalla_mcp.forward_default_wan import exact_default_nat;from firewalla_mcp.forward_dispatch import handle"
    subprocess.run([sys.executable,'-I','-c',code,str(archive)],check=True)


async def test_uncertain_disabled_creation_recovers_only_with_fresh_plan(migration,monkeypatch):
    fm,spec,store=migration;old=copy.deepcopy(store);p=await plan(migration)
    from firewalla_mcp import forward_rule_projection
    prior=forward_rule_projection.read_policy_rules;failed=[False]
    def interrupted(run,pids):
        if str(old['next_pid']) in pids and not failed[0]:
            failed[0]=True
            raise remote.Unsupported('synthetic full-table output limit')
        return prior(run,pids)
    monkeypatch.setattr(forward_rule_projection,'read_policy_rules',interrupted)
    result=await fm.apply(p['plan_id'])
    assert result['outcome']=='uncertain' and result['completed']==1
    new=next(r for r in store['policies'] if r['pid']==str(old['next_pid']))
    assert new['disabled']=='1' and all(m['dport']!='80' for m in store['maps'])
    calls=len(store['calls']);fresh=ForwardManager(fm.writes,fm.adapter_factory)
    recovery=await fresh.recover(p['plan_id'],False,int(time.time())+300)
    assert len(store['calls'])==calls and [s['operation'] for s in recovery['steps']]==['create','enable']
    assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
    assert all(r in store['policies'] for r in old['policies'])
    assert old['maps'][1] in store['maps']
