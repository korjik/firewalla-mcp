"""Synthetic native WAN contracts; no actual router mutations."""
import copy
import json
import time
import pytest
from firewalla_mcp import remote
from test_persistent_forward import appliance, apply, spec
from test_approval_bound_vpn import approved_config

WAN='11111111-1111-4111-8111-111111111111'
LAN='22222222-2222-4222-8222-222222222222'
OTHER='33333333-3333-4333-8333-333333333333'

def wan_spec():
    s=spec();s.pop('profile');s.update(kind='managed_interface_forward',interface_uuid=WAN);return s

@pytest.fixture
def wan(appliance,monkeypatch):
    env={'network':{'uuid':WAN,'interface':'eth0','type':'wan'},'addresses':['198.51.100.2'],'routing':[]}
    monkeypatch.setattr(remote,'interface_forward_environment',lambda s:copy.deepcopy(env))
    monkeypatch.setattr(remote,'interface_nat_guard',lambda s,owned,sets=None:(False,'nat'))
    appliance['policy']=None
    return appliance,env

def test_wan_native_create_and_owned_rollback(wan):
    state,_=wan;s=wan_spec();remote.validate_managed(s)
    result=apply(s)
    assert result['outcome']=='applied'
    assert state['maps'][0]['wanUUID']==WAN
    assert 'VC:' not in json.dumps(state['maps'])
    result=remote.managed_forward({'spec':s,'mode':'rollback','expected':result['state']['fingerprint'],'context':result['context'],'expires_at':int(time.time())+300})
    assert result['outcome']=='rolled_back' and not state['maps']

@pytest.mark.parametrize('row',[
    {'protocol':'tcp','dport':'40900:41100','enabled':False},
    {'wanUUID':WAN,'protocol':'tcp','dport':'41000'},
    {'applyToAll':True,'protocol':'tcp','dport':'41000'},
    {'_type':'dmz_host'},
    {'extIP':'198.51.100.2','protocol':'tcp','dport':'41000'},
])
def test_wan_conflicts_include_disabled_default_range_dmz(wan,row):
    state,_=wan;state['maps']=[row]
    assert apply(wan_spec())['outcome']=='stale' and state['calls']==0

def test_distinct_explicit_wan_mapping_is_preserved(wan):
    state,_=wan;row={'wanUUID':OTHER,'protocol':'tcp','dport':'41000'};state['maps']=[row]
    assert apply(wan_spec())['outcome']=='applied' and state['maps'][0]==row

def test_routing_or_interface_drift_prevents_apply(wan):
    state,env=wan;s=wan_spec();p=remote.forward_snapshot(s)
    env['routing']=[{'changed':True}]
    assert remote.managed_forward({'spec':s,'mode':'apply','expected':p['fingerprint']})['outcome']=='stale'
    assert not state['calls']

def test_wan_batch_and_partial(wan):
    state,_=wan;a=wan_spec();b=wan_spec();b.update(protocol='udp',owner_token='b'*32)
    batch={'kind':'managed_forward_batch','steps':[a,b]};remote.validate_managed(batch)
    p=remote.managed_forward_batch({'spec':batch,'mode':'preview'})
    r=remote.managed_forward_batch({'spec':batch,'mode':'apply','expected':p['fingerprint'],'expires_at':int(time.time())+300})
    assert r['outcome']=='applied' and state['calls']==2

@pytest.mark.parametrize('field,value',[('interface_uuid','*'),('interface_uuid','eth0;id'),('interface_uuid',WAN.upper()),('external_port',0),('destination_ip','192.0.2.2%eth0'),('destination_ip','2001:db8::1')])
def test_interface_validation(field,value):
    s=wan_spec();s[field]=value
    # numeric-only UUID has no upper-case variant
    if field=='interface_uuid' and value==WAN:return
    with pytest.raises((ValueError,TypeError)):remote.validate_managed(s)

def test_mixed_scope_batch_rejected():
    a=wan_spec();b=spec();b['owner_token']='b'*32
    with pytest.raises(ValueError):remote.validate_managed({'kind':'managed_forward_batch','steps':[a,b]})

@pytest.fixture
def network(monkeypatch):
    rows={WAN:{'name':'eth0','uuid':WAN,'type':'wan','ip4_subnets':['198.51.100.0/24']},LAN:{'name':'br0','uuid':LAN,'type':'lan','ip4_subnets':['192.0.2.0/24']}}
    state={'rows':rows,'stale':False,'overlap':False,'empty':False,'rules':True}
    def run(argv):
        if 'HGETALL' in argv:
            if argv[-1]=='sys:network:uuid':return "\n".join(v for k,r in rows.items() for v in (k,json.dumps(r)))
            return "\n".join(v for r in rows.values() for v in (r['name'],json.dumps({**r,'uuid':OTHER if state['stale'] and r['type']=='wan' else r['uuid'],'secret':'never expose'})))
        if argv[-1]=='-name':return '\n'.join('c_ip_'+u[:13]+'_set' for u in rows)
        if 'save' in argv:
            address='198.51.100.2' if WAN[:13] in argv[-1] or state['overlap'] else '192.0.2.1'
            return '' if state['empty'] else 'add '+argv[-1]+' '+address
        if argv[0]=='ip':return '[]'
        if argv[-1]=='FW_PRERT_PORT_FORWARD':return '-A FW_PRERT_PORT_FORWARD -p tcp --dport 41000 -m set --match-set c_ip_'+WAN[:13]+'_set dst -j DNAT --to-destination 192.0.2.20:41000'
        if argv[-1]=='FW_PREROUTING_EXT_IP':return '-A FW_PREROUTING_EXT_IP -d 198.51.100.2/32 -j FW_PRERT_PORT_FORWARD' if state['rules'] else ''
        raise AssertionError(argv)
    monkeypatch.setattr(remote,'run',run)
    return state

def test_current_interface_projection_and_kernel_contract(network):
    rows=remote.forward_networks();assert len(rows)==2 and 'secret' not in json.dumps(rows)
    env=remote.interface_forward_environment(wan_spec());assert env['addresses']==['198.51.100.2']
    ev=remote.forward_kernel_evidence(wan_spec());assert ev['nat_rule_observed'] and ev['vpn_ingress_link_observed']
    assert 'not a physical' in ev['interface_scope']
    network['rules']=False;assert not remote.forward_kernel_evidence(wan_spec())['vpn_ingress_link_observed']

@pytest.mark.parametrize('flag',['stale','overlap','empty'])
def test_unsafe_interface_scope_rejected(network,flag):
    network[flag]=True
    with pytest.raises(remote.Unsupported):remote.interface_forward_environment(wan_spec())

def test_lan_ingress_and_off_lan_destination_rejected(network):
    s=wan_spec();s['interface_uuid']=LAN
    with pytest.raises(remote.Unsupported):remote.interface_forward_environment(s)
    s=wan_spec();s['destination_ip']='203.0.113.20'
    with pytest.raises(remote.Unsupported):remote.interface_forward_environment(s)

def test_expired_wan_never_submits(wan):
    state,_=wan;s=wan_spec();p=remote.forward_snapshot(s)
    r=remote.managed_forward({'spec':s,'mode':'apply','expected':p['fingerprint'],'expires_at':int(time.time())-1})
    assert r['outcome']=='uncertain' and state['calls']==0

@pytest.mark.parametrize('change', ['negated_set','negated_destination','source','mark','restricted_ingress'])
def test_kernel_opposite_or_extra_scope_is_not_verified(network,monkeypatch,change):
    original=remote.run
    def changed(argv):
        value=original(argv)
        if change=='negated_set':value=value.replace('--match-set','! --match-set')
        if change=='negated_destination':value=value.replace('-d 198.51.100.2','! -d 198.51.100.2')
        if change=='source' and '-j DNAT' in value:value+=' -s 203.0.113.9/32'
        if change=='mark' and '-j DNAT' in value:value+=' -m mark --mark 1'
        if change=='restricted_ingress' and '-j FW_PRERT_PORT_FORWARD' in value:value+=' -p udp --dport 9'
        return value
    monkeypatch.setattr(remote,'run',changed)
    ev=remote.forward_kernel_evidence(wan_spec())
    assert not (ev['nat_rule_observed'] and ev['vpn_ingress_link_observed'])

def test_four_action_transport_bound():
    from firewalla_mcp.transport import remote_command
    steps=[]
    for i in range(4):
        s=wan_spec();s.update(external_port=65530+i,destination_port=65530+i,owner_token=str(i)*32);steps.append(s)
    cmd=remote_command('managed_write',{'revision':'a'*40,'spec':{'kind':'managed_forward_batch','steps':steps},'mode':'apply','expected':'a'*64,'expires_at':int(time.time())+300})
    assert cmd.startswith('timeout 110 ') and len(cmd.encode())<131072

def test_budget_stops_before_subprocess(monkeypatch):
    monkeypatch.setattr(remote,'COMMAND_DEADLINE',remote.time.monotonic()-1)
    monkeypatch.setattr(remote.subprocess,'Popen',lambda *a,**k:pytest.fail('expired budget must not spawn'))
    with pytest.raises(remote.Unsupported,match='budget'):remote.run(['ip','-j','rule','show'])

def test_batch_read_failure_after_first_action_preserves_partial(wan,monkeypatch):
    state,_=wan;a=wan_spec();b=wan_spec();b.update(protocol='udp',owner_token='b'*32)
    batch={'kind':'managed_forward_batch','steps':[a,b]};p=remote.managed_forward_batch({'spec':batch,'mode':'preview'})
    original=remote.forward_snapshot
    def delayed(s,*args,**kw):
        if state['calls'] and s['owner_token']=='b'*32:raise remote.Unsupported('operation time budget exhausted')
        return original(s,*args,**kw)
    monkeypatch.setattr(remote,'forward_snapshot',delayed)
    r=remote.managed_forward_batch({'spec':batch,'mode':'apply','expected':p['fingerprint'],'expires_at':int(time.time())+300})
    assert r['outcome']=='partial' and state['calls']==1 and len(r['steps'])==1

@pytest.mark.parametrize('rule',[
 '-A UPNP -p tcp --dport 41000 -j DNAT --to-destination 192.0.2.99:41000',
 '-A CUSTOM -p tcp --dport 40999:41001 -j DNAT --to-destination 192.0.2.99:41000',
 '-A DMZ -j DNAT --to-destination 192.0.2.99',
])
def test_dynamic_or_unmanaged_dnat_conflicts(monkeypatch,rule):
    monkeypatch.setattr(remote,'run',lambda argv:rule)
    assert remote.interface_nat_guard(wan_spec(),False)[0]

def test_kernel_guard_excludes_only_one_owned_mapping(monkeypatch):
    r='-A FW_PRERT_PORT_FORWARD -p tcp --dport 41000 -m set --match-set c_ip_'+WAN[:13]+'_set dst -j DNAT --to-destination 192.0.2.20:41000'
    monkeypatch.setattr(remote,'run',lambda argv:r)
    assert not remote.interface_nat_guard(wan_spec(),True)[0]
    assert remote.interface_nat_guard(wan_spec(),False)[0]
    monkeypatch.setattr(remote,'run',lambda argv:r+'\n'+r)
    assert remote.interface_nat_guard(wan_spec(),True)[0]

async def test_wan_plan_server_binding_replay_and_changed_target(approved_config):
    from test_approval_bound_vpn import Appliance
    from firewalla_mcp.writes import WriteManager
    c,_=approved_config;c=c.model_copy(update={'writes_enabled':True,'write_confirmation_mode':'host_confirmed'})
    manager=WriteManager(c,Appliance())
    p=await manager.preview('router-a',wan_spec())
    assert p['diff']['object']['interface_uuid']==WAN
    assert (await manager.apply(p['plan_id']))['data']['outcome']=='applied'
    assert (await manager.apply(p['plan_id']))['replayed'] is True
    q=await manager.preview('router-a',wan_spec())
    manager.plans[q['plan_id']]['spec']['interface_uuid']=OTHER
    with pytest.raises(ValueError):await manager.apply(q['plan_id'])

@pytest.mark.parametrize('qualifier',['! -p udp --dport 41000','-p tcp ! --dport 41001','! -d 198.51.100.9 --dport 41000'])
def test_negated_dnat_fails_closed(monkeypatch,qualifier):
    monkeypatch.setattr(remote,'run',lambda argv:'-A CUSTOM '+qualifier+' -j DNAT --to-destination 192.0.2.99:80')
    assert remote.interface_nat_guard(wan_spec(),False)[0]

def test_known_disjoint_destination_set_avoids_false_conflict(monkeypatch):
    selected='c_ip_'+WAN[:13]+'_set';other='c_ip_'+OTHER[:13]+'_set'
    monkeypatch.setattr(remote,'run',lambda argv:'-A FW_PRERT_PORT_FORWARD -p tcp --dport 41000 -m set --match-set '+other+' dst -j DNAT --to-destination 192.0.2.99:80')
    assert remote.interface_nat_guard(wan_spec(),False)[0]
    assert not remote.interface_nat_guard(wan_spec(),False,{selected:['198.51.100.2'],other:['203.0.113.2']})[0]
    assert remote.interface_nat_guard(wan_spec(),False,{selected:['198.51.100.2'],other:['198.51.100.2']})[0]
