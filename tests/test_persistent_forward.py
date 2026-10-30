import copy,json,time
import pytest
from firewalla_mcp import remote
from firewalla_mcp.writes import WriteManager
from test_approval_bound_vpn import approved_config, Appliance


def spec(**kw):
    return dict(kind='managed_forward',device='02:00:00:00:00:01',destination_ip='192.0.2.20',profile='profile_a',protocol='tcp',external_port=41000,destination_port=41000,owner_token='a'*32,maintenance_until=int(time.time())+300,**kw)

@pytest.fixture
def appliance(monkeypatch):
    state={'maps':[],'policy':{'state':True,'profileId':'profile_a'},'ip':'192.0.2.20','calls':0,'kernel':True,'ignore':False}
    def run(argv,**kwargs):
        if argv[:3]==['redis-cli','--raw','GET']:return json.dumps({'maps':state['maps']})
        if argv[-1]=='ipv4Addr':return state['ip']
        if argv[-1]=='vpnClient':return json.dumps(state['policy'])
        raise AssertionError(argv)
    def request(command,item,target,value,*args):
        assert (command,item,target)==('set','policy','0.0.0.0');state['calls']+=1
        v=value['portforward'];assert '*' not in v.values()
        if state['ignore']:return
        if v['state']:state['maps'].append({**v,'active':True})
        else:state['maps']=[r for r in state['maps'] if r['description']!=v['description']]
    monkeypatch.setattr(remote,'run',run);monkeypatch.setattr(remote,'management_request',request)
    monkeypatch.setattr(remote,'managed_vpn_safety',lambda p:({},'settingshash'))
    monkeypatch.setattr(remote,'forward_ingress_guard',lambda p:'ingresshash')
    monkeypatch.setattr(remote,'forward_kernel_evidence',lambda s:{'nat_rule_observed':bool(state['maps']) and state['kernel'],'vpn_ingress_link_observed':state['kernel']})
    monkeypatch.setattr(remote.time,'sleep',lambda t:None)
    return state

def apply(s):
    before=remote.managed_forward({'spec':s,'mode':'preview'})
    return remote.managed_forward({'spec':s,'mode':'apply','expected':before['fingerprint'],'expires_at':int(time.time())+300})

def test_native_request_and_exact_rollback(appliance):
    s=spec();result=apply(s);assert result['outcome']=='applied' and appliance['calls']==1
    assert appliance['maps'][0]['wanUUID']=='VC:profile_a'
    r=remote.managed_forward({'spec':s,'mode':'rollback','expected':result['state']['fingerprint'],'context':result['context'],'expires_at':int(time.time())+300})
    assert r['outcome']=='rolled_back' and not appliance['maps']

def test_disabled_range_duplicate_blocks_without_mutation(appliance):
    appliance['maps']=[{'wanUUID':'VC:profile_a','protocol':'tcp','dport':'40000-42000','enabled':False}]
    assert remote.managed_forward({'spec':spec(),'mode':'preview'})['present']
    assert apply(spec())['outcome']=='stale' and appliance['calls']==0

def test_ip_and_policy_binding(appliance):
    appliance['ip']='192.0.2.21'
    with pytest.raises(remote.Unsupported):remote.forward_snapshot(spec())
    appliance['ip']='192.0.2.20';appliance['policy']['profileId']='different'
    with pytest.raises(remote.Unsupported):remote.forward_snapshot(spec())

def test_stored_mapping_without_kernel_is_uncertain(appliance):
    appliance['kernel']=False;assert apply(spec())['outcome']=='uncertain'

@pytest.mark.parametrize('field,value',[('profile','../../bad'),('device','*'),('destination_ip','2001:db8::1'),('external_port',True),('protocol','tcp;id'),('owner_token','*')])
def test_bad_arguments(field,value):
    s=spec();s[field]=value
    with pytest.raises((ValueError,TypeError)):remote.validate_managed(s)

def test_wrong_snapshot_never_sends(appliance):
    assert remote.managed_forward({'spec':spec(),'mode':'apply','expected':'bad'})['outcome']=='stale';assert appliance['calls']==0

def test_compound_accounts_for_its_own_additions(appliance):
    a=spec();b=spec();b.update(protocol='udp',owner_token='b'*32)
    compound={'kind':'managed_forward_batch','steps':[a,b]};remote.validate_managed(compound)
    preview=remote.managed_forward_batch({'spec':compound,'mode':'preview'})
    r=remote.managed_forward_batch({'spec':compound,'mode':'apply','expected':preview['fingerprint'],'expires_at':int(time.time())+300})
    assert r['outcome']=='applied' and len(r['steps'])==2 and appliance['calls']==2

def test_compound_stops_on_unverified_kernel(appliance):
    a=spec();b=spec();b.update(protocol='udp',owner_token='b'*32);c={'kind':'managed_forward_batch','steps':[a,b]}
    p=remote.managed_forward_batch({'spec':c,'mode':'preview'});appliance['kernel']=False
    r=remote.managed_forward_batch({'spec':c,'mode':'apply','expected':p['fingerprint'],'expires_at':int(time.time())+300})
    assert r['outcome']=='uncertain' and len(r['steps'])==1 and appliance['calls']==1

def test_compound_rejects_duplicate_or_other_operations():
    s=spec()
    with pytest.raises(ValueError):remote.validate_managed({'kind':'managed_forward_batch','steps':[s,s]})
    with pytest.raises(ValueError):remote.validate_managed({'kind':'managed_forward_batch','steps':[s,{'kind':'managed_lifecycle'}]})

async def test_general_manager_host_confirmation_no_file(approved_config):
    c,_=approved_config;c=c.model_copy(update={'writes_enabled':True,'write_confirmation_mode':'host_confirmed','approval_directory':None})
    m=WriteManager(c,Appliance());p=await m.preview('router-a',spec())
    assert p['next_step']['apply_tool']=='apply_change' and p['approval_document'] is None
    assert (await m.apply(p['plan_id']))['data']['outcome']=='applied'


def test_native_shared_chain_overlapping_tunnel_ips_rejected(monkeypatch):
    def run(argv):
        if argv[-1]=='-name':return 'c_ip_profile_a_set4\nc_ip_profile_b_set4\n'
        return 'create '+argv[-1]+' hash:ip family inet\nadd '+argv[-1]+' 192.0.2.100\n'
    monkeypatch.setattr(remote,'run',run)
    with pytest.raises(remote.Unsupported,match='overlapping'):remote.forward_ingress_guard('profile_a')


def test_concurrent_mapping_after_submit_is_uncertain(appliance,monkeypatch):
    original=remote.management_request
    def mutate(*args):
        original(*args);appliance['maps'].append({'protocol':'udp','dport':'50000','wanUUID':'VC:other'})
    monkeypatch.setattr(remote,'management_request',mutate)
    assert apply(spec())['outcome']=='uncertain' and appliance['calls']==1


def test_forward_rejects_old_generic_revision_before_management(monkeypatch):
    monkeypatch.setattr(remote,'management_request',lambda *a:pytest.fail('no API call'))
    with pytest.raises(remote.Unsupported,match='reviewed installed revision'):
        remote.management_guard(remote.MANAGEMENT_REVISION,'managed_forward')


def test_remote_workflow_projects_only_declared_policy_and_owned_maps(appliance,monkeypatch):
    from test_network_workflow import spec as workflow
    w=workflow()
    monkeypatch.setattr(remote,'management_guard',lambda *a:None)
    monkeypatch.setattr(remote,'managed_lifecycle_state',lambda s:{'fingerprint':'runtime','field':{'observed_connected':True}})
    monkeypatch.setattr(remote,'workflow_profile_version',lambda p:'files-'+p)
    before=remote.workflow_state({'spec':w,'revision':'reviewed'})
    appliance['policy']['profileId']='profile_b'
    for step in remote.workflow_specs(w)[2:]:appliance['maps'].append({**remote.forward_value(step),'active':True})
    after=remote.workflow_state({'spec':w,'revision':'reviewed'})
    assert before['stable']==after['stable'] and before['owned_forward_steps']==[] and after['owned_forward_steps']==[0,1]
    appliance['maps'][0]['toPort']='42000'
    with pytest.raises(remote.Unsupported,match='owned mapping changed'):remote.workflow_state({'spec':w,'revision':'reviewed'})
