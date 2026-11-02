import asyncio
import copy
import time
from types import SimpleNamespace

import pytest

from firewalla_mcp import ipv6_adapter as native
from firewalla_mcp.ipv6_adapter import IPv6Adapter, normalized
from firewalla_mcp.ipv6_manager import IPv6Manager
from firewalla_mcp.ipv6_policy import native_allow
from firewalla_mcp.writes import digest

MAC='02:00:00:00:00:01';WAN='11111111-1111-4111-8111-111111111111'
ACTION={'source_network':'2001:db8:100::/48','protocol':'tcp','port':443}

class Site:
    def model_copy(self,deep=False):return self

class Writes:
    def __init__(self,path):
        self.config=SimpleNamespace(ipv6_policy_enabled=True,forwarding_recovery_directory=str(path),sites={'router-a':Site()},resolve=lambda box:box)
        self.locks={'router-a':asyncio.Lock()};self.claims=set();self.binding='stable'
    def enabled(self):pass
    def site_binding(self,box):return self.binding
    def consume_approval(self,plan):
        if plan['plan_id'] in self.claims:raise ValueError('Consumed')
        self.claims.add(plan['plan_id'])
    def audit(self,*args):pass

@pytest.fixture
def setup(tmp_path,monkeypatch):
    path=tmp_path/'journal';path.mkdir(mode=0o700);writes=Writes(path)
    store={'policies':[],'next':100,'calls':[],'proof':True,'fail':False}
    monkeypatch.setattr(IPv6Adapter,'guard',lambda self:None)
    monkeypatch.setattr(IPv6Adapter,'environment',lambda self:{'revision':'test','device':MAC,'ipv6_addresses':['2001:db8::2'],'wan':WAN})
    monkeypatch.setattr(native,'read_projection',lambda run:copy.deepcopy(store['policies']))
    monkeypatch.setattr(IPv6Adapter,'proof',lambda self,row,enabled=None:store['proof'])
    def request(mode,command,target,payload,create=False):
        store['calls'].append((command,copy.deepcopy(payload)))
        assert mode=='cmd' and target=='0.0.0.0'
        assert command in ('policy:create','policy:enable','policy:disable','policy:delete')
        if store['fail']:raise OSError('uncertain dispatch')
        if command=='policy:create':
            pid=str(store['next']);store['next']+=1
            store['policies'].append({**payload,'pid':pid,'timestamp':str(1700000000+store['next']),
                                      'identity_complete':True,'full_fingerprint':digest(payload)[:40]})
            return pid
        p=next(p for p in store['policies'] if p['pid']==payload['policyID'])
        if command=='policy:delete':store['policies'].remove(p)
        else:p['disabled']='0' if command=='policy:enable' else '1'
    monkeypatch.setattr(native.remote,'management_request',request)
    def factory(site,template,owned):return IPv6Adapter('test',template,owned)
    return IPv6Manager(writes,factory),writes,factory,store


def window():return int(time.time())+240

async def preview(manager,actions=None,removals=None):
    return await manager.preview('router-a',MAC,WAN,[ACTION] if actions is None else actions,removals or [],window())

async def test_create_inspect_remove_restart_restore(setup):
    manager,writes,factory,store=setup
    plan=await preview(manager)
    assert [s['operation'] for s in plan['steps']]==['create_disabled','enable']
    assert 'destination_ip' not in plan['template']
    assert (await manager.apply(plan['plan_id']))['outcome']=='applied'
    original_id=store['policies'][0]['pid']
    manager=IPv6Manager(writes,factory)
    view=await manager.inspect('router-a',MAC,WAN,window());assert len(view['owned_policies'])==1
    row=view['owned_policies'][0]
    removal=await preview(manager,[],[{'key':row['key'],'fingerprint':row['fingerprint']}])
    assert (await manager.apply(removal['plan_id']))['outcome']=='applied'
    assert store['policies']==[]
    manager=IPv6Manager(writes,factory)
    restore=await manager.recover(removal['plan_id'],True,window())
    assert (await manager.apply(restore['plan_id']))['outcome']=='applied'
    assert store['policies'][0]['pid']!=original_id
    view=await IPv6Manager(writes,factory).inspect('router-a',MAC,WAN,window())
    assert len(view['owned_policies'])==1 and view['owned_policies'][0]['enabled']
    assert all('origDst' not in payload and 'portforward' not in payload for _,payload in store['calls'])

async def test_unowned_equal_policy_is_never_adopted(setup):
    manager,writes,factory,store=setup
    p=native_allow(MAC,WAN,ACTION['source_network'],'tcp',443,'b'*32)
    store['policies']=[{**p,'pid':'99','timestamp':'1700000001','identity_complete':True,'full_fingerprint':'c'*40}]
    assert not (await manager.inspect('router-a',MAC,WAN,window()))['owned_policies']
    with pytest.raises(ValueError,match='Existing policy'):await preview(manager)
    assert not store['calls']

async def test_drift_replay_and_expired_plan(setup):
    manager,writes,factory,store=setup;plan=await preview(manager)
    writes.binding='changed'
    with pytest.raises(ValueError):await manager.apply(plan['plan_id'])
    assert not store['calls'];writes.binding='stable'
    assert (await manager.apply(plan['plan_id']))['outcome']=='applied'
    with pytest.raises(ValueError):await manager.apply(plan['plan_id'])
    plan2=await preview(manager,[{**ACTION,'port':444}])
    manager.plans[plan2['plan_id']]['expires_at']=0
    with pytest.raises(ValueError):await manager.apply(plan2['plan_id'])

async def test_uncertain_prior_state_never_blindly_retried(setup):
    manager,writes,factory,store=setup;plan=await preview(manager);store['fail']=True
    assert (await manager.apply(plan['plan_id']))['outcome']=='uncertain'
    with pytest.raises(ValueError):await manager.recover(plan['plan_id'],False,window())
    assert len(store['calls'])==1

async def test_flag_off_and_reference_block_removal(setup):
    manager,writes,factory,store=setup;plan=await preview(manager)
    writes.config.ipv6_policy_enabled=False
    with pytest.raises(ValueError):await manager.apply(plan['plan_id'])
    writes.config.ipv6_policy_enabled=True
    await manager.apply(plan['plan_id'])
    row=(await manager.inspect('router-a',MAC,WAN,window()))['owned_policies'][0]
    store['policies'].append({'pid':'9','timestamp':'1700000001','type':'category','target':'games','affectedPids':[row['instance']['id']],
                              'full_fingerprint':'f'*40,'identity_complete':False})
    with pytest.raises(ValueError,match='Referenced'):await preview(manager,[],[{'key':row['key'],'fingerprint':row['fingerprint']}])

async def test_replaced_birth_is_opaque_and_blocks_recovery(setup):
    manager,writes,factory,store=setup;plan=await preview(manager);await manager.apply(plan['plan_id'])
    store['policies'][0]['timestamp']='1800000000'
    fresh=IPv6Manager(writes,factory)
    assert not (await fresh.inspect('router-a',MAC,WAN,window()))['owned_policies']
    with pytest.raises(ValueError):await fresh.recover(plan['plan_id'],True,window())

@pytest.mark.parametrize('change',[{'origDst':'2001:db8::2'},{'purpose':'port_forwarding'},{'disabled':'maybe'},{'remotePort':'false'},{'scope':[MAC,MAC]}])
def test_unknown_native_metadata_rejected(change):
    row={**native_allow(MAC,WAN,'::/0','udp',443,'a'*32),'identity_complete':True,'pid':'99','timestamp':'1700000001',**change}
    with pytest.raises(ValueError):normalized(row)

async def test_duplicate_batch_and_unknown_removal_rejected(setup):
    manager,*_=setup
    with pytest.raises(ValueError):await preview(manager,[ACTION,ACTION])
    with pytest.raises(ValueError):await preview(manager,[],[{'key':'policy:99','fingerprint':'a'*64}])

async def test_policy_enable_failure_keeps_disabled_and_stops(setup,monkeypatch):
    manager,writes,factory,store=setup;plan=await preview(manager)
    real=native.remote.management_request
    def fail_enable(mode,command,target,payload,create=False):
        if command=='policy:enable':raise OSError('lost connection before unknown dispatch')
        return real(mode,command,target,payload,create)
    monkeypatch.setattr(native.remote,'management_request',fail_enable)
    result=await manager.apply(plan['plan_id'])
    assert result['outcome']=='uncertain' and result['completed']==1
    assert store['policies'][0]['disabled']=='1'
    with pytest.raises(ValueError):await manager.recover(plan['plan_id'],False,window())

async def test_changed_disclosure_cannot_apply(setup):
    manager,writes,factory,store=setup;plan=await preview(manager)
    manager.plans[plan['plan_id']]['disclosures'][0]['ipv6_sources']='::/0'
    with pytest.raises(ValueError):await manager.apply(plan['plan_id'])
    assert not store['calls']


def test_environment_only_bounded_device_fields_and_wan(monkeypatch):
    template={'kind':'ipv6_device_policy','device':MAC,'interface_uuid':WAN,'maintenance_until':window()}
    adapter=IPv6Adapter('test',template);calls=[]
    def run(args):
        calls.append(args)
        if args==['redis-cli','--raw','EXISTS','host:mac:'+MAC]:return '1'
        if args==['redis-cli','--raw','HGET','host:mac:'+MAC,'ipv6Addr']:return '["2001:db8::2"]'
        raise AssertionError('unexpected read')
    monkeypatch.setattr(native.remote,'run',run)
    monkeypatch.setattr(native.remote,'forward_networks',lambda:[{'uuid':WAN,'interface':'eth0','type':'wan','subnets':[]}])
    assert adapter.environment()['ipv6_addresses']==['2001:db8::2']
    assert len(calls)==2
    monkeypatch.setattr(native.remote,'run',lambda args:'1' if 'EXISTS' in args else '["fe80::1%eth0"]')
    with pytest.raises(ValueError):adapter.environment()

async def test_native_returning_old_pid_never_adopts(setup,monkeypatch):
    manager,writes,factory,store=setup
    store['policies'].append({'pid':'99','timestamp':'1700000001','type':'category','target':'games',
                              'full_fingerprint':'f'*40,'identity_complete':False})
    plan=await preview(manager)
    monkeypatch.setattr(native.remote,'management_request',lambda *args:'99')
    result=await manager.apply(plan['plan_id'])
    assert result['outcome']=='uncertain'
    assert not (await manager.inspect('router-a',MAC,WAN,window()))['owned_policies']
