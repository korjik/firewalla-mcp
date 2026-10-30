import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp import remote
from firewalla_mcp.models import Config,Site
from firewalla_mcp.vpn_writes import VPNWriteManager
from firewalla_mcp.vpn_import_mcp import ImportManager
from firewalla_mcp.writes import WriteManager
from firewalla_mcp.server import build_server
from test_vpn_mcp import dispatcher,LocalRPC
from test_vpn_import import sandbox,profile
from test_vpn_import_legacy import native_root_metadata

LIFE=dict(kind='managed_lifecycle',profile='profile_a',vpn_type='openvpn',desired='connect')
SWITCH=dict(kind='managed_vpn',device='02:00:00:00:00:01',expected_profile='profile_a',destination_profile='profile_b')


@pytest.fixture
def approved_config(tmp_path):
    ledger=tmp_path/'consumed';ledger.mkdir(mode=0o700)
    c=Config(sites={'router-a':Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',management_revision=remote.VPN_MANAGEMENT_REVISIONS[0])},
        aliases={'Router A':'router-a'},vpn_writes_enabled=True,vpn_target_policy='approval_bound',vpn_confirmation_mode='host_confirmed',
        approval_consumed_directory=str(ledger),audit_file=str(tmp_path/'audit'))
    return c,None


class Appliance:
    def __init__(self):self.state='a'*64;self.mutations=0;self.calls=[]
    async def run(self,site,operation,args):
        self.calls.append(copy.deepcopy(args));assert operation=='managed_write'
        if args['mode']=='preview':return {'status':'ok','data':{'fingerprint':self.state,'present':False,'field':{'state':True,'profileId':'profile_a'}}}
        if args['expected']!=self.state:return {'status':'ok','data':{'outcome':'stale','changed':False}}
        assert isinstance(args['expires_at'],int)
        self.mutations+=1
        return {'status':'ok','data':{'outcome':'applied'}}


@pytest.mark.parametrize('spec',[LIFE,SWITCH])
async def test_unlisted_target_host_confirmed_plan(approved_config,spec):
    config,issue=approved_config;router=Appliance();manager=VPNWriteManager(config,router)
    plan=await manager.preview('Router A',spec)
    assert plan['box']=='router-a' and plan['target_authorization']=='trusted_mcp_host_confirmation'
    assert not config.sites['router-a'].managed_devices and not config.sites['router-a'].managed_vpn_profiles
    assert router.mutations==0
    assert (await manager.apply(plan['plan_id']))['data']['outcome']=='applied'
    assert (await manager.apply(plan['plan_id']))['replayed'] and router.mutations==1






@pytest.mark.parametrize('field',['target','state','expiry','box_config'])
async def test_plan_and_target_tampering_rejected(approved_config,field):
    config,issue=approved_config;router=Appliance();manager=VPNWriteManager(config,router)
    plan=await manager.preview('router-a',LIFE)
    stored=manager.plans[plan['plan_id']]
    if field=='target':stored['spec']['profile']='other'
    if field=='state':stored['expected']='b'*64
    if field=='expiry':stored['expires_at']+=1
    if field=='box_config':manager.config.sites['router-a'].host='192.0.2.99'
    with pytest.raises(ValueError,match='changed'):await manager.apply(plan['plan_id'])
    assert router.mutations==0


async def test_returned_preview_cannot_change_internal_plan(approved_config):
    config,issue=approved_config;manager=VPNWriteManager(config,Appliance())
    plan=await manager.preview('router-a',LIFE);plan['spec']['profile']='other';plan['diff']['object']['profile']='third'
    assert manager.plans[plan['plan_id']]['spec']['profile']=='profile_a'


async def test_state_drift_consumes_approval_without_mutating(approved_config):
    config,issue=approved_config;router=Appliance();manager=VPNWriteManager(config,router)
    plan=await manager.preview('router-a',LIFE);router.state='b'*64
    assert (await manager.apply(plan['plan_id']))['data']['outcome']=='stale'
    assert (await manager.apply(plan['plan_id']))['replayed'] and router.mutations==0


async def test_durable_replay_guard_survives_manager_recreation(approved_config):
    config,issue=approved_config;router=Appliance();manager=VPNWriteManager(config,router)
    plan=await manager.preview('router-a',LIFE);saved=copy.deepcopy(manager.plans)
    await manager.apply(plan['plan_id'])
    restarted=VPNWriteManager(config,router);restarted.plans=saved
    with pytest.raises(ValueError,match='consumed'):await restarted.apply(plan['plan_id'])
    assert router.mutations==1


async def test_expiry_and_unsupported_scope(approved_config,monkeypatch):
    config,issue=approved_config;router=Appliance();manager=VPNWriteManager(config,router)
    for spec in ({'kind':'route'},{**LIFE,'profile':'../../key'},{**LIFE,'vpn_type':'shell'}):
        with pytest.raises(ValueError):await manager.preview('router-a',spec)
    assert not router.calls
    plan=await manager.preview('router-a',LIFE)
    monkeypatch.setattr('firewalla_mcp.writes.time.time',lambda:plan['expires_at']+1)
    with pytest.raises(ValueError,match='expired'):await manager.apply(plan['plan_id'])
    assert router.mutations==0


async def test_box_change_during_preview_does_not_create_plan(approved_config):
    config,_=approved_config;router=Appliance();manager=VPNWriteManager(config,router);original=router.run
    async def changed(*args):
        result=await original(*args);manager.config.sites['router-a'].host='192.0.2.99';return result
    router.run=changed
    with pytest.raises(ValueError,match='during preview'):await manager.preview('router-a',LIFE)
    assert manager.plans=={}


async def test_generic_write_manager_does_not_inherit_scope_relaxation(approved_config):
    config,_=approved_config;config.writes_enabled=True
    with pytest.raises(ValueError,match='host_confirmed'):WriteManager(config,Appliance()).validate('router-a',LIFE)


async def test_mcp_boolean_is_not_approval_and_no_approval_tool(approved_config):
    config,_=approved_config;router=Appliance();server=build_server(config,router,vpn_write_catalog=True)
    tools={t.name:t for t in await server.list_tools()};assert not any(t.startswith('approve') for t in tools)
    assert set(tools['apply_vpn_change'].inputSchema['properties'])=={'plan_id'}
    preview=await server.call_tool('preview_vpn_lifecycle',{'box_name':'router-a','profile':'profile_a','vpn_type':'openvpn','desired':'connect'})
    # SDK ignores unknown fields: they are not consent attestations. A wrong
    # plan still fails regardless of claimed consent, before router dispatch.
    with pytest.raises(Exception):await server.call_tool('apply_vpn_change',{'plan_id':'0'*32,'approved':True,'user_confirmed':True})
    assert router.mutations==0


@pytest.mark.parametrize('source_permission',['owner_only','existing_0644'])
async def test_import_registered_archive_host_confirmation(approved_config,dispatcher,source_permission):
    config,issue=approved_config;d,root,values=dispatcher
    policy=json.loads(d.policy_file.read_text());policy.update(target_policy='approval_bound',sources={},archives=[],source_permission_modes=['owner_only','existing_0644']);d.policy_file.write_text(json.dumps(policy))
    if source_permission=='existing_0644':(root/'source.userpass').chmod(0o644)
    before=(root/'source.userpass').stat().st_mode
    import time
    manager=ImportManager(config,LocalRPC(d))
    plan=await manager.preview_import('Router A','source','sample','0644',int(time.time())+300,source_permission)
    assert plan['preview']['source_permission']==source_permission and plan['preview']['target_policy']=='approval_bound'
    assert 'synthetic-password' not in json.dumps(plan)
    assert 'approval_document' not in plan and 'ssh_command' not in plan['next_step']
    result=await manager.apply_import(plan['plan_id'])
    assert result['data']['state']=='imported_unassigned_passive_checks'
    assert (root/'source.userpass').stat().st_mode==before
    for target in result['data']['profiles']:assert (root/(target+'.userpass')).read_bytes()==values['userpass']




def test_remote_expiry_is_checked_before_management(monkeypatch):
    monkeypatch.setattr(remote,'management_guard',lambda *args:pytest.fail('expired request must stop before API'))
    for expiry in (None,True,1,99999999999):
        with pytest.raises(ValueError,match='deadline'):remote.managed_write({'mode':'apply','spec':dict(LIFE),'expires_at':expiry})
