import asyncio
import copy
import time
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp.probe_grants import ProbeGrants,JOURNAL_ID
from firewalla_mcp.server import build_server
from test_writes import manager

@pytest.fixture
def grants(manager,tmp_path):
    path=tmp_path/'grants';path.mkdir(mode=0o700)
    manager.config.diagnostic_grants_enabled=True;manager.config.diagnostic_grants_directory=str(path)
    manager.transport.run=AsyncMock(return_value={'status':'ok','data':{'connected':True}})
    return ProbeGrants(manager)

def grant(g,**kw):
    p=g.preview_grant('router-a',kw.get('address','10.20.30.40'),kw.get('ports',[80,443]),kw.get('ttl',600))
    return p,g.apply(p['plan_id'])

async def test_exact_scope_restart_revoke_and_existing_config_preserved(grants):
    g=grants;before=copy.deepcopy(g.config.model_dump());p,r=grant(g)
    assert g.config.model_dump()==before and not g.writes.transport.run.called
    restarted=ProbeGrants(g.writes)
    await restarted.probe('router-a','10.20.30.40',80)
    assert restarted.inventory()['grants'][0]['used']==1
    with pytest.raises(ValueError):await restarted.probe('router-a','10.20.30.40',81)
    with pytest.raises(ValueError):await restarted.probe('router-b','10.20.30.40',80)
    rev=restarted.preview_revoke(r['grant_id']);restarted.apply(rev['plan_id'])
    with pytest.raises(ValueError):await restarted.probe('router-a','10.20.30.40',80)
    assert g.writes.transport.run.call_count==1
    with pytest.raises(ValueError):restarted.apply(p['plan_id'])

@pytest.mark.parametrize('address',['127.0.0.1','0.0.0.0','169.254.169.254','100.100.100.200','168.63.129.16','224.0.0.1','255.255.255.255','198.18.0.1','100.64.0.1','::1','::ffff:10.20.30.40','fe80::1%eth0','example.org','10.0.0.0/24','10.0.0.1;id'])
def test_special_use_hosts_networks_and_injection_rejected(grants,address):
    with pytest.raises(ValueError):grants.preview_grant('router-a',address,[80],600)

@pytest.mark.parametrize('ports',[[0],[65536],[True],['80'],[80,80],[],list(range(1,10)),['80-443']])
def test_port_bounds(grants,ports):
    with pytest.raises(ValueError):grants.preview_grant('router-a','10.20.30.40',ports,600)

@pytest.mark.parametrize('address',['10.20.30.40','172.20.0.10','192.168.50.20','8.8.8.8'])
def test_private_public_exact_grants(grants,address):
    assert grants.preview_grant('router-a',address,[81,443],600)['grant']['address']==address

def test_protected_configured_hosts_and_deny_list(grants):
    grants.config.diagnostic_grants_deny_addresses=['10.20.30.40']
    with pytest.raises(ValueError,match='Protected'):grants.preview_grant('router-a','10.20.30.40',[80],600)
    with pytest.raises(ValueError,match='Protected'):grants.preview_grant('router-a',grants.config.sites['router-a'].host,[80],600)

async def test_expiry_replay_tamper_and_config_drift(grants,monkeypatch):
    now=time.time();monkeypatch.setattr('firewalla_mcp.probe_grants.time.time',lambda:now)
    p,r=grant(grants,ttl=60)
    with pytest.raises(ValueError):grants.apply(p['plan_id'])
    p=grants.preview_grant('router-a','10.20.30.41',[443],600)
    grants.plans[p['plan_id']]['grant']['ports']=[22]
    with pytest.raises(ValueError,match='changed'):grants.apply(p['plan_id'])
    monkeypatch.setattr('firewalla_mcp.probe_grants.time.time',lambda:now+61)
    with pytest.raises(ValueError):await grants.probe('router-a','10.20.30.40',80)
    p=grants.preview_grant('router-a','10.20.30.41',[443],600)
    grants.config.sites['router-a'].host='10.0.0.254'
    with pytest.raises(ValueError,match='changed'):grants.apply(p['plan_id'])

async def test_attempt_limit_and_busy_revoke(grants):
    p,r=grant(grants)
    started=asyncio.Event();release=asyncio.Event()
    async def slow(*args,**kwargs):started.set();await release.wait();return {'status':'ok'}
    grants.writes.transport.run.side_effect=slow
    task=asyncio.create_task(grants.probe('router-a','10.20.30.40',80));await started.wait()
    with pytest.raises(BlockingIOError):ProbeGrants(grants.writes).preview_revoke(r['grant_id'])
    release.set();await task;grants.writes.transport.run.side_effect=None
    for _ in range(15):await grants.probe('router-a','10.20.30.40',80)
    with pytest.raises(ValueError):await grants.probe('router-a','10.20.30.40',80)
    assert grants.writes.transport.run.call_count==16

async def test_catalog_opt_in_and_tcp_integration(grants):
    g=grants;server=build_server(g.config,g.writes.transport)
    names={t.name for t in await server.list_tools()}
    assert {'preview_diagnostic_grant','preview_diagnostic_revoke','apply_diagnostic_grant_plan','diagnostic_grants'}<=names
    p,r=grant(g)
    await server.call_tool('tcp_probe',{'box_name':'router-a','address':'10.20.30.40','port':80})
    assert g.writes.transport.run.call_count==1
    with pytest.raises(Exception):await server.call_tool('tcp_probe',{'box_name':'router-a','address':'10.20.30.40','port':81})
    assert g.writes.transport.run.call_count==1
    g.config.diagnostic_grants_enabled=False
    assert 'diagnostic_grants' not in {t.name for t in await build_server(g.config).list_tools()}

async def test_legacy_network_permission_remains_independent(grants):
    g=grants;g.config.sites['router-a'].probe_networks=['10.20.30.0/24']
    p,r=grant(g);rev=g.preview_revoke(r['grant_id']);g.apply(rev['plan_id'])
    await build_server(g.config,g.writes.transport).call_tool('tcp_probe',{'box_name':'router-a','address':'10.20.30.40','port':81})
    assert g.writes.transport.run.call_count==1

def test_journal_torn_record_fail_closed(grants):
    grant(grants)
    path=grants.journal.root.path(JOURNAL_ID).with_suffix('.journal')
    with path.open('ab') as f:f.write(b'{')
    with pytest.raises(ValueError,match='interrupted'):ProbeGrants(grants.writes).inventory()


async def test_queued_transport_rechecks_expiry_after_capacity(grants,monkeypatch):
    from firewalla_mcp.transport import SSHTransport
    transport=SSHTransport();transport.limit=asyncio.Semaphore(0)
    now=[time.time()];monkeypatch.setattr('firewalla_mcp.transport.time.time',lambda:now[0])
    spawn=AsyncMock();monkeypatch.setattr('firewalla_mcp.transport.asyncio.create_subprocess_exec',spawn)
    pending=asyncio.create_task(transport.run(grants.config.sites['router-a'],'tcp',{'address':'10.20.30.40','port':80},dispatch_deadline=now[0]+10))
    await asyncio.sleep(0);now[0]+=11;transport.limit.release()
    result=await pending
    assert result['status']=='unavailable' and 'expired' in result['reason']
    spawn.assert_not_called()


def test_permission_state_separate_from_other_ledgers(grants):
    grants.config.diagnostic_grants_directory=grants.config.approval_consumed_directory
    with pytest.raises(ValueError,match='separate'):ProbeGrants(grants.writes)

async def test_scope_change_invalidates_use_but_preserves_history_and_revoke(grants):
    p,r=grant(grants)
    grants.config.diagnostic_grants_deny_addresses=['10.20.30.40']
    assert grants.inventory()['grants'][0]['active'] is False
    with pytest.raises(ValueError):await grants.probe('router-a','10.20.30.40',80)
    rev=grants.preview_revoke(r['grant_id']);assert grants.apply(rev['plan_id'])['status']=='applied'
