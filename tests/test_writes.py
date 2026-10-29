import copy
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp.models import Config,Site
from firewalla_mcp.writes import WriteManager
from firewalla_mcp import remote

SPEC=dict(kind="route",destination="192.0.2.0/24",table=42420,route_type="blackhole",gateway=None,interface=None)

@pytest.fixture
def manager(tmp_path):
    approvals=tmp_path/'approvals';approvals.mkdir(mode=0o700)
    site=Site(host="192.0.2.1",identity_file="/key",known_hosts_file="/known_hosts",vantage_group="a",allowed_route_tables=[42420],allowed_filter_chains=["TEST"],allowed_nat_chains=["TESTNAT"])
    config=Config(sites={"router-a":site},writes_enabled=True,approval_directory=str(approvals),audit_file=str(tmp_path/'audit.jsonl'))
    transport=AsyncMock();transport.run.return_value={"status":"ok","data":{"fingerprint":"a"*64,"present":False}}
    return WriteManager(config,transport)

def approve(plan):
    p=Path(plan['approval_file']);p.write_text(json.dumps(plan['approval_document']));p.chmod(0o600)

async def test_default_disabled(manager):
    manager.config.writes_enabled=False
    with pytest.raises(ValueError,match="disabled"): await manager.preview("router-a",copy.deepcopy(SPEC))
    manager.transport.run.assert_not_called()

@pytest.mark.parametrize("field,value",[("table",254),("table",42421),("destination","192.0.2.0/24;id"),("gateway","192.0.2.1"),("interface","x;id"),("route_type","throw")])
async def test_bad_route(manager,field,value):
    spec=copy.deepcopy(SPEC);spec[field]=value
    with pytest.raises(ValueError):await manager.preview("router-a",spec)
    manager.transport.run.assert_not_called()

async def test_no_approval_no_mutation(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));manager.transport.reset_mock()
    with pytest.raises(ValueError,match="approval"):await manager.apply(plan['plan_id'])
    manager.transport.run.assert_not_called()

async def test_wrong_digest(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));plan['approval_document']['digest']='b'*64;approve(plan)
    with pytest.raises(ValueError,match="match"):await manager.apply(plan['plan_id'])
    assert manager.transport.run.await_count==1

async def test_expired(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));approve(plan)
    manager.plans[plan['plan_id']]['expires_at']=0
    with pytest.raises(ValueError,match="expired"):await manager.apply(plan['plan_id'])

async def test_apply_idempotent_and_rollback(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));approve(plan)
    manager.transport.run.return_value={"status":"ok","data":{"outcome":"applied","changed":True,"state":{"fingerprint":"b"*64,"present":True}}}
    await manager.apply(plan['plan_id'])
    count=manager.transport.run.await_count
    assert (await manager.apply(plan['plan_id']))['replayed']
    assert manager.transport.run.await_count==count
    manager.transport.run.return_value={"status":"ok","data":{"fingerprint":"b"*64,"present":True}}
    rollback=await manager.rollback_preview(plan['plan_id'])
    assert rollback['mode']=='rollback'
    with pytest.raises(ValueError):await manager.apply(rollback['plan_id'])
    approve(rollback)
    manager.transport.run.return_value={"status":"ok","data":{"outcome":"rolled_back","state":{"fingerprint":"a"*64,"present":False}}}
    assert (await manager.apply(rollback['plan_id']))['data']['outcome']=='rolled_back'
    audit=Path(manager.config.audit_file).read_text()
    assert '192.0.2' not in audit and 'gateway' not in audit

async def test_uncertain_never_retry(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));approve(plan)
    manager.transport.run.return_value={"status":"unavailable","reason":"timeout"}
    await manager.apply(plan['plan_id'])
    count=manager.transport.run.await_count
    assert (await manager.apply(plan['plan_id']))['status']=='uncertain'
    assert manager.transport.run.await_count==count
    with pytest.raises(ValueError):await manager.rollback_preview(plan['plan_id'])

async def test_rollback_stale(manager):
    plan=await manager.preview("router-a",copy.deepcopy(SPEC));approve(plan)
    manager.transport.run.return_value={"status":"ok","data":{"outcome":"applied","state":{"fingerprint":"b"*64,"present":True}}}
    await manager.apply(plan['plan_id'])
    manager.transport.run.return_value={"status":"ok","data":{"fingerprint":"c"*64,"present":True}}
    assert (await manager.rollback_preview(plan['plan_id']))['status']=='stale'

async def test_existing_not_replaced(manager):
    manager.transport.run.return_value={"status":"ok","data":{"fingerprint":"a"*64,"present":True}}
    assert (await manager.preview('router-a',copy.deepcopy(SPEC)))['status']=='no_change'

async def test_symlink_approval_rejected(manager,tmp_path):
    plan=await manager.preview('router-a',copy.deepcopy(SPEC))
    target=tmp_path/'target';target.write_text(json.dumps(plan['approval_document']))
    Path(plan['approval_file']).symlink_to(target)
    with pytest.raises(ValueError):await manager.apply(plan['plan_id'])
    assert manager.transport.run.await_count==1

async def test_audit_failure_prevents_mutation(manager):
    plan=await manager.preview('router-a',copy.deepcopy(SPEC));approve(plan)
    manager.config.audit_file='/nonexistent/audit'
    with pytest.raises(OSError):await manager.apply(plan['plan_id'])
    assert manager.transport.run.await_count==1

@pytest.mark.parametrize('kind',['filter_rule','dnat'])
async def test_rule_previews(manager,kind):
    if kind=='filter_rule':
        spec=dict(kind=kind,chain='TEST',source='192.0.2.0/24',destination='198.51.100.0/24',protocol='tcp',destination_port=443,action='DROP')
    else:
        spec=dict(kind=kind,chain='TESTNAT',public_address='203.0.113.1',interface='eth0',protocol='tcp',external_port=443,destination_address='192.0.2.2',destination_port=443)
    plan=await manager.preview('router-a',spec)
    argv,tag=remote.write_spec(plan['spec'])
    assert tag.startswith('fw-mcp-') and '-A' in argv
    spec['chain']='FORWARD'
    with pytest.raises(ValueError):await manager.preview('router-a',spec)

@pytest.mark.parametrize('change',[{'destination':'x;id'},{'table':254},{'interface':'$(id)'},{'route_type':'unreachable'}])
def test_remote_revalidates(change):
    spec={**SPEC,**change}
    with pytest.raises((ValueError,TypeError)):remote.write_spec(spec)

def test_remote_cas_no_mutation(monkeypatch):
    monkeypatch.setattr(remote,'write_state',lambda spec:{'fingerprint':'b'*64,'present':False})
    monkeypatch.setattr(remote,'run',lambda *a:pytest.fail('mutation forbidden'))
    result=remote.write_operation({'mode':'apply','spec':SPEC,'expected':'a'*64})
    assert result['outcome']=='stale' and result['changed'] is False

def test_remote_route_apply_rollback(monkeypatch):
    present=False
    calls=[]
    def state(spec):return {'fingerprint':('b' if present else 'a')*64,'present':present}
    def run(argv):
        nonlocal present
        calls.append(argv);present='add' in argv
        return ''
    monkeypatch.setattr(remote,'write_state',state);monkeypatch.setattr(remote,'run',run)
    assert remote.write_operation({'mode':'apply','spec':SPEC,'expected':'a'*64})['outcome']=='applied'
    assert remote.write_operation({'mode':'rollback','spec':SPEC,'expected':'b'*64})['outcome']=='rolled_back'
    assert calls[0][:6]==['sudo','-n','ip','-4','route','add']
    assert calls[1][:6]==['sudo','-n','ip','-4','route','del']

def test_remote_mutation_timeout_uncertain(monkeypatch):
    monkeypatch.setattr(remote,'write_state',lambda spec:{'fingerprint':'a'*64,'present':False})
    def fail(*a):raise remote.Unsupported('timeout')
    monkeypatch.setattr(remote,'run',fail)
    assert remote.write_operation({'mode':'apply','spec':SPEC,'expected':'a'*64})['outcome']=='uncertain'

async def test_concurrent_apply_only_once(manager):
    import asyncio
    plan=await manager.preview('router-a',copy.deepcopy(SPEC));approve(plan)
    manager.transport.run.return_value={'status':'ok','data':{'outcome':'applied','state':{'fingerprint':'b'*64,'present':True}}}
    await asyncio.gather(manager.apply(plan['plan_id']),manager.apply(plan['plan_id']))
    assert manager.transport.run.await_count==2 # preview plus one apply
