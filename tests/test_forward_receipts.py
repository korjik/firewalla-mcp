import copy
import os
from pathlib import Path
import pytest
from firewalla_mcp.forward_receipts import ForwardReceipts
from firewalla_mcp.writes import WriteManager
from test_writes import manager
from test_interface_forward import wan_spec

@pytest.fixture
def receipts(tmp_path):
    p=tmp_path/'receipts';p.mkdir(mode=0o700)
    return ForwardReceipts(str(p))

def test_exclusive_start_and_completed_transition(receipts):
    p={'plan_id':'a'*32,'digest':'b'*64}
    receipts.save(p,'started')
    with pytest.raises(FileExistsError):receipts.save(p,'started')
    receipts.save(p,'completed')
    assert receipts.load('a'*32)['phase']=='completed'
    with pytest.raises(ValueError):receipts.save(p,'completed')

@pytest.mark.parametrize('ident',['../x','A'*32,'x'*33,''])
def test_invalid_identifier(receipts,ident):
    with pytest.raises(ValueError):receipts.load(ident)

def test_symlink_and_world_readable_rejected(receipts,tmp_path):
    target=tmp_path/'target';target.write_text('{}')
    receipts.path('a'*32).symlink_to(target)
    with pytest.raises(OSError):receipts.load('a'*32)
    p={'plan_id':'b'*32,'digest':'c'*64};receipts.save(p,'started')
    receipts.path('b'*32).chmod(0o644)
    with pytest.raises(ValueError):receipts.load('b'*32)

async def completed(manager,monkeypatch,tmp_path):
    p=tmp_path/'durable';p.mkdir(mode=0o700)
    manager.config.forwarding_recovery_directory=str(p)
    manager.forward_receipts=ForwardReceipts(str(p))
    monkeypatch.setattr(manager,'validate',lambda *args:manager.config.sites['router-a'])
    plan=await manager.preview('router-a',wan_spec())
    manager.transport.run.return_value={'status':'ok','data':{'outcome':'applied','verification':'stored_mapping_verified','context':{'owner_token':plan['spec']['owner_token']},'state':{'fingerprint':'b'*64,'present':True}}}
    await manager.apply(plan['plan_id'])
    return plan

async def test_restart_new_confirmed_rollback_plan(manager,monkeypatch,tmp_path):
    plan=await completed(manager,monkeypatch,tmp_path)
    fresh=WriteManager(manager.config,manager.transport)
    monkeypatch.setattr(fresh,'validate',lambda *args:manager.config.sites['router-a'])
    manager.transport.run.return_value={'status':'ok','data':{'fingerprint':'b'*64,'present':True}}
    rollback=await fresh.rollback_preview(plan['plan_id'])
    assert rollback['mode']=='rollback' and rollback['plan_id']!=plan['plan_id']
    assert rollback['target_authorization']=='trusted_mcp_host_confirmation'
    assert manager.transport.run.call_args.args[2]['mode']=='preview'

async def test_restart_drift_cannot_delete(manager,monkeypatch,tmp_path):
    plan=await completed(manager,monkeypatch,tmp_path)
    fresh=WriteManager(manager.config,manager.transport)
    monkeypatch.setattr(fresh,'validate',lambda *args:manager.config.sites['router-a'])
    manager.transport.run.return_value={'status':'ok','data':{'fingerprint':'c'*64,'present':True}}
    assert (await fresh.rollback_preview(plan['plan_id']))['status']=='stale'

async def test_started_receipt_never_autoretries(manager,monkeypatch,tmp_path):
    plan=await completed(manager,monkeypatch,tmp_path)
    p=manager.forward_receipts.path(plan['plan_id'])
    import json
    d=json.loads(p.read_text());d['phase']='started';p.write_text(json.dumps(d))
    fresh=WriteManager(manager.config,manager.transport)
    with pytest.raises(ValueError,match='interrupted'):await fresh.rollback_preview(plan['plan_id'])

async def test_expired_memory_uses_durable_receipt_for_repeat_inspection(manager,monkeypatch,tmp_path):
    from firewalla_mcp.writes import digest
    plan=await completed(manager,monkeypatch,tmp_path)
    # Simulate time passage without altering the signed plan material.
    import firewalla_mcp.writes as writes
    monkeypatch.setattr(writes.time,'time',lambda:plan['expires_at']+1)
    manager.transport.run.return_value={'status':'ok','data':{'fingerprint':'c'*64,'present':True}}
    assert (await manager.rollback_preview(plan['plan_id']))['status']=='stale'
    assert (await manager.rollback_preview(plan['plan_id']))['status']=='stale'
    manager.transport.run.return_value={'status':'ok','data':{'fingerprint':'b'*64,'present':True}}
    rollback=await manager.rollback_preview(plan['plan_id'])
    assert rollback['expires_at']>writes.time.time() and rollback['mode']=='rollback'
