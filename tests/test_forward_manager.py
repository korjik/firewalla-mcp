import time
from pathlib import Path
import pytest
from firewalla_mcp.forward_manager import ForwardManager
from firewalla_mcp.forward_native import NativeForwardAdapter
from firewalla_mcp.server import build_server
from test_forward_native import native_fixture
from test_writes import manager
from test_forward_lifecycle import ACTIONS

@pytest.fixture
def coordinator(manager,native_fixture,tmp_path):
    adapter,tx,spec,store=native_fixture
    manager.config.forwarding_recovery_directory=tx.journals.root.directory
    manager.config.forwarding_lifecycle_enabled=True
    manager.config.sites['router-a'].management_revision=adapter.revision
    return ForwardManager(manager,lambda site,template:NativeForwardAdapter(site.management_revision,template)),spec,store

async def test_host_confirmed_preview_apply_restart_recovery(coordinator):
    fm,spec,store=coordinator
    p=await fm.preview('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'],[ACTIONS[1]],[],int(time.time())+300)
    assert p['disclosures'][0]['dnat_required'] is False
    assert not store['calls']
    assert (await fm.apply(p['plan_id']))['outcome']=='applied'
    with pytest.raises(ValueError):await fm.apply(p['plan_id'])
    fresh=ForwardManager(fm.writes,fm.adapter_factory)
    recovery=await fresh.recover(p['plan_id'],True,int(time.time())+300)
    assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
    assert not store['maps'] and not store['policies']
    assert len(list(Path(fm.config.approval_consumed_directory).glob('*.used')))==2

async def test_optional_tools_and_typed_advertised_fields(coordinator):
    fm,_,_=coordinator
    server=build_server(fm.config)
    tools={t.name:t for t in await server.list_tools()}
    for name in ('inspect_forwarding_lifecycle','preview_forwarding_lifecycle','apply_forwarding_lifecycle','preview_forwarding_recovery'):assert name in tools
    schema=tools['preview_forwarding_lifecycle'].inputSchema
    assert schema['$defs']['LifecycleAction']['properties']['protocol']['const']=='tcp'
    assert tools['apply_forwarding_lifecycle'].annotations.readOnlyHint is False
    fm.config.forwarding_lifecycle_enabled=False
    assert 'apply_forwarding_lifecycle' not in {t.name for t in await build_server(fm.config).list_tools()}

async def test_modified_disclosures_are_bound(coordinator):
    fm,spec,store=coordinator
    p=await fm.preview('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'],[ACTIONS[1]],[],int(time.time())+300)
    fm.plans[p['plan_id']]['disclosures'][0]['dnat_required']=True
    with pytest.raises(ValueError,match='changed'):await fm.apply(p['plan_id'])
    assert not store['calls']
