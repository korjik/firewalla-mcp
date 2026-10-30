import copy
import pytest
from firewalla_mcp.models import Config
from firewalla_mcp.server import build_server
from firewalla_mcp.vpn_writes import VPNWriteManager
from firewalla_mcp.host_confirmation import claim
from test_approval_bound_vpn import approved_config, Appliance, LIFE

@pytest.fixture
def host_config(approved_config):
    config,_=approved_config
    return config.model_copy(update={'vpn_confirmation_mode':'host_confirmed','approval_directory':None,'approval_issuer':None})

async def test_mcp_preview_then_apply_no_external_issuer(host_config):
    router=Appliance();server=build_server(host_config,transport=router,vpn_write_catalog=True)
    r=await server.call_tool('preview_vpn_lifecycle',dict(box_name='Router A',profile='profile_a',vpn_type='openvpn',desired='connect'))
    p=r[1];assert p['approval_document'] is None and p['approval_file'] is None
    assert p['next_step']['mechanism']=='trusted_mcp_host' and 'ssh_command' not in p['next_step']
    assert router.mutations==0
    # Represents an authenticated host apply AFTER host confirmation. The server
    # intentionally cannot distinguish this from a host violating that policy.
    r=await server.call_tool('apply_vpn_change',p['next_step']['apply_arguments'])
    assert r[1]['data']['outcome']=='applied' and router.mutations==1
    await server.call_tool('apply_vpn_change',p['next_step']['apply_arguments']);assert router.mutations==1
    tools={t.name:t for t in await server.list_tools()}
    assert tools['apply_vpn_change'].annotations.readOnlyHint is False
    assert tools['apply_vpn_change'].annotations.destructiveHint is True
    assert set(tools['apply_vpn_change'].inputSchema['properties'])=={'plan_id'}
    caps=(await server.call_tool('write_capabilities',{}))[1]
    assert caps['confirmation_mode']=='host_confirmed'

async def test_state_drift_prevents_dispatch(host_config):
    router=Appliance();m=VPNWriteManager(host_config,router);p=await m.preview('router-a',LIFE)
    router.state='b'*64
    assert (await m.apply(p['plan_id']))['data']['outcome']=='stale';assert router.mutations==0

async def test_altered_target_and_mode_rejected(host_config):
    m=VPNWriteManager(host_config,Appliance());p=await m.preview('router-a',LIFE)
    m.plans[p['plan_id']]['spec']['profile']='other'
    with pytest.raises(ValueError,match='Plan changed'):await m.apply(p['plan_id'])
    m.plans[p['plan_id']]['spec']['profile']=LIFE['profile'];m.config.vpn_confirmation_mode='operator'
    # Configuration/issuer requirements fail closed before any dispatch.
    with pytest.raises(ValueError):await m.apply(p['plan_id'])

async def test_expiry_and_restart_replay_rejected(host_config):
    m=VPNWriteManager(host_config,Appliance());p=await m.preview('router-a',LIFE)
    original=copy.deepcopy(m.plans[p['plan_id']]);await m.apply(p['plan_id'])
    restarted=VPNWriteManager(host_config,Appliance());restarted.plans[p['plan_id']]=original
    with pytest.raises(ValueError,match='consumed'):await restarted.apply(p['plan_id'])
    with pytest.raises(ValueError,match='expired'):claim(host_config,{'expires_at':0})

async def test_no_unknown_plan_or_general_operation(host_config):
    m=VPNWriteManager(host_config,Appliance())
    with pytest.raises(ValueError,match='Unknown plan'):await m.apply('0'*32)
    with pytest.raises(ValueError,match='outside VPN'):await m.preview('router-a',{'kind':'managed_block'})
    with pytest.raises(ValueError,match='Unknown box'):await m.preview('unconfigured',LIFE)

def test_mode_is_opt_in_and_requires_ledger(host_config):
    assert Config.model_fields['vpn_confirmation_mode'].default=='operator'
    c=host_config.model_copy(update={'approval_consumed_directory':None})
    with pytest.raises(ValueError,match='ledger'):build_server(c,transport=Appliance(),vpn_write_catalog=True)
