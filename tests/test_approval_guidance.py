import json
import shlex
import pytest
from pydantic import ValidationError
from firewalla_mcp.models import ApprovalIssuer
from firewalla_mcp.vpn_writes import VPNWriteManager
from firewalla_mcp.server import build_server
from test_approval_bound_vpn import approved_config, Appliance, LIFE

ISSUER=dict(ssh_host='mcp-host',python='/usr/bin/python3',script='/usr/local/libexec/firewalla-vpn-approve.py')

async def test_preview_and_error_discover_exact_ssh_step(approved_config):
    config,issue=approved_config;config.approval_issuer=ApprovalIssuer(**ISSUER)
    router=Appliance();manager=VPNWriteManager(config,router)
    plan=await manager.preview('router-a',LIFE);step=plan['next_step']
    assert step['ssh_host']=='mcp-host'
    argv=shlex.split(step['ssh_command']);assert argv[-6:]==['--plan-id',plan['plan_id'],'--digest',plan['digest'],'--expires-at',str(plan['expires_at'])]
    assert step['apply_tool']=='apply_vpn_change' and step['requires_exact_user_confirmation'] is True
    with pytest.raises(ValueError) as error:await manager.apply(plan['plan_id'])
    payload=json.loads(str(error.value));assert payload['next_step']==step
    assert router.mutations==0
    issue(plan);assert (await manager.apply(plan['plan_id']))['data']['outcome']=='applied'

async def test_unconfigured_does_not_guess_or_self_authorize(approved_config):
    config,_=approved_config;manager=VPNWriteManager(config,Appliance())
    step=(await manager.preview('router-a',LIFE))['next_step']
    assert step['status']=='issuer_not_configured' and 'ssh_command' not in step

async def test_issuer_change_invalidates_existing_plan(approved_config):
    config,issue=approved_config;config.approval_issuer=ApprovalIssuer(**ISSUER)
    manager=VPNWriteManager(config,Appliance());plan=await manager.preview('router-a',LIFE);issue(plan)
    manager.config.approval_issuer=ApprovalIssuer(**{**ISSUER,'ssh_host':'other-host'})
    with pytest.raises(ValueError,match='configuration binding changed'):await manager.apply(plan['plan_id'])

@pytest.mark.parametrize('changes',[{'ssh_host':'host;id'},{'script':'/tmp/a\ncommand'},{'python':'python3'},{'script':'/tmp/../issuer'}])
def test_instruction_injection_rejected(changes):
    with pytest.raises(ValidationError):ApprovalIssuer(**{**ISSUER,**changes})

async def test_mcp_catalog_and_capabilities_explain_external_step(approved_config):
    config,_=approved_config;config.approval_issuer=ApprovalIssuer(**ISSUER)
    server=build_server(config,transport=Appliance(),vpn_write_catalog=True)
    tools={t.name:t for t in await server.list_tools()}
    assert 'authorized SSH' in tools['apply_vpn_change'].description
    result=await server.call_tool('write_capabilities',{})
    assert result[1]['approval_workflow']['ssh_host']=='mcp-host'
    result=await server.call_tool('preview_vpn_lifecycle',dict(box_name='router-a',profile='profile_a',vpn_type='openvpn',desired='connect'))
    assert result[1]['next_step']['ssh_command']
