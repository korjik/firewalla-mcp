import pytest
from firewalla_mcp.models import Config
from firewalla_mcp.vpn_writes import VPNWriteManager
from test_approval_bound_vpn import approved_config, Appliance, LIFE

@pytest.mark.parametrize("legacy",[
    {"write_confirmation_mode":"operator"}, {"vpn_confirmation_mode":"operator"},
    {"approval_directory":"/old"}, {"approval_issuer":None}, {"trusted_approval_uid":0},
    {"writes_enabled":True}, {"vpn_writes_enabled":True}, {"writes_enabled":"true"}, {"vpn_writes_enabled":1}])
def test_legacy_configs_fail_closed_with_migration(legacy):
    with pytest.raises(ValueError,match="[Mm]igrat|migration"):
        Config(sites={},**legacy)

async def test_guidance_only_uses_internal_ssh_and_plan(approved_config):
    config,_=approved_config;router=Appliance();m=VPNWriteManager(config,router)
    plan=await m.preview("router-a",LIFE);step=plan["next_step"]
    assert step["mechanism"]=="trusted_mcp_host"
    assert step["apply_arguments"]=={"plan_id":plan["plan_id"]}
    assert "ssh_command" not in step and "approval_document" not in plan
    assert step["requires_exact_user_confirmation"]
    assert router.mutations==0
