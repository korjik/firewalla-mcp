import copy
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from pydantic import ValidationError
from firewalla_mcp.models import Config,IPv6PolicyAction
from firewalla_mcp.server import build_server
from firewalla_mcp.forward_dispatch import handle
from firewalla_mcp.forward_transport import LifecycleSSH
from firewalla_mcp.ipv6_transport import IPv6SSH
from firewalla_mcp.ipv6_manager import IPv6Manager
from test_ipv6_lifecycle import setup,MAC,WAN,ACTION,window


def config(tmp_path,enabled):
    ledger=tmp_path/'ledger';ledger.mkdir(mode=0o700)
    journal=tmp_path/'journal';journal.mkdir(mode=0o700)
    return Config(sites={},writes_enabled=True,write_confirmation_mode='host_confirmed',vpn_target_policy='approval_bound',
        approval_consumed_directory=str(ledger),audit_file=str(tmp_path/'audit'),
        forwarding_recovery_directory=str(journal),ipv6_policy_enabled=enabled)

async def test_catalog_opt_in_and_mutation_annotations(tmp_path):
    c=config(tmp_path,False);assert not c.forwarding_lifecycle_enabled
    assert not any('ipv6' in t.name for t in await build_server(c).list_tools())
    c.ipv6_policy_enabled=True
    tools={t.name:t for t in await build_server(c).list_tools()}
    names={'inspect_ipv6_policies','preview_ipv6_policy_plan','apply_ipv6_policy_plan','preview_ipv6_policy_recovery'}
    assert names<=set(tools)
    assert tools['apply_ipv6_policy_plan'].annotations.readOnlyHint is False
    assert tools['apply_ipv6_policy_plan'].annotations.idempotentHint is False
    assert 'destination_ip' not in tools['preview_ipv6_policy_plan'].inputSchema['properties']
    assert tools['preview_ipv6_policy_plan'].annotations.readOnlyHint is True

@pytest.mark.parametrize('change',[{'source_network':'192.0.2.0/24'},{'source_network':'fe80::%eth0/64'},
 {'source_network':'2001:db8::1/64'},{'protocol':'tcp;id'},{'port':True},{'port':65536},{'origDst':'2001:db8::2'}])
def test_schema_rejects_mixed_or_expanded_scope(change):
    with pytest.raises(ValidationError):IPv6PolicyAction(**{**ACTION,**change})

def test_model_canonicalizes_ipv6_source():
    assert IPv6PolicyAction(**{**ACTION,'source_network':'2001:DB8:100::/48'}).source_network=='2001:db8:100::/48'

async def test_pinned_dispatch_transport_create_restart_and_recover(setup,monkeypatch):
    _,writes,_,store=setup
    class Site:
        management_revision='test'
        def model_copy(self,deep=False):return self
    writes.config.sites['router-a']=Site()
    requests=[]
    async def request(self,operation,arguments):
        req={'operation':operation,'revision':self.site.management_revision,'template':self.template,'arguments':arguments}
        requests.append(copy.deepcopy(req))
        # Wire serialization loses no ownership/allocation fields.
        return await handle(json.loads(json.dumps(req)))
    monkeypatch.setattr(LifecycleSSH,'request',request)
    m=IPv6Manager(writes,IPv6SSH)
    p=await m.preview('router-a',MAC,WAN,[ACTION],[],window())
    result=await m.apply(p['plan_id']);assert result['outcome']=='applied'
    assert all(r['template']['kind']=='ipv6_device_policy' for r in requests)
    assert any(r['arguments']['ipv6_owned'] for r in requests)
    m=IPv6Manager(writes,IPv6SSH)
    recovery=await m.recover(p['plan_id'],True,window())
    assert (await m.apply(recovery['plan_id']))['outcome']=='applied'
    assert store['policies']==[]

async def test_ipv6_dispatch_rejects_nat_receipts(setup):
    template={'kind':'ipv6_device_policy','device':MAC,'interface_uuid':WAN,'maintenance_until':window()}
    with pytest.raises(ValueError,match='cannot adopt'):
        await handle({'operation':'snapshot','revision':'test','template':template,'arguments':{'receipts':[{}]}})

async def test_transport_rejects_altered_allocated_target(setup,monkeypatch):
    from firewalla_mcp.ipv6_policy import native_allow
    site=SimpleNamespace(management_revision='test')
    template={'kind':'ipv6_device_policy','device':MAC,'interface_uuid':WAN,'maintenance_until':window()}
    t=IPv6SSH(site,template,[]);value=native_allow(MAC,WAN,'::/0','tcp',443,'a'*32)
    step={'key':'policy:ipv6:'+'a'*32,'after':{'value':value}}
    t.request=AsyncMock(return_value={'verified':True,'allocated_instance':{'key':step['key'],'value':{**value,'localPort':'80'},'instance':{'id':'123','birth':'1700000001'}}})
    with pytest.raises(ValueError,match='scope'):await t.mutate(step,'a'*64,int(time.time())+60)
    assert t.owned==[]
