"""Synthetic contract fixtures; no vendor source or appliance state vendored."""
import hashlib,json
import pytest
from firewalla_mcp import remote
from test_vpn_firmware_contract import contract
from test_approval_bound_vpn import approved_config
from firewalla_mcp.writes import WriteManager

@pytest.fixture
def policy_contract(contract,monkeypatch):
    root,state,runner=contract;hashes={}
    for name in remote.POLICY_SOURCE_HASHES:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic '+name);hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest()
    monkeypatch.setattr(remote,'POLICY_SOURCE_HASHES',hashes)
    return root,state,runner

@pytest.mark.parametrize('revision',remote.VPN_MANAGEMENT_REVISIONS)
def test_policy_pins_with_translation_only_edit(policy_contract,revision):
    root,state,runner=policy_contract;state['revision']=revision
    assert remote.policy_source_guard(revision,str(root),runner)['policy_contract_files_verified']==5

@pytest.mark.parametrize('name',list(remote.POLICY_SOURCE_HASHES))
def test_policy_dependency_drift_rejected(policy_contract,name):
    root,state,runner=policy_contract;(root/name).write_text('drift')
    with pytest.raises(remote.Unsupported,match='digest'):remote.policy_source_guard(state['revision'],str(root),runner)

@pytest.mark.parametrize('kind,feature',[('managed_feature','adblock'),('managed_feature','safeSearch'),('managed_scoped','unbound'),('managed_rule',None)])
def test_management_dispatch_requires_policy_guard(monkeypatch,kind,feature):
    calls=[];monkeypatch.setattr(remote,'policy_source_guard',lambda revision:calls.append('policy'))
    monkeypatch.setattr(remote,'management_request',lambda *a:calls.append('ping'))
    remote.management_guard(remote.VPN_MANAGEMENT_REVISIONS[0],kind,feature)
    assert calls==['policy','ping']

@pytest.mark.parametrize('feature',['doh','ntp_redirect',None])
def test_unreviewed_service_rejected_before_api(monkeypatch,feature):
    monkeypatch.setattr(remote,'management_request',lambda *a:pytest.fail('must not contact API'))
    with pytest.raises(remote.Unsupported):remote.management_guard(remote.VPN_MANAGEMENT_REVISIONS[0],'managed_scoped',feature)

@pytest.mark.parametrize('count',[398,512,513])
def test_bounded_complete_rule_index(monkeypatch,count):
    def run(argv):
        if 'ZRANGE' in argv:
            assert argv[-1]=='512';return '\n'.join(str(i+1) for i in range(count))
        assert 'EVAL' in argv and int(argv[4])==count
        return json.dumps([['category','games','block','outbound','[]','0',False,False,False,False,False,False,'hash'] for _ in range(count)])
    monkeypatch.setattr(remote,'run',run)
    if count>512:
        with pytest.raises(remote.Unsupported):remote.managed_rule_snapshot()
    else:assert len(remote.managed_rule_snapshot())==count


def test_host_confirmed_current_control_validation(approved_config):
    c,_=approved_config;c=c.model_copy(update={'writes_enabled':True,'write_confirmation_mode':'host_confirmed'})
    m=WriteManager(c,None)
    spec=dict(kind='managed_feature',device='02:00:00:00:00:01',feature='unbound',desired='disable')
    assert m.validate('router-a',spec)
    with pytest.raises(ValueError,match='not reviewed'):m.validate('router-a',{**spec,'feature':'doh'})
