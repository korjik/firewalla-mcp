"""Synthetic fixtures for the observed contract; no appliance policy/config data."""
import hashlib
import json
import os
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp import remote
from firewalla_mcp.models import Config,Site
from firewalla_mcp.vpn_writes import VPNWriteManager
from test_managed_extensions import lifecycle, LIFE


@pytest.fixture
def contract(tmp_path,monkeypatch):
    root=tmp_path/'source';root.mkdir()
    hashes={}
    for name in remote.VPN_SOURCE_HASHES:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(('synthetic contract '+name).encode());hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest()
    p=root/'locales/en.json';p.parent.mkdir();p.write_text(json.dumps({'notice':{'title':'Example'}}))
    monkeypatch.setattr(remote,'VPN_SOURCE_HASHES',hashes)
    state={'revision':remote.VPN_MANAGEMENT_REVISIONS[0],'tree':remote.VPN_SOURCE_TREE,'dirty':' M locales/en.json\0'}
    def runner(argv):
        if argv[-1]=='HEAD':return state['revision']
        if argv[-1]=='HEAD^{tree}':return state['tree']
        if 'status' in argv:return state['dirty']
        raise AssertionError(argv)
    return root,state,runner


@pytest.mark.parametrize('revision',remote.VPN_MANAGEMENT_REVISIONS)
def test_both_exact_revisions_accept_only_translation_edit(contract,revision):
    root,state,runner=contract;state['revision']=revision
    result=remote.vpn_source_guard(revision,str(root),runner)
    assert result['contract_files_verified']==11 and result['translation_only_edit']
    state['dirty']='';assert not remote.vpn_source_guard(revision,str(root),runner)['translation_only_edit']


@pytest.mark.parametrize('path',['controllers/netbot.js','net2/Monitorable.js','extension/vpnclient/OpenVPNClient.js','package.json','locales/zh.json'])
def test_meaningful_or_unreviewed_dirty_file_rejected(contract,path):
    root,state,runner=contract;state['dirty']=' M '+path+'\0'
    with pytest.raises(remote.Unsupported):remote.vpn_source_guard(state['revision'],str(root),runner)


@pytest.mark.parametrize('kind',['revision','tree','hash','locale_json','locale_nonstring','symlink','ancestor_symlink','deleted_locale','renamed_locale'])
def test_drift_and_type_changes_fail_closed(contract,kind):
    root,state,runner=contract;revision=state['revision']
    if kind=='revision':state['revision']='b'*40
    if kind=='tree':state['tree']='b'*40
    if kind=='hash':(root/'net2/Host.js').write_text('changed')
    if kind=='locale_json':(root/'locales/en.json').write_text('broken')
    if kind=='locale_nonstring':(root/'locales/en.json').write_text('{"command":42}')
    if kind=='symlink':
        p=root/'net2/Host.js';target=root/'other';target.write_bytes(p.read_bytes());p.unlink();p.symlink_to(target)
    if kind=='ancestor_symlink':
        (root/'api').rename(root/'api-real');(root/'api').symlink_to(root/'api-real',target_is_directory=True)
    if kind=='deleted_locale':state['dirty']=' D locales/en.json\0'
    if kind=='renamed_locale':state['dirty']='R  locales/en.json\0something.js\0'
    with pytest.raises((remote.Unsupported,OSError,ValueError)):remote.vpn_source_guard(revision,str(root),runner)


def test_new_revision_cannot_enable_other_managed_writes(monkeypatch):
    calls=[];monkeypatch.setattr(remote,'vpn_source_guard',lambda revision:calls.append('guard'))
    monkeypatch.setattr(remote,'management_request',lambda *args:calls.append('ping'))
    for kind in ('managed_feature','managed_scoped',None):
        with pytest.raises(remote.Unsupported):remote.management_guard(remote.VPN_MANAGEMENT_REVISIONS[0],kind)
    assert calls==[]
    remote.management_guard(remote.VPN_MANAGEMENT_REVISIONS[0],'managed_lifecycle')
    assert calls==['guard','ping']


def test_reviewed_settings_defaults_not_guessed_null(tmp_path,monkeypatch):
    p=tmp_path/'settings';original=os.open
    monkeypatch.setattr(remote.os.path,'isfile',lambda name:'ovpn_profile' in name)
    monkeypatch.setattr(remote.os,'open',lambda name,flags:original(p,flags))
    p.write_text(json.dumps({'strictVPN':True,'routeDNS':False}))
    selected,fingerprint=remote.managed_vpn_safety('example')
    assert selected==dict(strictVPN=True,routeDNS=False,overrideDefaultRoute=True,c2sSNATDisabled=False)
    assert fingerprint==hashlib.sha256(p.read_bytes()).hexdigest()
    for bad in (None,'false',0,[]):
        p.write_text(json.dumps({'c2sSNATDisabled':bad}))
        with pytest.raises(remote.Unsupported):remote.managed_vpn_safety('example')


def test_new_profile_missing_cache_is_unknown_not_already_stopped(lifecycle,monkeypatch):
    original=remote.run
    monkeypatch.setattr(remote,'run',lambda argv:'' if argv[0]=='redis-cli' else original(argv))
    for desired in ('connect','disconnect'):
        state=remote.managed_lifecycle_state({**LIFE,'vpn_type':'openvpn','desired':desired})
        assert state['field']=={'observed_connected':None,'administrative_intent':'unknown'}
        assert state['present'] is False
    assert not lifecycle['calls']


def test_unknown_cache_with_interface_does_not_hide_transition(lifecycle,monkeypatch):
    lifecycle['connected']=True;original=remote.run
    monkeypatch.setattr(remote,'run',lambda argv:'' if argv[0]=='redis-cli' else original(argv))
    with pytest.raises(remote.Unsupported):remote.managed_lifecycle_state(LIFE)


async def test_new_revision_local_scope_gate(tmp_path):
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',
        management_revision=remote.VPN_MANAGEMENT_REVISIONS[0],managed_vpn_profiles=['vpn-a'])
    manager=VPNWriteManager(Config(sites={'router-a':site},vpn_writes_enabled=True,
        approval_consumed_directory=str(tmp_path),write_confirmation_mode="host_confirmed",vpn_confirmation_mode="host_confirmed",vpn_target_policy="approval_bound",audit_file=str(tmp_path/'audit')),AsyncMock())
    assert manager.validate('router-a',dict(LIFE))==site
    assert manager.validate('router-a',{**LIFE,'profile':'other'})==site


def test_vpn_rollback_cannot_supply_other_policy_fields(monkeypatch):
    monkeypatch.setattr(remote,'management_guard',lambda *args:None)
    monkeypatch.setattr(remote,'run',lambda *args:'1')
    monkeypatch.setattr(remote,'managed_state',lambda *args:pytest.fail('invalid context must stop before state/API'))
    spec=dict(kind='managed_vpn',device='02:00:00:00:00:01',expected_profile='source',destination_profile='target')
    for context in ({'before':{'state':False,'profileId':'source'}},{'before':{'state':True,'profileId':'other'}},{'before':{'state':True,'profileId':'source','arbitrary':'x'}}):
        with pytest.raises(ValueError):remote.managed_write(dict(spec=spec,mode='rollback',context=context,revision=remote.VPN_MANAGEMENT_REVISIONS[0]))
