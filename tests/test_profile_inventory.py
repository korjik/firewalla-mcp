import json
import pytest
from firewalla_mcp import remote


def test_openvpn_allowlisted_endpoints_no_inline_secrets():
    data=remote.openvpn_endpoints('proto udp\nremote vpn.example.org 1194\nremote 192.0.2.4 443 tcp-client\n<tls-auth>\nSECRET\nremote fake.invalid 99\n</tls-auth>\nauth-user-pass /secret/file\nscript-security 2\n')
    assert len(data['configured_endpoints'])==2
    assert data['configured_endpoints'][0]['transport']=='udp'
    assert data['configured_endpoints'][1]['transport']=='tcp'
    assert 'SECRET' not in json.dumps(data) and '/secret' not in json.dumps(data)
    assert all(e['active'] is None for e in data['configured_endpoints'])


def test_missing_defaults_and_connection_blocks_are_unknown():
    data=remote.openvpn_endpoints('remote vpn.example.org\n<connection>\nremote second.example.org 443\n</connection>')
    assert not data['endpoints_complete']
    assert data['configured_endpoints'][0]['port'] is None
    assert data['configured_endpoints'][0]['transport'] is None


@pytest.mark.parametrize('host',['bad\nname','bad%scope','https://example.org','a;echo','$(id)'])
def test_endpoint_validation(host):
    with pytest.raises(ValueError):remote.endpoint_host(host)


def test_wireguard_projection_drops_keys_dns_and_preserves_peers():
    result=remote.wireguard_endpoints({'privateKey':'SECRET','dns':['192.0.2.53'],'peers':[{'publicKey':'SECRET','presharedKey':'SECRET','endpoint':'[2001:db8::1]:51820'},{'endpoint':'vpn.example.org:443'}]})
    assert len(result['configured_endpoints'])==2
    assert 'SECRET' not in json.dumps(result) and '192.0.2.53' not in json.dumps(result)
    assert result['configured_endpoints'][0]['transport']=='udp'


def test_inventory_disconnected_duplicate_missing_name_orphan(tmp_path,monkeypatch):
    folder=tmp_path/'ovpn_profile';folder.mkdir()
    for identifier,name in [('abc','Same'),('def','Same'),('ghi',None)]:
        (folder/(identifier+'.ovpn')).write_text('remote vpn.example.org 1194\nproto udp\n')
        (folder/(identifier+'.settings')).write_text(json.dumps({'displayName':name,'password':'SECRET'}))
    monkeypatch.setattr(remote,'network',lambda _: {'rows':[{'ifname':'vpn_abc','operstate':'UP'},{'ifname':'vpn_orphan'}],'truncated':False})
    monkeypatch.setattr(remote,'run',lambda _: 'false')
    result=remote.saved_vpn_profiles(str(tmp_path))
    assert len(result['profiles'])==3
    assert [p['name'] for p in result['profiles']]==['Same','Same',None]
    assert not result['profiles'][1]['interface_present']
    assert result['profiles'][0]['cached_connected'] is False
    assert result['profiles'][0]['administrative_state']=='unknown'
    assert result['unmatched_interfaces']==['vpn_orphan']
    assert 'SECRET' not in json.dumps(result)


def test_safe_file_rejects_symlink_and_oversize(tmp_path):
    p=tmp_path/'real';p.write_text('abc');link=tmp_path/'link';link.symlink_to(p)
    with pytest.raises(OSError):remote.safe_profile_file(link)
    with pytest.raises(remote.Unsupported):remote.safe_profile_file(p,2)


def test_membership_empty_lua_arrays(monkeypatch):
    monkeypatch.setattr(remote,'run',lambda _: '{"tags":{},"hosts":{},"complete":true}')
    assert remote.membership_snapshot()=={'tags':[],'hosts':[],'complete':True}


@pytest.mark.parametrize('cached,present,expected',[(True,True,'unknown'),(True,False,'unknown'),(False,False,'disconnected'),(False,True,'unknown'),(None,False,'unknown')])
def test_passive_health_never_infers_enabled_or_healthy(cached,present,expected):
    from firewalla_mcp.presentation import describe_vpn_inventory
    row=describe_vpn_inventory({'profiles':[{'cached_connected':cached,'interface_present':present}]},'2026-01-01T00:00:00+00:00')['profiles'][0]
    assert row['enabled']['value'] is None
    assert row['connected']['value'] is cached and row['connected']['freshness']=='unknown'
    assert row['health']['status']==expected and row['health']['healthy'] is not True
    assert row['health']['active_probe_performed'] is False
