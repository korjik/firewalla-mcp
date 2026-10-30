import json

import pytest
from firewalla_mcp.vpn_import import ImportBlocked, digest, validate_profile
from test_vpn_import import profile, sandbox, approve  # noqa: F401


def provider(profile, compression=b'comp-lzo\n'):
    return profile + b'key-direction 1\n' + compression + b'<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n' + (b'1234567890abcdef1234567890abcdef\n' * 16) + b'-----END OpenVPN Static key V1-----\n</tls-auth>\n'


@pytest.mark.parametrize('mode,expected', [(b'', 'adaptive'), (b' no', 'no'), (b' yes', 'yes'), (b' adaptive', 'adaptive')])
def test_provider_preserves_bytes_and_reports_risk(profile, mode, expected):
    data = provider(profile, b'comp-lzo' + mode + b'\n')
    before = data[:]
    result = validate_profile(data, digest(data), 'vpn.example.test', provider_features=True)
    assert result['compression'] == expected and result['compression_server_push_possible']
    assert result['inline_tls_auth'] and result['profile_contains_shared_key']
    assert data == before
    assert '1234567890abcdef' not in json.dumps(result)
    with pytest.raises(ImportBlocked):
        validate_profile(data, digest(data), 'vpn.example.test')


@pytest.mark.parametrize('replace,with_value', [(b'key-direction 1', b'key-direction 0'),
    (b'key-direction 1\n', b''), (b'comp-lzo', b'comp-lzo invalid'),
    (b'1234567890abcdef1234567890abcdef', b'invalid-key'),
    (b'</tls-auth>', b''), (b'</tls-auth>', b'</tls-auth>\n<tls-auth>\n</tls-auth>'),
    (b'key-direction 1', b'tls-auth /tmp/key\nkey-direction 1')])
def test_invalid_provider_input_fails_safe(profile, replace, with_value):
    data = provider(profile).replace(replace, with_value)
    with pytest.raises(ImportBlocked) as error:
        validate_profile(data, digest(data), 'vpn.example.test', provider_features=True)
    assert '1234567890abcdef' not in str(error.value)


def test_provider_transaction_approval_binding_and_original_bytes(sandbox):
    root, tool, target, _ = sandbox
    tool.provider_features = True
    data = provider(target['content'])
    target = {**target, 'content': data, 'sha256': digest(data)}
    plan = tool.plan('source', [target])
    assert plan['provider_features'] and plan['targets'][0]['inline_tls_auth']
    assert '1234567890abcdef' not in json.dumps(plan)
    approve(root, plan)
    tool.provider_features = False
    with pytest.raises(ImportBlocked, match='policy changed'):
        tool.apply(plan['transaction'])
    assert not (root / 'target_a.ovpn').exists()
    tool.provider_features = True
    tool.apply(plan['transaction'])
    assert (root / 'target_a.ovpn').read_bytes() == data
    assert (root / 'target_a.ovpn').stat().st_mode & 0o777 == 0o600
    rollback = tool.rollback_plan(plan['transaction'])
    approve(root, rollback, 'rollback')
    tool.rollback(plan['transaction'])
    assert not (root / 'target_a.ovpn').exists()


def test_provider_per_remote_udp_without_global_proto(profile):
    from firewalla_mcp.vpn_import import validate_profile,digest
    data=profile.replace(b'proto udp\n',b'').replace(b'remote vpn.example.test 1194',b'remote vpn.example.test 1194 udp')
    result=validate_profile(data,digest(data),'vpn.example.test',provider_features=True)
    assert result['protocol']=='udp' and result['profile_bytes_preserved']


def test_conflicting_per_remote_transport_rejected(profile):
    from firewalla_mcp.vpn_import import validate_profile,digest,ImportBlocked
    data=profile.replace(b'proto udp',b'proto tcp').replace(b'remote vpn.example.test 1194',b'remote vpn.example.test 1194 udp')
    with pytest.raises(ImportBlocked):validate_profile(data,digest(data),'vpn.example.test',provider_features=True)
