import copy

import pytest

from firewalla_mcp.ipv6_policy import native_allow, scope_disclosure, validate, verify_policy

MAC = '02:00:00:00:00:01'
WAN = '11111111-1111-4111-8111-111111111111'


def value(protocol='tcp', source='2001:db8:100::/48'):
    return native_allow(MAC, WAN, source, protocol, 443, 'a'*32)


def evidence(protocol='tcp', entries=('2001:db8:100::/48',)):
    rules = []
    for family in (4, 6):
        lines = []
        for direction in ('ORIGINAL', 'REPLY'):
            remote, local = ('src', 'dst') if direction == 'ORIGINAL' else ('dst', 'src')
            lines.append(f'-A FW_FIREWALL_DEV_ALLOW_LO -p {protocol} -m set '
                         f'--match-set c_bd_123_set{"6" if family == 6 else ""} {remote} '
                         f'-m set --match-set c_oif_{WAN[:13]}_set {remote},{remote} '
                         f'-m set --match-set c_{MAC}_set {local} '
                         f'-m set --match-set c_bp_123_local_port {local} '
                         f'-m conntrack --ctdir {direction} -m comment --comment rule_123 '
                         '-j MARK --set-xmark 0x7b/0xffff')
        rules.append(lines)
    sets = {'c_bd_123_set': 'create c_bd_123_set hash:net family inet hashsize 1024',
            'c_bd_123_set6': 'create c_bd_123_set6 hash:net family inet6 hashsize 1024',
            'c_bp_123_local_port': 'create c_bp_123_local_port bitmap:port range 0-65535\nadd c_bp_123_local_port 443'}
    sets['c_bd_123_set6'] += ''.join('\nadd c_bd_123_set6 '+entry for entry in entries)
    return *rules, sets


@pytest.mark.parametrize('protocol', ['tcp', 'udp'])
def test_native_and_dual_family_proof(protocol):
    v = value(protocol)
    assert validate(v) == v
    assert not {'origDst', 'origDport', 'family', 'af'} & v.keys()
    assert verify_policy(v, '123', *evidence(protocol), True)
    disclosure = scope_disclosure(v)
    assert disclosure['single_destination_address'] is False
    assert 'future' in disclosure['destination_scope']
    assert disclosure['external_reachability'] == 'unverified'


@pytest.mark.parametrize('source', ['0.0.0.0/0', '2001:db8::1/64', '2001:DB8::/32',
                                    '2001:db8::1', 'fe80::%eth0/64', '::/0\n', '', None])
def test_invalid_source(source):
    with pytest.raises(ValueError):
        value(source=source)


@pytest.mark.parametrize('field, replacement', [('scope', [MAC, MAC]), ('scope', ['02:00:00:00:00:0a']),
    ('localPort', '0443'), ('localPort', '65536'), ('type', 'ip'), ('protocol', 'icmp'),
    ('origDst', '2001:db8::1'), ('origDport', '443'), ('family', 6), ('disabled', True),
    ('owanUUID', 'VC:test'), ('description', 'name')])
def test_extra_or_noncanonical_semantics(field, replacement):
    v = value();v[field] = replacement
    with pytest.raises(ValueError):
        validate(v)


@pytest.mark.parametrize('port', [True, 0, 65536, '443', 1.5])
def test_bad_port(port):
    with pytest.raises(ValueError):
        native_allow(MAC, WAN, '::/0', 'tcp', port, 'a'*32)


@pytest.mark.parametrize('source, entries', [('::/0', ('::/1', '8000::/1')),
                                           ('2001:db8::1/128', ('2001:db8::1',))])
def test_universal_and_host_source(source, entries):
    assert verify_policy(value(source=source), '123', *evidence(entries=entries), True)


@pytest.mark.parametrize('entries', [(), ('::/1',), ('2001:db8::/32',),
                                    ('2001:db8:100::/48', '2001:db8:200::/48'),
                                    ('2001:db8:100::/48', '2001:db8:100::/48')])
def test_source_set_must_be_exact(entries):
    assert not verify_policy(value(), '123', *evidence(entries=entries), True)


def test_ipv4_exclusion_and_port_set():
    a,b,s = evidence();s['c_bd_123_set'] += '\nadd c_bd_123_set 192.0.2.0/24'
    assert not verify_policy(value(), '123', a,b,s, True)
    a,b,s = evidence();s['c_bp_123_local_port'] += '\nadd c_bp_123_local_port 80'
    assert not verify_policy(value(), '123', a,b,s, True)


@pytest.mark.parametrize('old,new', [(' -p tcp ', ' -p udp '), (' -j MARK ', ' -j ACCEPT '),
    (' --ctdir ORIGINAL ', ' --ctdir REPLY '), ('0x7b/0xffff', '0x7c/0xffff'),
    (' c_bd_123_set6 ', ' other_set '), (' --match-set ', ' ! --match-set '),
    (' -j MARK ', ' --ctorigdstport 443 -j MARK '), (' -j MARK ', ' --ctorigdst 2001:db8::1 -j MARK '),
    ('FW_FIREWALL_DEV_ALLOW_LO', 'FW_FIREWALL_DEV_ALLOW_HI')])
def test_unexpected_rule_shape(old,new):
    a,b,s = evidence();b[0] = b[0].replace(old,new)
    try:
        assert not verify_policy(value(), '123', a,b,s, True)
    except ValueError:
        pass


def test_both_family_exact_counts_disabled_and_missing_sets():
    a,b,s = evidence()
    assert not verify_policy(value(), '123', [],b,s, True)
    assert not verify_policy(value(), '123', a,b+[b[0]],s, True)
    assert not verify_policy(value(), '123', a,b,s, False)
    assert verify_policy(value(), '123', [],[],{}, False)
    with pytest.raises(ValueError):
        verify_policy(value(), '123', a,b,{}, True)
    with pytest.raises(ValueError):
        verify_policy(value(), '123', a,b,s, 'false')


def test_no_input_mutation():
    v=value();a,b,s=evidence();before=copy.deepcopy((v,a,b,s))
    assert verify_policy(v,'123',a,b,s,True)
    assert (v,a,b,s)==before
