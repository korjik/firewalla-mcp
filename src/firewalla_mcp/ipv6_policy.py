"""Pure device-wide IPv6 inbound policy and enforcement contract.

No registered tool, mutation, NAT, or ownership inference. Callers must supply
source guards, exact identity, confirmation, journal and state/recovery checks.
Proof covers rule shape/source sets, not traversal or external reachability.
"""
import ipaddress
import re
import shlex

from .forward_enforcement import canonical_rule, ipset_entries
from .forward_policy import native_allow as ipv4_allow


def native_allow(device, interface_uuid, source_network, protocol, port, owner):
    """One WAN, MAC, IPv6 source CIDR and TCP/UDP destination port.

    Destination is the native device set, including future IPv6 addresses.
    origDst/origDport and family selectors are deliberately absent.
    """
    if not isinstance(source_network, str) or '%' in source_network or '/' not in source_network:
        raise ValueError('Explicit unscoped IPv6 CIDR required')
    network = ipaddress.IPv6Network(source_network, strict=True)
    if str(network) != source_network:
        raise ValueError('Canonical IPv6 CIDR required')
    value = ipv4_allow(device, interface_uuid, '0.0.0.0/0', protocol, port, port, owner)
    value['target'] = str(network)
    del value['origDport']
    return value


def validate(value):
    """Reject extra selectors rather than silently discarding them."""
    if not isinstance(value, dict) or not isinstance(value.get('scope'), list) or len(value['scope']) != 1:
        raise ValueError('Single-device policy required')
    description = value.get('description')
    if not isinstance(description, str) or not re.fullmatch(r'mcp:[a-f0-9]{32}', description):
        raise ValueError('Exact owner description required')
    port = value.get('localPort')
    if not isinstance(port, str) or not re.fullmatch(r'[1-9][0-9]{0,4}', port):
        raise ValueError('Canonical port required')
    expected = native_allow(value['scope'][0], value.get('owanUUID'), value.get('target'),
                            value.get('protocol'), int(port), description[4:])
    if value != expected:
        raise ValueError('Unsupported or noncanonical IPv6 policy')
    return expected


def scope_disclosure(value):
    value = validate(value)
    return {'ipv6_sources': value['target'], 'device': value['scope'][0],
            'wan_uuid': value['owanUUID'], 'protocol': value['protocol'],
            'destination_port': int(value['localPort']), 'ipv4_allowed': False,
            'ipv4_exclusion_requires': 'verified empty IPv4 source counterpart',
            'destination_scope': 'all device IPv6 addresses, including future addresses',
            'single_destination_address': False, 'nat_or_translation': False,
            'dnat_required': False, 'external_reachability': 'unverified'}


def verify_policy(value, pid, rules4, rules6, sets, enabled):
    """Both families must have exactly the expected positive set rules.

    An empty IPv4 source set excludes IPv4; the IPv6 set must equal the approved
    CIDR. Disabled state requires absence of all rules bearing this PID.
    Raises ValueError on malformed evidence; otherwise returns proof boolean.
    """
    value = validate(value)
    if type(enabled) is not bool or not isinstance(pid, str) or not re.fullmatch(r'[1-9][0-9]{0,4}', pid) or int(pid) > 65535:
        raise ValueError('Exact PID and boolean state required')
    selected = []
    for family, lines in ((4, rules4), (6, rules6)):
        if not isinstance(lines, list) or len(lines) > 4096:
            raise ValueError('Rule bound')
        rows = []
        for line in lines:
            if not isinstance(line, str) or len(line) > 8192:
                raise ValueError('Rule byte bound')
            tokens = shlex.split(line)
            if any(tokens[i:i+2] == ['--comment', 'rule_' + pid] for i in range(len(tokens)-1)):
                rows.append(canonical_rule(line))
        selected.append((family, rows))
    if not enabled:
        return all(not rows for _, rows in selected)
    source = 'c_bd_' + pid + '_set'
    local = 'c_bp_' + pid + '_local_port'
    if not isinstance(sets, dict) or not {source, source+'6', local} <= sets.keys():
        raise ValueError('Complete source and port sets required')
    if ipset_entries(sets[source], source, 'inet', 'hash:net'):
        return False
    network = ipaddress.IPv6Network(value['target'])
    expected_sources = {str(network)} if network.prefixlen else {'::/1', '8000::/1'}
    entries = ipset_entries(sets[source+'6'], source+'6', 'inet6', 'hash:net')
    if any('%' in entry for entry in entries):
        raise ValueError('Scoped ipset address')
    actual = [str(ipaddress.IPv6Network(entry, strict=True)) for entry in entries]
    if len(actual) != len(expected_sources) or set(actual) != expected_sources:
        return False
    if ipset_entries(sets[local], local, None, 'bitmap:port') != [value['localPort']]:
        return False
    device = 'c_' + value['scope'][0] + '_set'
    wan = 'c_oif_' + value['owanUUID'][:13] + '_set'
    for family, rows in selected:
        expected = []
        for direction in ('ORIGINAL', 'REPLY'):
            remote_side, local_side = ('src', 'dst') if direction == 'ORIGINAL' else ('dst', 'src')
            expected.append({'-A': 'FW_FIREWALL_DEV_ALLOW_LO', '-p': value['protocol'],
                'sets': sorted([(source+('6' if family == 6 else ''), remote_side),
                                (wan, remote_side+','+remote_side), (device, local_side), (local, local_side)]),
                '--ctdir': direction, '--comment': 'rule_'+pid, '-j': 'MARK',
                '--set-xmark': (int(pid), 65535)})
        if len(rows) != 2 or any(row not in rows for row in expected):
            return False
    return True
