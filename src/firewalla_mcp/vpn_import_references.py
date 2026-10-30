"""Pure selected-field reference checks; no Redis/API access or import authorization.

Disabled policy references still count for a new-ID maintenance import. A
collector must separately prove bounded enumeration completed for every family.
"""
import json

from .vpn_import import ImportBlocked, need, profile_id


def reference_hits(value, family, targets):
    need(isinstance(targets, (list, tuple)) and 1 <= len(targets) <= 3, "Invalid reference targets")
    targets = {profile_id(t) for t in targets}
    need(family in ('global_vpn', 'scoped_vpn', 'dns_vpn', 'route_wan', 'virtual_wan'), "Unknown reference family")
    if isinstance(value, str) and family != 'route_wan':
        need(len(value.encode()) <= 8192, "Reference field exceeds bound")
        try:
            value = json.loads(value)
        except ValueError:
            raise ImportBlocked("Malformed reference field") from None
    found = set()
    def add(identifier):
        if identifier is None or identifier == '':
            return
        need(isinstance(identifier, str) and len(identifier) <= 80, "Unknown reference identifier")
        if identifier in targets:
            found.add(identifier)
    if value is None or value == '':
        pass
    elif family in ('scoped_vpn', 'dns_vpn'):
        need(isinstance(value, dict) and set(value) <= {'state', 'profileId'}, "Unknown scoped VPN schema")
        need('state' not in value or value['state'] is None or type(value['state']) is bool, "Unknown policy state")
        add(value.get('profileId'))
    elif family == 'global_vpn':
        need(isinstance(value, dict), "Unknown global VPN schema")
        if 'multiClients' in value:
            need(set(value) == {'multiClients'}, "Unreviewed global reference fields")
            rows = value['multiClients']
        else:
            rows = [value]
        need(isinstance(rows, list) and len(rows) <= 64, "Global reference enumeration bound")
        for row in rows:
            need(isinstance(row, dict) and row.get('type') in ('openvpn', 'wireguard'), "Unknown global VPN type")
            kind = row['type']
            need(set(row) <= {'type', 'state', kind} and type(row.get('state')) is bool, "Unknown global VPN fields")
            nested = row.get(kind)
            need(isinstance(nested, dict) and set(nested) <= {'profileId', 'settings'}, "Unknown global profile reference")
            add(nested.get('profileId'))
    elif family == 'route_wan':
        need(isinstance(value, str) and len(value) <= 128, "Unknown route WAN schema")
        if value.startswith('VC:'):
            add(value[3:])
        elif ':' in value:
            raise ImportBlocked("Indirect route reference requires separate resolution")
    else:
        need(isinstance(value, list) and len(value) <= 64, "Unknown virtual WAN members")
        for member in value:
            need(isinstance(member, dict) and set(member) <= {'profileId', 'seq', 'weight'}, "Unknown virtual WAN member")
            add(member.get('profileId'))
    return {'referenced_targets': sorted(found), 'family': family, 'field_parse_complete': True,
            'inventory_complete': False, 'safe_to_import': False}
