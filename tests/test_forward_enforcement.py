import pytest
from firewalla_mcp.forward_policy import native_allow
from firewalla_mcp.forward_enforcement import verify_policy
V=native_allow('02:00:00:00:00:01','11111111-1111-4111-8111-111111111111','203.0.113.0/24','tcp',443,443,'a'*32)
def fixture():
    rows=[]
    for af in (4,6):
        lines=[]
        for direction in ('ORIGINAL','REPLY'):
            remote,local=('src','dst') if direction=='ORIGINAL' else ('dst','src')
            lines.append(f'-A FW_FIREWALL_DEV_ALLOW_LO -p tcp -m set --match-set c_bd_123_set{"6" if af==6 else ""} {remote} -m set --match-set c_oif_11111111-1111_set {remote},{remote} -m set --match-set c_02:00:00:00:00:01_set {local} -m set --match-set c_bp_123_local_port {local} -m conntrack --ctorigdstport 443 -m conntrack --ctdir {direction} -m comment --comment rule_123 -j MARK --set-xmark 0x7b/0xffff')
        rows.append(lines)
    sets={'c_bd_123_set':'create c_bd_123_set hash:net family inet hashsize 1024\nadd c_bd_123_set 203.0.113.0/24',
          'c_bd_123_set6':'create c_bd_123_set6 hash:net family inet6 hashsize 1024',
          'c_bp_123_local_port':'create c_bp_123_local_port bitmap:port range 0-65535\nadd c_bp_123_local_port 443'}
    return *rows,sets

def test_full_native_shape_and_positive_empty_ipv6_source():
    a,b,s=fixture();assert verify_policy(V,'123',a,b,s,True)

@pytest.mark.parametrize('replacement',[(' -p tcp ',' -p udp '),(' --ctorigdstport 443 ',' --ctorigdstport 80 '),(' -j MARK ',' -j ACCEPT '),(' c_bd_123_set6 ',' other_set '),(' --match-set ',' ! --match-set ')])
def test_broader_or_unknown_rule_rejected(replacement):
    a,b,s=fixture();b[0]=b[0].replace(*replacement)
    try:assert not verify_policy(V,'123',a,b,s,True)
    except ValueError:pass

def test_nonempty_ipv6_or_extra_rule_rejected():
    a,b,s=fixture();s['c_bd_123_set6']+='\nadd c_bd_123_set6 ::/1'
    assert not verify_policy(V,'123',a,b,s,True)
    a,b,s=fixture();b.append(b[0]);assert not verify_policy(V,'123',a,b,s,True)

def test_disabled_requires_no_remaining_commented_rules():
    a,b,s=fixture();assert not verify_policy(V,'123',a,b,s,False)
    assert verify_policy(V,'123',[],[],{},False)

def test_single_source_ipset_host_form_is_canonicalized():
    value={**V,'target':'203.0.113.9/32'}
    a,b,s=fixture();s['c_bd_123_set']=s['c_bd_123_set'].replace('203.0.113.0/24','203.0.113.9')
    assert verify_policy(value,'123',a,b,s,True)
