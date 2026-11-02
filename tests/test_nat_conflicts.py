"""Sanitized NAT regression cases; no router calls."""
import pytest
from unittest.mock import patch
from firewalla_mcp import remote

def spec(port):
    return dict(kind='managed_interface_forward',device='02:00:00:00:00:01',destination_ip='192.0.2.20',interface_uuid='11111111-1111-4111-8111-111111111111',protocol='tcp',external_port=port,destination_port=port)

@pytest.mark.parametrize('port',[80,443])
@pytest.mark.parametrize('row',[
    '-A FW_POSTROUTING -m conntrack --ctstate DNAT -j FW_POSTROUTING_PORT_FORWARD',
    '-A FW_PREROUTING_DNS_DEFAULT -p tcp -m tcp --dport 53 -m set ! --match-set dns_exempt src -j DNAT --to-destination 192.0.2.1:53',
])
def test_unrelated_rule_should_not_conflict(port,row):
    with patch.object(remote,'run',return_value=row):
        assert remote.interface_nat_guard(spec(port),False)[0] is False

@pytest.mark.parametrize('row',[
    '-A UPNP -p tcp --dport 80 -j DNAT --to-destination 192.0.2.99:80',
    '-A CUSTOM -p tcp --dport 70:90 -j DNAT --to-destination 192.0.2.99:80',
    '-A CUSTOM ! -p udp --dport 80 -j DNAT --to-destination 192.0.2.99:80',
    '-A CUSTOM -p tcp ! --dport 443 -j DNAT --to-destination 192.0.2.99:80',
])
def test_legitimate_or_potential_collision_stays_blocked(row):
    with patch.object(remote,'run',return_value=row):
        assert remote.interface_nat_guard(spec(80),False)[0] is True

@pytest.mark.parametrize('clause,overlap',[
 ('-p udp --dport 80',False),('-p 6 --dport 80',True),
 ('-p 17 --dport 80',False),('! -p tcp --dport 80',False),
 ('-p tcp --dports 53,80,443',True),('-p tcp --dport :79',False),
 ('-p tcp --dport 81:',False),('-p tcp ! --dports 80,443',False),
 ('-p tcp --dport 80 ! --match-set excluded src',True),
 ('--protocol=tcp --destination-port=80',True),
])
def test_clause_overlap(clause,overlap):
    row='-A CUSTOM '+clause+' -j DNAT --to-destination 192.0.2.20:80'
    with patch.object(remote,'run',return_value=row):
        assert remote.interface_nat_guard(spec(80),False)[0] is overlap

@pytest.mark.parametrize('literal',['DNAT','--jump=DNAT','-j DNAT'])
def test_comment_literals_are_not_actions(literal):
    row='-A CUSTOM -m comment --comment "'+literal+'" -j ACCEPT'
    with patch.object(remote,'run',return_value=row):
        assert remote.interface_nat_guard(spec(80),False)[0] is False

def test_evidence_is_bounded_and_contains_no_destination():
    row='-A UPNP -p tcp --dport 80 -j DNAT --to-destination 192.0.2.99:80'
    with patch.object(remote,'run',return_value='\n'.join([row]*12)):
        conflict,evidence=remote.interface_nat_guard(spec(80),False)
    assert conflict and evidence['count']==12 and evidence['truncated']
    assert len(evidence['rules'])==8 and '192.0.2.99' not in str(evidence)

@pytest.mark.parametrize('clause',['-p mystery','-p tcp --dport service','-p tcp --dport 90:80','-p tcp -p udp'])
def test_ambiguous_selectors_fail_closed(clause):
    with patch.object(remote,'run',return_value='-A CUSTOM '+clause+' -j DNAT'):
        with pytest.raises(remote.Unsupported):
            remote.interface_nat_guard(spec(80),False)
