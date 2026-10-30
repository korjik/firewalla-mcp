import json
import pytest
from firewalla_mcp.vpn_import import ImportBlocked
from firewalla_mcp.vpn_import_references import reference_hits

TARGET='012345abcd'

@pytest.mark.parametrize('family,value', [
    ('scoped_vpn', {'state':False,'profileId':TARGET}),
    ('dns_vpn', {'state':None,'profileId':TARGET}),
    ('global_vpn', {'multiClients':[{'type':'openvpn','state':False,'openvpn':{'profileId':TARGET,'settings':{'ignored':'synthetic'}}}]}),
    ('route_wan','VC:'+TARGET),
    ('virtual_wan',[{'profileId':TARGET,'seq':1,'weight':50}]),
])
def test_disabled_and_indirect_explicit_references_count(family,value):
    result=reference_hits(value,family,[TARGET])
    assert result['referenced_targets']==[TARGET]
    assert result['safe_to_import'] is False and result['inventory_complete'] is False
    assert 'synthetic' not in json.dumps(result)


def test_reference_matching_is_exact():
    assert reference_hits({'profileId':TARGET+'x'},'scoped_vpn',[TARGET])['referenced_targets']==[]


@pytest.mark.parametrize('family,value', [
    ('scoped_vpn',{'profileId':TARGET,'unknownReferences':[TARGET]}),
    ('global_vpn',{'multiClients':[], 'other':{}}),
    ('global_vpn',{'multiClients':[{'type':'future','state':False}]}),
    ('virtual_wan',[{'profileId':TARGET,'other':1}]),
    ('route_wan','VWG:group'),('dns_vpn','bad JSON'),
])
def test_unknown_reference_shapes_fail_closed(family,value):
    with pytest.raises(ImportBlocked):reference_hits(value,family,[TARGET])
