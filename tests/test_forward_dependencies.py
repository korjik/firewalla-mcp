import pytest
from firewalla_mcp.forward_dependencies import dependencies
M={'toMac':'02:00:00:00:00:01','toPort':'443','dport':'8443','protocol':'tcp','wanUUID':'wan-a'}
def policy(**kw):return {'pid':'1','identity_complete':True,'type':'mac','target':M['toMac'],'direction':'inbound','protocol':'tcp','localPort':'443','action':'allow',**kw}
def test_exact_and_range_dependencies_even_disabled():
    r=dependencies(M,[policy(localPort='440-445',disabled='1')],inventory_complete=True)
    assert r['complete'] and r['referring_policy_ids']==['1'] and r['relationships'][0]['disabled']
    assert not r['relationships'][0]['removal_authorized']
def test_external_and_internal_ports_are_distinct():
    assert dependencies(M,[policy(origDport='8443')],inventory_complete=True)['referring_policy_ids']==['1']
    assert dependencies(M,[policy(localPort='8443')],inventory_complete=True)['absence_proven']
def test_unresolved_inheritance_prevents_absence():
    r=dependencies(M,[policy(type='net',target='203.0.113.0/24',tag='["group-a"]')],inventory_complete=True)
    assert not r['complete'] and not r['absence_proven']
def test_resolved_global_and_group_are_preserved_shared():
    for p in [policy(type='net',scope=[],target='203.0.113.0/24'),policy(type='net',target='203.0.113.0/24',tag=['group-a'])]:
        r=dependencies(M,[p],inventory_complete=True,group_tags=['group-a'],network_tags=[])
        assert r['shared'] and r['referring_policy_ids']==['1']
@pytest.mark.parametrize('change',[{'localPort':'service'},{'protocol':'tcp,udp'},{'identity_complete':False},{'targetRgId':'rulegroup'}])
def test_unknown_never_absent(change):
    r=dependencies(M,[policy(**change)],inventory_complete=True)
    assert not r['complete'] and not r['absence_proven']
def test_truncated_inventory_not_absent():
    assert not dependencies(M,[],inventory_complete=False)['absence_proven']

@pytest.mark.parametrize('kind', ['mac','internet'])
@pytest.mark.parametrize('target', ['TAG',''])
def test_internet_scope_aliases_are_dependencies(kind,target):
    r=dependencies(M,[policy(type=kind,target=target,scope=[M['toMac']])],inventory_complete=True)
    assert r['referring_policy_ids']==['1'] and not r['absence_proven']

def test_internet_literal_mac_overrides_scope():
    r=dependencies(M,[policy(type='internet',scope=['02:00:00:00:00:02'])],inventory_complete=True)
    assert r['referring_policy_ids']==['1']

def test_disjoint_scope_combined_with_matching_group_is_unresolved():
    r=dependencies(M,[policy(type='net',target='203.0.113.0/24',scope=['02:00:00:00:00:02'],tag=['group-a'])],inventory_complete=True,group_tags=['group-a'],network_tags=[])
    assert not r['absence_proven'] and r['unresolved_policy_ids']==['1']

def test_unknown_internet_target_is_unresolved():
    r=dependencies(M,[policy(target='unexpected')],inventory_complete=True)
    assert not r['absence_proven'] and not r['complete']
