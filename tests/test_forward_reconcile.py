import pytest
from firewalla_mcp.forward_reconcile import desired_set,reconcile

def row(ident,kind='mapping',value=None):
    return {'id':ident,'kind':kind,'value':value or {'port':443},'fingerprint':'a'*64,'supported':True,'dependencies':[]}

def test_unrelated_preserved_and_complete_order():
    unrelated=row('game',value={'port':19132})
    p=reconcile([unrelated],[row('new-allow','allow_policy'),row('new-map')])
    assert p['preserve']==[unrelated]
    assert [s['operation'] for s in p['steps']]==['create_disabled','create','enable']
    assert p['atomic'] is False

def test_exact_desired_preserved_without_recreation():
    old=row('old');assert reconcile([old],[row('desired')])['steps']==[]

def test_unknown_historical_ownership_blocks_deletion():
    with pytest.raises(ValueError,match='ownership'):reconcile([row('old')],[],remove_ids=['old'])

def test_owned_remove_order():
    rows=[row('nat'),row('allow','allow_policy')]
    p=reconcile(rows,[],remove_ids=['nat','allow'],verified_owned_ids=['nat','allow'])
    assert [s['object']['id'] for s in p['steps']]==['allow','nat']

def test_dependency_and_inherited_rejection():
    r=row('old');r['dependencies']=['preserved']
    with pytest.raises(ValueError,match='dependency'):reconcile([r,row('preserved')],[],remove_ids=['old'],verified_owned_ids=['old'])
    r['supported']=False
    with pytest.raises(ValueError,match='inherited'):reconcile([r],[])

def test_explicit_source_no_default_and_canonical_targets():
    args=('02:00:00:00:00:01','192.0.2.20','11111111-1111-4111-8111-111111111111','198.51.100.2')
    a={'protocol':'tcp','external_port':443,'destination_port':443}
    with pytest.raises(ValueError,match='source'):desired_set(*args,[a])
    a['source_network']='203.0.113.0/24'
    assert desired_set(*args,[a])[0]['source_network']=='203.0.113.0/24'
    with pytest.raises(ValueError,match='duplicate'):desired_set(*args,[a,a])

def test_preserved_reverse_dependency_blocks_removal():
    p=row('preserved');p['dependencies']=['allow']
    with pytest.raises(ValueError,match='depends'):
        reconcile([p,row('allow','allow_policy')],[],remove_ids=['allow'],verified_owned_ids=['allow'])

def test_missing_reference_and_duplicate_desired_rejected():
    p=row('p');p['dependencies']=['missing']
    with pytest.raises(ValueError,match='incomplete'):reconcile([p],[])
    with pytest.raises(ValueError,match='duplicate desired'):reconcile([],[row('x'),row('y')])

def test_desired_reference_and_preserved_id_collision():
    r=row('new');r['dependencies']=['missing']
    with pytest.raises(ValueError,match='desired dependency'):reconcile([], [r])
    with pytest.raises(ValueError,match='collides'):reconcile([row('same')],[row('same',value={'port':80})])

def legacy_mapping():
    return {'_type':'port_forward','active':True,'description':'mcp:'+'a'*32,'dport':'443','enabled':True,'protocol':'tcp','state':True,'toIP':'192.0.2.20','toMac':'02:00:00:00:00:01','toPort':'443','wanUUID':'11111111-1111-4111-8111-111111111111'}

def selection_for(row):
    from firewalla_mcp.writes import digest
    return {'device':row['toMac'],'destination':row['toIP'],'interface_uuid':row['wanUUID'],'protocol':row['protocol'],'external_port':443,'destination_port':443,'expected_fingerprint':digest(row)}

def test_exact_legacy_adoption_requires_all_evidence():
    from firewalla_mcp.forward_reconcile import adopt_mapping_removal
    r=legacy_mapping();s=selection_for(r)
    from firewalla_mcp.forward_dependencies import require_mapping_removal
    dep=require_mapping_removal(r,[r])
    p=adopt_mapping_removal([r],s,dep)
    assert p['execution_enabled'] is False and p['authorization_required'].startswith('fresh')
    with pytest.raises(ValueError,match='evidence'):adopt_mapping_removal([r],s,{'complete':False})
    with pytest.raises(ValueError,match='ambiguous'):adopt_mapping_removal([r,r],s,dep)
    changed={**r,'description':'mcp:'+'b'*32}
    with pytest.raises(ValueError,match='changed'):adopt_mapping_removal([changed],s,dep)
    with pytest.raises(ValueError,match='shape'):adopt_mapping_removal([{**r,'applyToAll':True}],s,dep)
