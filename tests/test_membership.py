import pytest
from firewalla_mcp.membership import membership_directory, person_devices


def snapshot():
    return {'complete':True,'tags':[{'uid':'1','type':'user','name':'Alex'}, {'uid':'2','type':'user','name':'Jordan'},
             {'uid':'3','type':'group','name':'Empty group'}],
            'hosts':[{'mac':f'02:00:00:00:00:{i:02x}','name':f'Device {i}','userTags':'["1"]'} for i in range(1,5)]
                    +[{'mac':'02:00:00:00:00:05','name':"Jordan phone",'userTags':'[]','tags':'[]'}]}


def test_people_four_and_zero_without_guessing_name_ownership():
    directory=membership_directory(snapshot())
    assert person_devices(directory,'Alex')['assigned_device_count']==4
    result=person_devices(directory,'Jordan')
    assert result['assigned_device_count']==0 and result['assigned_devices']==[]
    assert len(result['unassigned_name_matches'])==1 and not result['name_match_is_membership']
    assert len(directory['ungrouped_devices'])==1
    assert directory['groups'][0]['assigned_device_count']==0


def test_incomplete_snapshot_cannot_claim_zero_members():
    data=snapshot();data['complete']=False
    assert person_devices(membership_directory(data),'Jordan')['assigned_device_count'] is None


def test_duplicate_scan_rows_do_not_double_count():
    data=snapshot();data['hosts'].append(dict(data['hosts'][0]))
    assert person_devices(membership_directory(data),'Alex')['assigned_device_count']==4


def test_unknown_tag_preserves_reference_and_uncertainty():
    data=snapshot();data['hosts'][0]['userTags']='["99"]'
    result=membership_directory(data)
    assert not result['complete'] and result['devices'][0]['people'][0]['id']=='99'
    assert result['people'][1]['assigned_device_count'] is None


def test_group_and_person_ids_remain_typed():
    data=snapshot();data['tags'].append({'uid':'1','type':'group','name':'Group one'})
    data['hosts'][0]['tags']='["1"]'
    result=membership_directory(data)
    assert result['people'][0]['assigned_device_count']==4
    assert result['groups'][1]['assigned_device_count']==1


def test_ambiguous_person_name_requires_id():
    data=snapshot();data['tags'].append({'uid':'9','type':'user','name':'Alex'})
    with pytest.raises(ValueError):person_devices(membership_directory(data),'Alex')


def test_unknown_membership_shape_not_empty():
    data=snapshot();data['hosts'][0]['userTags']='{"unexpected":true}'
    with pytest.raises(ValueError):membership_directory(data)


def test_explicit_device_tag_relationship_assigns_person_without_name_guess():
    data=snapshot();data['tags'].append({'uid':'8','type':'device','name':'Device tag','userTags':'["2"]'})
    data['hosts'][-1]['deviceTags']='["8"]'
    result=person_devices(membership_directory(data),'Jordan')
    assert result['assigned_device_count']==1
    assert result['unassigned_name_matches']==[]


def test_tag_cycle_rejected_instead_of_inventing_membership():
    data=snapshot();data['tags'][0]['userTags']='["1"]'
    with pytest.raises(ValueError):membership_directory(data)


def test_multi_parent_paths_do_not_double_count():
    data=snapshot();data['tags'] += [
        {'uid':'8','type':'device','name':'First','userTags':'["1"]'},
        {'uid':'9','type':'device','name':'Second','userTags':'["1"]'}]
    data['hosts'][0]['deviceTags']='["8","9"]'
    assert person_devices(membership_directory(data),'Alex')['assigned_device_count']==4
