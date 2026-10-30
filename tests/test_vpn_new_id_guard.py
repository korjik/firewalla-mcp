import json,time
import pytest
from firewalla_mcp.vpn_import import InactiveImport,ImportBlocked,fresh_profile_id
from firewalla_mcp.vpn_new_id_guard import NewIdObservation
from test_vpn_import import sandbox,approve,profile
T='012345abcd'


def runner(argv):
    if argv[:3]==['redis-cli','--raw','EVAL']:
        return json.dumps({'scan_complete':True,'issues':{},'targets':[{'profile_id':T,'reference_families':{}}]})
    if argv[:2]==['ip','-j']:return '[]'
    if argv[0]=='systemctl':return 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled'
    if argv[:3]==['redis-cli','--raw','EXISTS']:return '0'
    if argv[:3]==['redis-cli','--raw','GET']:return ''
    raise AssertionError(argv)


def test_real_command_adapter_projects_unknown_admin_intent(tmp_path):
    guard=NewIdObservation([T],runner)
    (tmp_path/'ovpn_profile').mkdir()
    assert guard.collision_check(tmp_path)['file_collision_check_complete']
    assert guard([T])[T]['administrative_intent']=='unknown'
    (tmp_path/'ovpn_profile'/(T+'.settings')).write_text('{}')
    with pytest.raises(ImportBlocked):guard.collision_check(tmp_path)


@pytest.mark.parametrize('kind',['interface','active','enabled','cache','references'])
def test_observation_changes_block(kind):
    def changed(argv):
        if kind=='interface' and argv[0]=='ip':return json.dumps([{'ifname':'vpn_'+T}])
        if kind in ('active','enabled') and argv[0]=='systemctl':return runner(argv).replace('inactive','active') if kind=='active' else runner(argv).replace('disabled','enabled')
        if kind=='cache' and argv[:3]==['redis-cli','--raw','GET']:return 'true'
        if kind=='references' and argv[:3]==['redis-cli','--raw','EVAL']:return runner(argv).replace('"reference_families": {}','"reference_families": ["route_wan"]')
        return runner(argv)
    with pytest.raises(ImportBlocked):NewIdObservation([T],changed)([T])


def test_explicit_weaker_mode_bound_to_plan_and_truthful_result(sandbox):
    root,_,target,_=sandbox
    guard=NewIdObservation([T],runner)
    tool=InactiveImport(root,guard,maintenance_window={'nonce':'1'*32,'expires':int(time.time())+300},observational_new_ids=True)
    try:
        plan=tool.plan('source',[dict(target,id=T)])
        assert plan['maintenance']['observational_new_ids'] is True
        assert plan['maintenance']['administrative_state_guarantee'].startswith('unknown')
        approve(root,plan)
        assert tool.apply(plan['transaction'])['state']=='imported_unassigned_passive_checks'
    finally:tool.close()


def test_strict_mode_rejects_weaker_evidence(sandbox):
    _,tool,target,_=sandbox;tool.probe=NewIdObservation([T],runner)
    with pytest.raises(ImportBlocked):tool.plan('source',[dict(target,id=T)])


def test_weaker_mode_requires_window_before_any_directory_write(tmp_path):
    with pytest.raises(ImportBlocked,match='maintenance window'):
        InactiveImport(tmp_path,NewIdObservation([T],runner),observational_new_ids=True)
    assert not (tmp_path/'.mcp-import').exists()


def test_weaker_contract_change_invalidates_approval(sandbox):
    root,_,target,_=sandbox
    tool=InactiveImport(root,NewIdObservation([T],runner),maintenance_window={'nonce':'1'*32,'expires':int(time.time())+300},observational_new_ids=True)
    try:
        plan=tool.plan('source',[dict(target,id=T)]);approve(root,plan)
        tool.observational_new_ids=False
        with pytest.raises(ImportBlocked):tool.apply(plan['transaction'])
        assert not (root/(T+'.ovpn')).exists()
    finally:tool.close()



def test_false_cache_after_discovery_does_not_claim_administrative_stop():
    def observed(argv):
        return 'false' if argv[:3]==['redis-cli','--raw','GET'] else runner(argv)
    data=NewIdObservation([T],observed)([T])
    assert data[T]['administrative_intent']=='unknown'


def test_preexisting_false_cache_blocks_fresh_id_collision_check(tmp_path):
    def prior(argv):
        return '1' if argv[:3]==['redis-cli','--raw','EXISTS'] else runner(argv)
    with pytest.raises(ImportBlocked):NewIdObservation([T],prior).collision_check(tmp_path)
