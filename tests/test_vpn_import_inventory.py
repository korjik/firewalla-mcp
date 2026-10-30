import json
import pytest
from firewalla_mcp.vpn_import_inventory import collect_references, REFERENCE_LUA
from firewalla_mcp.vpn_import import ImportBlocked
T='012345abcd'


def result(complete=True,issues=None,families=None):
    return json.dumps({'scan_complete':complete,'issues':issues or {},'targets':[{'profile_id':T,'reference_families':families or {}}],'counts':{'policy':20,'virtual_wan':2,'dns_vpn':1}})


def test_complete_reference_enumeration_never_invents_admin_state():
    r=collect_references([T],lambda _:result())
    assert r['reference_enumeration_complete'] and r['targets'][T]['unreferenced']
    assert r['targets'][T]['administrative_intent']=='unknown' and not r['safe_to_import']


@pytest.mark.parametrize('kwargs',[{'complete':False},{'issues':['field_limit']},{'issues':['json_schema']},{'issues':['policy_type']}])
def test_incomplete_unknown_not_unreferenced(kwargs):
    r=collect_references([T],lambda _:result(**kwargs))
    assert r['targets'][T]['unreferenced'] is None and not r['reference_enumeration_complete']


@pytest.mark.parametrize('family',['policy_vpn','route_wan','virtual_wan','dns_vpn'])
def test_each_reference_family_blocks(family):
    r=collect_references([T],lambda _:result(families=[family]))
    assert r['targets'][T]['unreferenced'] is False


def test_fixed_read_command_and_no_hash_dumps():
    def runner(argv):
        assert argv[:3]==['redis-cli','--raw','EVAL']
        assert argv[3]==REFERENCE_LUA and argv[4]=='0'
        assert json.loads(argv[5])==[T]
        assert 'HGETALL' not in argv[3] and 'HSET' not in argv[3]
        return result()
    collect_references([T],runner)


@pytest.mark.parametrize('targets',[[],[T,T],['bad;id'],['a'*11]])
def test_invalid_targets_do_not_run(targets):
    def never(_):raise AssertionError('must not run')
    with pytest.raises(ImportBlocked):collect_references(targets,never)


def test_bad_projection_fails_closed():
    with pytest.raises(ImportBlocked):collect_references([T],lambda _:'{"scan_complete":true,"issues":[],"targets":[]}')
