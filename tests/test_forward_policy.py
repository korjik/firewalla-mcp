import json
import pytest
from firewalla_mcp.forward_policy import native_allow,scope_disclosure,reject_duplicate,read_projection

ARGS=('02:00:00:00:00:01','11111111-1111-4111-8111-111111111111','0.0.0.0/0','tcp',443,443,'a'*32)

def test_exact_app_style_scope_no_hidden_broadening():
    value=native_allow(*ARGS)
    assert value['type']=='net' and value['target']=='0.0.0.0/0'
    assert not {'origDst','upnp','trust','ctstate'}&value.keys()
    scope=scope_disclosure(value)
    assert scope['ipv6_allowed'] is False and scope['dnat_required'] is False
    assert scope['original_destination_ip_restricted'] is False

@pytest.mark.parametrize('index,value',[(0,'x;id'),(1,'wan-a'),(2,'::/0'),(2,'192.0.2.1/24'),(3,'icmp'),(4,True),(5,0),(6,'x')])
def test_invalid_arguments(index,value):
    args=list(ARGS);args[index]=value
    with pytest.raises(ValueError):native_allow(*args)

def test_disabled_duplicate_rejected_not_reactivated():
    desired=native_allow(*ARGS)
    old={**desired,'scope':json.dumps(desired['scope']),'disabled':'1','description':'other','identity_complete':True}
    with pytest.raises(ValueError,match='Existing'):reject_duplicate([old],desired)
    old['localPort']='80';reject_duplicate([old],desired)

def test_unknown_identity_blocks_creation():
    with pytest.raises(ValueError,match='Incomplete'):reject_duplicate([{'identity_complete':False}],native_allow(*ARGS))

def test_projection_never_returns_unselected_fields():
    row={'pid':'1','identity_complete':True,'full_fingerprint':'a'*40}
    calls=[]
    def run(args):calls.append(args);return json.dumps([row])
    assert read_projection(run)==[row]
    assert calls[0][0:3]==['redis-cli','--raw','EVAL']
    row['password']='secret'
    with pytest.raises(ValueError,match='fields'):read_projection(run)

@pytest.mark.parametrize('field,value',[('upnp','false'),('dnsmasq_only','false'),('trust','false'),('seq','1')])
def test_native_default_values_never_hide_disabled_duplicate(field,value):
    desired=native_allow(*ARGS)
    existing={**desired,'disabled':'1','identity_complete':True,field:value}
    with pytest.raises(ValueError,match='Existing'):reject_duplicate([existing],desired)

def test_native_scope_filter_cannot_hide_duplicate():
    desired=native_allow(*ARGS)
    existing={**desired,'scope':desired['scope']+['not-a-mac'],'identity_complete':True}
    with pytest.raises(ValueError,match='scope'):reject_duplicate([existing],desired)


@pytest.mark.parametrize('field,value',[('type','category'),('action','block'),('localPort',None),('scope',['02:00:00:00:00:02']),('direction','outbound')])
def test_unrelated_incomplete_metadata_cannot_block_new_allow(field,value):
    desired=native_allow(*ARGS)
    row={**desired,field:value,'identity_complete':False,'legacy_identity':False}
    reject_duplicate([row],desired)

def test_matching_incomplete_identity_still_blocks_and_legacy_aliases_never_skip():
    desired=native_allow(*ARGS)
    with pytest.raises(ValueError,match='Incomplete'):
        reject_duplicate([{**desired,'identity_complete':False}],desired)
    with pytest.raises(ValueError,match='legacy'):
        reject_duplicate([{**desired,'type':'category','identity_complete':False,'legacy_identity':True}],desired)

def test_udp_native_allow_preserves_protocol():
    args=list(ARGS);args[3]='udp'
    assert native_allow(*args)['protocol']=='udp'

@pytest.mark.parametrize('value',[['method'],{},[]])
def test_unknown_field_names_are_bounded_projection_metadata(value):
 row={'pid':'1','identity_complete':False,'full_fingerprint':'a'*40,'unknown_fields':value}
 result=read_projection(lambda args:json.dumps([row]))
 assert result[0]['unknown_fields']==([] if value=={} else value)
 assert result[0]['identity_complete'] is False

@pytest.mark.parametrize('value',[['bad\nname'],['x'*97],['ok']*97,'method'])
def test_unknown_field_metadata_rejects_unbounded_input(value):
 row={'pid':'1','identity_complete':False,'full_fingerprint':'a'*40,'unknown_fields':value}
 with pytest.raises(ValueError):read_projection(lambda args:json.dumps([row]))
