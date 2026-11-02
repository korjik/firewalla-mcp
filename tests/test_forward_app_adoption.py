import copy
import pytest
from firewalla_mcp.forward_app_adoption import legacy_allow,select_app_objects
from firewalla_mcp.writes import digest
from test_forward_reconcile import legacy_mapping

def fixture(protocol='tcp'):
 m=legacy_mapping();m.update(description='Game server',autoFirewall=1,ts=1700000000.25,protocol=protocol)
 m.pop('_type',None)
 p={'pid':'123','timestamp':'1700000001','full_fingerprint':'a'*40,'identity_complete':True,
    'type':'mac','target':'TAG','action':'allow','direction':'inbound','scope':[m['toMac']],
    'protocol':protocol,'localPort':m['toPort']}
 ms=[{'fingerprint':digest(m)}];ps=[{'id':'123','birth':p['timestamp'],'fingerprint':p['full_fingerprint']}]
 return m,p,ms,ps

@pytest.mark.parametrize('protocol',['tcp','udp'])
def test_explicit_app_selection_no_execution_or_label_ownership(protocol):
 m,p,ms,ps=fixture(protocol)
 result=select_app_objects([m],[p],ms,ps)
 assert result['execution_enabled'] is False
 assert result['policies'][0]['value']['protocol']==protocol
 assert result['policies'][0]['instance']['id']=='123'
 assert 'IPv6' in result['policies'][0]['disclosure']
 assert result['mappings'][0]['value']==m
 assert result['automatic_policy_selection'] is False

@pytest.mark.parametrize('change',[{'scope':[]},{'scope':['02:00:00:00:00:01','02:00:00:00:00:02']},{'action':'block'}, {'direction':'bidirection'},{'protocol':'*'},{'localPort':'1-65535'},{'cronTime':'* * * * *'},{'targetRgId':'group'}, {'tag':['tag']},{'owanUUID':'wan'},{'origDport':'443'},{'identity_complete':False},{'upnp':'1'},{'seq':'1'},{'duration':'60'}])
def test_unreviewed_or_broader_semantics_rejected(change):
 m,p,ms,ps=fixture();p.update(change)
 with pytest.raises(ValueError):select_app_objects([m],[p],ms,ps)

@pytest.mark.parametrize('field,value',[('timestamp','new birth'),('full_fingerprint','b'*40),('pid','124')])
def test_policy_id_birth_fingerprint_drift(field,value):
 m,p,ms,ps=fixture();p[field]=value
 with pytest.raises(ValueError):select_app_objects([m],[p],ms,ps)

def test_unselected_global_policy_preserved():
 m,p,ms,ps=fixture();global_rule={'pid':'124','scope':[],'action':'block'}
 result=select_app_objects([m],[p,global_rule],ms,ps)
 assert result['preserved_policy_count']==1

def test_referenced_policy_blocks_adoption():
 m,p,ms,ps=fixture();ref={'pid':'124','affectedPids':['123']}
 with pytest.raises(ValueError,match='Referenced'):select_app_objects([m],[p,ref],ms,ps)

def test_mapping_drift_and_duplicate_selection():
 m,p,ms,ps=fixture()
 with pytest.raises(ValueError):select_app_objects([{**m,'description':'changed'}],[p],ms,ps)
 with pytest.raises(ValueError):select_app_objects([m],[p],ms+ms,ps)

def test_policy_not_selected_implicitly():
 m,p,ms,ps=fixture();result=select_app_objects([m],[p],ms,[])
 assert not result['policies'] and result['preserved_policy_count']==1

def test_ipv6_nat_is_not_inferred():
 m,p,ms,ps=fixture();m['toIP']='2001:db8::10';ms=[{'fingerprint':digest(m)}]
 with pytest.raises(ValueError):select_app_objects([m],[p],ms,ps)

@pytest.mark.parametrize('field',['origDst','origDport','owanUUID','wanUUID','remotePort','resolver','targetRgId','expire','cronTime'])
@pytest.mark.parametrize('value',['false','[]',False,[]])
def test_scalar_selector_not_erased_as_boolean_or_array(field,value):
 m,p,ms,ps=fixture();p[field]=value
 with pytest.raises(ValueError):select_app_objects([m],[p],ms,ps)

@pytest.mark.parametrize('change',[{'timestamp':True},{'timestamp':'nan'},{'timestamp':-1},{'timestamp':{}},{'disabled':'unknown'},{'disabled':2},{'disabled':[]},{'disabled':'false'}])
def test_unknown_birth_and_state_fail_closed(change):
 m,p,ms,ps=fixture();p.update(change)
 with pytest.raises(ValueError):legacy_allow(p)
