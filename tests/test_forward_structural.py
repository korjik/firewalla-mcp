import copy
import pytest
from firewalla_mcp.forward_dependencies import require_mapping_removal, hairpin_evidence
from test_forward_reconcile import legacy_mapping


def other(row,**kw):return {**row,'description':'mcp:'+'b'*32,**kw}

def test_exact_native_match_ignores_description_mac_and_coerces_ports():
    row=legacy_mapping()
    duplicate=other(row,toMac='02:00:00:00:00:02',dport=443,toPort=443)
    with pytest.raises(ValueError,match='selector'):
        require_mapping_removal(row,[row,duplicate])

@pytest.mark.parametrize('change',[
 {'wanUUID':'22222222-2222-4222-8222-222222222222'},
 {'dport':'8443'}, {'extIP':'198.51.100.1'}, {'applyToAll':True},
 {'active':False,'enabled':False}, {'toPort':'440-445'}, {'protocol':None},
])
def test_shared_hairpin_never_removed_even_other_wan_or_disabled(change):
    row=legacy_mapping()
    with pytest.raises(ValueError,match='hairpin|structural|selector'):
        require_mapping_removal(row,[row,other(row,**change)])

@pytest.mark.parametrize('change',[{'toIP':'192.0.2.21'},{'toPort':'8443','dport':'8443'},{'protocol':'udp'},{'_type':'dmz_host'}])
def test_proven_disjoint_resources_are_preserved(change):
    row=legacy_mapping()
    assert require_mapping_removal(row,[row,other(row,**change)])['selected_match']

@pytest.mark.parametrize('field,value',[('wanUUID','*'),('dport','*'),('toPort','*'),('protocol',''),('dport',False),('_type','dmz_host')])
def test_requested_wildcards_and_native_false_coercion_rejected(field,value):
    row={**legacy_mapping(),field:value}
    with pytest.raises(ValueError):require_mapping_removal(row,[row])

@pytest.mark.parametrize('change',[{'toIP':None},{'toGuid':'identity'},{'unknownSelector':'x'},{'protocol':'icmp'},{'toPort':'service'}])
def test_unknown_related_resources_fail_closed(change):
    row=legacy_mapping()
    with pytest.raises(ValueError,match='structural'):
        require_mapping_removal(row,[row,other(row,**change)])

RULE='-A FW_POSTROUTING_PORT_FORWARD -d 192.0.2.20/32 -p tcp -m tcp --dport 443 -j FW_POSTROUTING_HAIRPIN'
def test_exact_hairpin_evidence_and_absence():
    row=legacy_mapping();calls=[]
    def run(args):calls.append(args);return RULE
    assert hairpin_evidence(run,row)
    assert calls[0]==['sudo','-n','iptables','-t','nat','-S','FW_POSTROUTING_PORT_FORWARD']
    assert not hairpin_evidence(lambda a:'-N FW_POSTROUTING_PORT_FORWARD',row)
    assert not hairpin_evidence(lambda a:RULE.replace('443','80'),row)

@pytest.mark.parametrize('rules',[RULE+'\n'+RULE,RULE.replace('/32','/24'),RULE.replace('443','440:445'),RULE.replace('-p tcp -m tcp ','') ,RULE+' --comment arbitrary',RULE.replace('-j FW_POSTROUTING_HAIRPIN','-j ACCEPT'),RULE.replace('-d ','! -d ')])
def test_ambiguous_kernel_evidence_blocks(rules):
    with pytest.raises(ValueError):hairpin_evidence(lambda a:rules,legacy_mapping())
