import copy
import pytest
from firewalla_mcp.forward_dependencies import require_mapping_removal,hairpin_evidence
from test_forward_reconcile import legacy_mapping as mapping

@pytest.mark.parametrize('protocol',['tcp','udp'])
def test_app_mapping_exact_protocol_removal(protocol):
    m=mapping();m.update(protocol=protocol,description='Game server',autoFirewall=1,ts=1700000000.25)
    m.pop('_type',None)
    other={**m,'protocol':'udp' if protocol=='tcp' else 'tcp'}
    assert require_mapping_removal(m,[m,other])['selected_match']
    def run(args):return '\n'.join('-A FW_POSTROUTING_PORT_FORWARD -d '+m['toIP']+'/32 -p '+p+' -m '+p+' --dport '+str(m['toPort'])+' -j FW_POSTROUTING_HAIRPIN' for p in ['tcp','udp'])
    assert hairpin_evidence(run,m)

@pytest.mark.parametrize('protocol',['tcp','udp'])
def test_app_shared_hairpin_preserved(protocol):
    m=mapping();m.update(protocol=protocol,autoFirewall=1,ts=1)
    other={**m,'dport':str(int(m['dport'])+1),'description':'another forward'}
    with pytest.raises(ValueError,match='Shared hairpin'):require_mapping_removal(m,[m,other])

@pytest.mark.parametrize('field,value',[('autoFirewall',True),('autoFirewall',2),('ts',float('nan')),('ts',-1),('cronTime','* * * * *')])
def test_unknown_app_metadata_rejected(field,value):
    m=mapping();m[field]=value
    with pytest.raises(ValueError):require_mapping_removal(m,[m])
