import pytest
from firewalla_mcp.forwarding_guidance import guidance
from test_writes import manager
from test_interface_forward import wan_spec

@pytest.mark.parametrize('phase',['preview','inventory','existing'])
def test_intent_never_implies_reachability(phase):
    g=guidance(phase=phase)
    assert g['service_ready']=='unknown'
    assert g['verification_levels']['independent_external_reachability']=='not_tested'
    assert g['verification_levels']['firewall_allow_policy']=='not_evaluated_or_changed'

@pytest.mark.parametrize('observed',[True,False,None])
def test_mapping_evidence_does_not_prove_permission(observed):
    g=guidance(result={'data':{'outcome':'applied','verification':'stored_mapping_verified','evidence':{'nat_rule_observed':observed}}},phase='apply')
    assert g['verification_levels']['stored_mapping']=='mapping_verified'
    assert g['verification_levels']['kernel_nat']=={True:'observed',False:'not_observed',None:'not_checked'}[observed]
    assert g['service_ready']=='unknown'

def test_partial_batch_does_not_become_verified():
    g=guidance({'kind':'managed_forward_batch'},{'data':{'outcome':'partial','steps':[{'verification':'stored_mapping_verified'}]}},phase='apply')
    assert g['verification_levels']['stored_mapping']=='not_checked'

def test_rollback_is_removal_not_service_ready():
    g=guidance(result={'data':{'outcome':'rolled_back','verification':'stored_mapping_verified','evidence':{'nat_rule_observed':False}}},phase='apply')
    assert g['verification_levels']['stored_mapping']=='removal_verified'
    assert g['service_ready']=='unknown'

async def test_guidance_in_preview_and_apply(manager,monkeypatch):
    site=manager.config.sites['router-a']
    monkeypatch.setattr(manager,'validate',lambda *args:site)
    p=await manager.preview('router-a',wan_spec())
    assert p['forwarding_guidance']['service_ready']=='unknown'
    manager.transport.run.return_value={'status':'ok','data':{'outcome':'applied','verification':'stored_mapping_verified','evidence':{'nat_rule_observed':True},'state':{'fingerprint':'b'*64,'present':True}}}
    r=await manager.apply(p['plan_id'])
    assert r['forwarding_guidance']['verification_levels']['stored_mapping']=='mapping_verified'
    assert r['forwarding_guidance']['service_ready']=='unknown'

async def test_no_change_retains_incomplete_service_warning(manager,monkeypatch):
    monkeypatch.setattr(manager,'validate',lambda *args:manager.config.sites['router-a'])
    manager.transport.run.return_value={'status':'ok','data':{'fingerprint':'a'*64,'present':True,'conflict':False}}
    r=await manager.preview('router-a',wan_spec())
    assert r['status']=='no_change' and r['forwarding_guidance']['service_ready']=='unknown'
    assert not manager.plans

def test_uncertain_rollback_does_not_claim_mapping_present():
    g=guidance(result={'data':{'outcome':'uncertain','verification':'stored_mapping_verified','evidence':{'nat_rule_observed':True}}},phase='apply')
    assert g['verification_levels']['stored_mapping']=='stored_state_verified'
    assert g['service_ready']=='unknown'
