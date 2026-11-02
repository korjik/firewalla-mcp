import copy
import time
import pytest
from test_forward_native import native_fixture
from firewalla_mcp.forward_app_adapter import AppForwardAdapter
from firewalla_mcp.forward_transaction import ForwardTransaction,build_plan
from firewalla_mcp import forward_native as native

@pytest.fixture
def adopted(native_fixture,monkeypatch):
 old,tx,spec,s=native_fixture
 m={**native.remote.forward_value(spec),'active':True,'description':'Game server','autoFirewall':1,'ts':1700000000.25}
 p={'pid':'98','timestamp':'1700000001','full_fingerprint':'a'*40,'identity_complete':True,'type':'mac','target':'TAG','action':'allow','direction':'inbound','scope':[spec['device']],'protocol':'tcp','localPort':m['toPort']}
 s['maps']=[m];s['policies']=[p]
 a=AppForwardAdapter(old.revision,spec,[],{'mappings':[m],'policies':[p]})
 monkeypatch.setattr('firewalla_mcp.forward_policy.read_projection',lambda run:copy.deepcopy(s['policies']))
 monkeypatch.setattr(a,'legacy_proof',lambda row,rules=None:True)
 monkeypatch.setattr('firewalla_mcp.forward_app_adapter.hairpin_evidence',lambda run,value:any(r['toIP']==value['toIP'] and r['protocol']==value['protocol'] and r['toPort']==value['toPort'] for r in s['maps']))
 monkeypatch.setattr(native.remote,'forward_kernel_evidence',lambda spec:{'nat_rule_observed':any(r['toIP']==spec['destination_ip'] and r['dport']==str(spec['external_port']) for r in s['maps']),'vpn_ingress_link_observed':True})
 # Reuse the isolated private journal; no router calls.
 tx=ForwardTransaction(str(tx.journals.root.root()),a,lambda p:None)
 return a,tx,s

async def test_adopted_policy_delete_and_restart_restore(adopted,monkeypatch):
 a,tx,s=adopted;initial=await a.snapshot();key='policy:app:98';row=initial['objects'][key];disabled={**row,'enabled':False}
 plan=build_plan('router-a','binding',initial,[{'operation':'disable','key':key,'before':row,'after':disabled},{'operation':'remove','key':key,'before':disabled,'after':None}])
 assert (await tx.execute(plan,'binding'))['outcome']=='applied'
 fresh=AppForwardAdapter(a.revision,a.template,a.receipts,{'mappings':a.app_maps,'policies':a.app_policies})
 monkeypatch.setattr(fresh,'legacy_proof',lambda row,rules=None:True)
 tx=ForwardTransaction(str(tx.journals.root.root()),fresh,lambda p:None)
 recovery=await tx.recovery_preview(plan['plan_id'],'binding',rollback=True)
 assert (await tx.execute(recovery,'binding'))['outcome']=='applied'
 current=await fresh.snapshot()
 restored=current['objects'][key]
 assert restored['value']==row['value'] and restored['enabled']
 assert restored['instance']['id']!='98'

async def test_adopted_policy_changed_semantics_rejected(adopted):
 a,tx,s=adopted;s['policies'][0]['remotePort']='53'
 with pytest.raises(ValueError,match='identity changed'):await a.snapshot()

async def test_unrelated_policy_preserved(adopted):
 a,tx,s=adopted;s['policies'].append({'pid':'50','timestamp':'1','full_fingerprint':'b'*40,'identity_complete':False})
 state=await a.snapshot();assert state['objects']['policy:50']['value']=={'policy_fingerprint':'b'*40}

async def test_equal_unallocated_policy_never_acquires_old_identity(adopted):
 a,tx,s=adopted;old=copy.deepcopy(s['policies'][0]);s['policies']=[{**old,'pid':'99','timestamp':'1700000099'}]
 state=await a.snapshot()
 assert 'policy:app:98' not in state['objects']
 assert 'policy:99' in state['objects']

async def test_verified_allocation_survives_journal_reload(adopted,monkeypatch):
 a,tx,s=adopted
 # Only the private verified transaction records can make a restored ID
 # eligible on a fresh helper instance; structural equality alone cannot.
 current={**s['policies'][0],'pid':'99','timestamp':'1700000099'};s['policies']=[current]
 fresh=AppForwardAdapter(a.revision,a.template,[],{'mappings':a.app_maps,'policies':a.app_policies,
  'policy_instances':[{'key':'policy:app:98','id':'99','birth':'1700000099'}]})
 assert (await fresh.snapshot())['objects']['policy:app:98']['instance']['id']=='99'
