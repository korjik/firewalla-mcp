import copy
import time
import pytest
from test_forward_metadata_manager import metadata,coordinator,manager,native_fixture
from firewalla_mcp.forward_manager import ForwardManager
from firewalla_mcp import forward_native as native
from firewalla_mcp.forward_policy import native_allow

@pytest.fixture
def reset_fixture(metadata,monkeypatch):
 fm,spec,s=metadata;fm.config.forwarding_app_management_enabled=True
 old_snapshot=native.remote.forward_snapshot
 def snapshot(spec):
  result=old_snapshot(spec)
  result['collisions']=[r for r in result['collisions'] if r['protocol']==spec['protocol']]
  return result
 monkeypatch.setattr(native.remote,'forward_snapshot',snapshot)
 for proto in ['tcp','udp']:
  for port in [19132,19133]:
   m={**s['maps'][0],'toMac':'02:00:00:00:00:02','toIP':'192.0.2.22','protocol':proto,'dport':str(port),'toPort':str(port),'description':f'Game {proto} {port}','autoFirewall':1,'ts':1700000000}
   s['maps'].append(m)
   pid=str(90+len(s['policies']))
   s['policies'].append({'pid':pid,'timestamp':'1700000001','full_fingerprint':pid.zfill(40),'identity_complete':True,'purpose':'port_forwarding','updatedTime':'1700000002.1234567','type':'mac','target':'TAG','action':'allow','direction':'inbound','scope':[m['toMac']],'protocol':proto,'localPort':str(port)})
 for port,token in [(80,'c'),(443,'d')]:
  v=native_allow(spec['device'],spec['interface_uuid'],'0.0.0.0/0','tcp',port,port,token*32)
  s['policies'].append({**v,'pid':str(port),'timestamp':'1700000002','full_fingerprint':token*40,'identity_complete':True})
 monkeypatch.setattr('firewalla_mcp.forward_policy.read_projection',lambda run:copy.deepcopy(s['policies']))
 monkeypatch.setattr('firewalla_mcp.forward_app_adapter.AppForwardAdapter.legacy_proof',lambda self,row:True)
 monkeypatch.setattr('firewalla_mcp.forward_app_adapter.hairpin_evidence',lambda run,value:any(r['toIP']==value['toIP'] and r['protocol']==value['protocol'] and r['toPort']==value['toPort'] for r in s['maps']))
 return fm,spec,s

async def plan_reset(fm,spec,*,all_mappings=True):
 args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
 inv=await fm.inspect_app_objects(*args,int(time.time())+600)
 maps=[{k:m[k] for k in ['key','fingerprint']} for m in inv['mappings']]
 ps=[{k:p[k] for k in ['id','birth','fingerprint']} for p in inv['policy_candidates']]
 actions=[{'protocol':'tcp','external_port':p,'destination_port':p,'source_network':'0.0.0.0/0','display_name':name} for p,name in [(80,'Automation HTTP'),(443,'Automation HTTPS')]]
 return args,await fm.preview_app_reset(*args,maps,ps,actions,all_mappings,int(time.time())+600)

async def test_full_reset_multi_device_then_restart_recovery(reset_fixture):
 fm,spec,s=reset_fixture;original=copy.deepcopy(s['maps']);args,p=await plan_reset(fm,spec)
 assert len(p['steps'])==24
 assert p['scope']=='native_forwarding_reset'
 result=await fm.apply(p['plan_id']);assert result['outcome']=='applied',result
 assert len(s['maps'])==2 and len(s['policies'])==2
 assert {r['description'] for r in s['maps']}=={'Automation HTTP','Automation HTTPS'}
 fresh=ForwardManager(fm.writes,fm.adapter_factory)
 view=await fresh.inspect(*args,int(time.time())+600)
 assert len([r for r in view['objects'] if r['kind']=='mapping'])==2
 recovery=await fresh.recover(p['plan_id'],True,int(time.time())+600)
 result=await fresh.apply(recovery['plan_id']);assert result['outcome']=='applied',result
 assert sorted(s['maps'],key=lambda m:m['description'])==sorted(original,key=lambda m:m['description'])
 assert len(s['policies'])==6

async def test_app_mode_off_no_preview(reset_fixture):
 fm,spec,s=reset_fixture;fm.config.forwarding_app_management_enabled=False
 with pytest.raises(ValueError,match='disabled'):await plan_reset(fm,spec)
 assert not s['calls']

async def test_reset_rejects_drift_replay_and_preserves_unselected_policy(reset_fixture):
 fm,spec,s=reset_fixture
 s['policies'].append({'pid':'999','timestamp':'1','full_fingerprint':'f'*40,'identity_complete':False,'type':'category','target':'games','action':'block'})
 args,p=await plan_reset(fm,spec)
 s['maps'][2]['description']='External edit'
 with pytest.raises(ValueError,match='Initial state changed'):await fm.apply(p['plan_id'])
 assert not s['calls']

async def test_reset_partial_expiry_restart_restore(reset_fixture,monkeypatch):
 fm,spec,s=reset_fixture;original_maps=copy.deepcopy(s['maps']);args,p=await plan_reset(fm,spec)
 original=fm.transaction
 def transaction(*args,**kwargs):
  tx=original(*args,**kwargs);mutate=tx.adapter.mutate
  async def interrupted(*args):
   result=await mutate(*args);tx.clock=lambda:p['expires_at']+1;return result
  tx.adapter.mutate=interrupted;return tx
 monkeypatch.setattr(fm,'transaction',transaction)
 result=await fm.apply(p['plan_id']);assert result['outcome']=='partial_expired' and result['completed']==1
 fresh=ForwardManager(fm.writes,fm.adapter_factory)
 recovery=await fresh.recover(p['plan_id'],True,int(time.time())+600)
 assert (await fresh.apply(recovery['plan_id']))['outcome']=='applied'
 assert s['maps']==original_maps
 with pytest.raises(ValueError):await fresh.apply(recovery['plan_id'])

async def test_all_mappings_rejects_omitted_object(reset_fixture):
 fm,spec,s=reset_fixture;args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
 inv=await fm.inspect_app_objects(*args,int(time.time())+600)
 maps=[{k:m[k] for k in ['key','fingerprint']} for m in inv['mappings']][:-1]
 with pytest.raises(ValueError,match='Additional mappings'):
  await fm.preview_app_reset(*args,maps,[],[],True,int(time.time())+600)
 assert not s['calls']

async def test_new_tools_optin_and_family_contract(reset_fixture):
 fm,spec,s=reset_fixture
 from firewalla_mcp.server import build_server
 from firewalla_mcp.models import AppRecreateAction
 tools={t.name:t for t in await build_server(fm.config).list_tools()}
 assert tools['preview_forwarding_reset'].annotations.readOnlyHint
 assert 'inspect_forwarding_app_objects' in tools
 args={'protocol':'udp','external_port':1234,'destination_port':1234,'source_network':'203.0.113.0/24','display_name':'UDP service','address_family':'ipv4'}
 assert AppRecreateAction(**args).protocol=='udp'
 for update in [{'address_family':'ipv6'},{'source_network':'2001:db8::/32'},{'protocol':'icmp'}]:
  with pytest.raises(ValueError):AppRecreateAction(**{**args,**update})

async def test_maximum_reset_and_restart_rollback_proof_bounds(reset_fixture):
 fm,spec,s=reset_fixture;args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
 for port in [19200,19201]:
  s['maps'].append({**s['maps'][2],'protocol':'udp','dport':str(port),'toPort':str(port),'description':f'Extra UDP {port}'})
 original=copy.deepcopy(s['maps'])
 inv=await fm.inspect_app_objects(*args,int(time.time())+600)
 maps=[{k:m[k] for k in ['key','fingerprint']} for m in inv['mappings']]
 ps=[{k:p[k] for k in ['id','birth','fingerprint']} for p in inv['policy_candidates']]
 actions=[{'protocol':'tcp','external_port':p,'destination_port':p,'source_network':'0.0.0.0/0','display_name':'Service '+str(p)} for p in [80,443,8080,8443]]
 plan=await fm.preview_app_reset(*args,maps,ps,actions,True,int(time.time())+600)
 assert len(plan['steps'])==32
 result=await fm.apply(plan['plan_id']);assert result['outcome']=='applied',result
 fresh=ForwardManager(fm.writes,fm.adapter_factory)
 recovery=await fresh.recover(plan['plan_id'],True,int(time.time())+600)
 assert len(recovery['steps'])==32
 result=await fresh.apply(recovery['plan_id']);assert result['outcome']=='applied',result
 assert sorted(s['maps'],key=lambda x:x['description'])==sorted(original,key=lambda x:x['description'])
 # Fresh ordinary inspection reloads only journal-verified allocated IDs.
 again=ForwardManager(fm.writes,fm.adapter_factory)
 view=await again.inspect(*args,int(time.time())+600)
 assert len(view['objects'])==14

async def test_udp_recreation_preserves_family_and_protocol(reset_fixture):
 fm,spec,s=reset_fixture;args=('router-a',spec['device'],spec['destination_ip'],spec['interface_uuid'])
 inv=await fm.inspect_app_objects(*args,int(time.time())+600)
 maps=[{k:m[k] for k in ['key','fingerprint']} for m in inv['mappings']]
 ps=[{k:p[k] for k in ['id','birth','fingerprint']} for p in inv['policy_candidates']]
 actions=[{'protocol':'udp','external_port':5555,'destination_port':5555,'source_network':'203.0.113.0/24','display_name':'UDP service'}]
 plan=await fm.preview_app_reset(*args,maps,ps,actions,True,int(time.time())+600)
 result=await fm.apply(plan['plan_id']);assert result['outcome']=='applied',result
 assert len(s['maps'])==1 and s['maps'][0]['protocol']=='udp'
 assert len(s['policies'])==1 and s['policies'][0]['protocol']=='udp' and s['policies'][0]['target']=='203.0.113.0/24'
