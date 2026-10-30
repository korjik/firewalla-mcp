import copy,time
import pytest
from firewalla_mcp.workflows import VPNWorkflowManager
from test_approval_bound_vpn import approved_config


def spec():return {'kind':'vpn_workflow','device':'02:00:00:00:00:01','destination_ip':'192.0.2.20','expected_profile':'profile_a','destination_profile':'profile_b','vpn_type':'openvpn','maintenance_until':int(time.time())+300,'forwards':[{'protocol':'tcp','external_port':41000,'destination_port':41000,'owner_token':'a'*32},{'protocol':'udp','external_port':41000,'destination_port':41000,'owner_token':'b'*32}]}

class Router:
 def __init__(self):self.policy='profile_a';self.connected=False;self.owned=[];self.stable='stable';self.applied=[];self.fail=None;self.drift=None;self.preview_drift=False;self.false_connected=False
 async def run(self,site,op,args):
  if op=='managed_workflow_state':return {'status':'ok','data':{'stable':self.stable,'policy':{'state':True,'profileId':self.policy},'lifecycle':{'fingerprint':str(self.connected),'field':{'observed_connected':self.connected}},'owned_forward_steps':self.owned.copy()}}
  assert op=='managed_write';s=args['spec'];kind=s['kind']
  if args['mode']=='preview':
   if self.preview_drift:self.stable='changed'
   return {'status':'ok','data':{'fingerprint':'fresh','present':kind=='managed_lifecycle' and self.connected}}
  self.applied.append(kind)
  if self.fail==kind:return {'status':'ok','data':{'outcome':'uncertain'}}
  if kind=='managed_lifecycle':self.connected=not self.false_connected
  elif kind=='managed_vpn':self.policy='profile_b'
  else:self.owned.append(len(self.owned))
  if self.drift==kind:self.stable='changed'
  return {'status':'ok','data':{'outcome':'applied'}}

@pytest.fixture
def manager(approved_config):
 c,_=approved_config;c=c.model_copy(update={'writes_enabled':True,'write_confirmation_mode':'host_confirmed','approval_directory':None})
 r=Router();return VPNWorkflowManager(c,r),r

async def test_full_projected_sequence_one_plan_and_replay(manager):
 m,r=manager;p=await m.preview_workflow('Router A',spec());assert len(p['steps'])==4 and p['dependencies']==[[],[0],[1],[2]]
 assert p['next_step']['apply_tool']=='apply_network_plan' and 'ssh_command' not in p['next_step']
 result=await m.apply_workflow(p['plan_id']);assert result['status']=='applied' and len(result['steps'])==4
 assert r.applied==['managed_lifecycle','managed_vpn','managed_forward','managed_forward']
 assert (await m.apply_workflow(p['plan_id']))['replayed'];assert len(r.applied)==4

async def test_async_connection_failure_stops_before_device_change(manager):
 m,r=manager;r.fail='managed_lifecycle';p=await m.preview_workflow('router-a',spec())
 result=await m.apply_workflow(p['plan_id']);assert result['status']=='partial' and r.applied==['managed_lifecycle'] and r.policy=='profile_a'

async def test_existing_connection_skips_start(manager):
 m,r=manager;r.connected=True;p=await m.preview_workflow('router-a',spec());assert (await m.apply_workflow(p['plan_id']))['status']=='applied';assert 'managed_lifecycle' not in r.applied

@pytest.mark.parametrize('kind',['managed_lifecycle','managed_vpn','managed_forward'])
async def test_external_drift_after_step_stops_without_rollback(manager,kind):
 m,r=manager;r.drift=kind;p=await m.preview_workflow('router-a',spec());result=await m.apply_workflow(p['plan_id']);assert result['status']=='partial';assert r.applied[-1]==kind
 assert (await m.apply_workflow(p['plan_id']))['replayed']

async def test_fresh_step_fingerprint_cannot_adopt_external_drift(manager):
 m,r=manager;p=await m.preview_workflow('router-a',spec());r.preview_drift=True
 assert (await m.apply_workflow(p['plan_id']))['status']=='uncertain';assert not r.applied

async def test_altered_expired_initial_state_fail_closed(manager):
 m,r=manager;p=await m.preview_workflow('router-a',spec());m.plans[p['plan_id']]['steps'][1]['destination_profile']='other'
 with pytest.raises(ValueError,match='Plan changed'):await m.apply_workflow(p['plan_id'])
 assert not r.applied

async def test_initial_state_drift_before_consumption(manager):
 m,r=manager;p=await m.preview_workflow('router-a',spec());r.policy='profile_b'
 with pytest.raises(ValueError,match='policy transition'):await m.apply_workflow(p['plan_id'])
 assert not r.applied

async def test_restart_durable_claim_prevents_replay(manager):
 m,r=manager;p=await m.preview_workflow('router-a',spec());original=copy.deepcopy(m.plans[p['plan_id']]);await m.apply_workflow(p['plan_id'])
 fresh=VPNWorkflowManager(m.config,Router());fresh.plans[p['plan_id']]=original
 with pytest.raises(ValueError,match='consumed'):await fresh.apply_workflow(p['plan_id'])


async def test_acknowledged_start_without_connected_observation_stops(manager):
 m,r=manager;r.false_connected=True;p=await m.preview_workflow('router-a',spec())
 result=await m.apply_workflow(p['plan_id']);assert result['status']=='partial' and r.policy=='profile_a' and r.applied==['managed_lifecycle']

async def test_expired_plan_does_not_claim_or_dispatch(manager,monkeypatch):
 m,r=manager;p=await m.preview_workflow('router-a',spec())
 monkeypatch.setattr(time,'time',lambda:p['expires_at']+1)
 with pytest.raises(ValueError,match='expired'):await m.apply_workflow(p['plan_id'])
 assert not r.applied

async def test_expanded_catalog_preserves_existing_vpn_tools(manager):
 from firewalla_mcp.server import build_server
 m,r=manager;c=m.config.model_copy(update={'vpn_writes_enabled':True,'vpn_confirmation_mode':'host_confirmed'})
 combined={t.name for t in await build_server(c,transport=r).list_tools()}
 vpn_config=c.model_copy(update={'writes_enabled':False})
 old={t.name for t in await build_server(vpn_config,transport=r,vpn_write_catalog=True).list_tools()}
 assert old<=combined and len(combined)==57
 assert {'preview_network_plan','apply_network_plan','preview_forward_plan','preview_persistent_vpn_forward'}<=combined
