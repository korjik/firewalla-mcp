"""Bounded VPN start -> explicit policy switch -> 1/2 persistent forwards.

One host-confirmed immutable plan. Each internal SSH call retains firmware/state
checks. Projected changes are limited to declared runtime/policy/owned mappings.
"""
import copy
import secrets
import time
from .writes import WriteManager,digest
from .remote import workflow_specs,VPN_MANAGEMENT_REVISIONS


class VPNWorkflowManager(WriteManager):
    def apply_tool_name(self):return 'apply_network_plan'

    def enabled(self):
        super().enabled()
        if not self.host_confirmed():raise ValueError('Network plans require host-confirmed general writes')

    async def state(self,site,spec):
        r=await self.transport.run(site,'managed_workflow_state',{'spec':spec,'revision':site.management_revision})
        if r.get('status')!='ok':raise ValueError('Workflow state unsupported or unavailable; no automatic action')
        return r['data']

    async def preview_workflow(self,box,spec):
        self.enabled();box=self.config.resolve(box)
        self.plans={k:v for k,v in self.plans.items() if v["expires_at"]>time.time()}
        if len(self.plans)>=128:raise ValueError("Workflow plan capacity reached")
        if box not in self.config.sites:raise ValueError('Unknown box')
        spec=copy.deepcopy(spec);steps=workflow_specs(spec)
        if type(spec['maintenance_until']) is not int or not time.time()<spec['maintenance_until']<=time.time()+600:raise ValueError('Maintenance deadline required')
        site=self.config.sites[box].model_copy(deep=True)
        if site.management_revision not in VPN_MANAGEMENT_REVISIONS:raise ValueError('Unreviewed workflow revision')
        binding=self.site_binding(box)
        async with self.locks[box]:
            initial=await self.state(site,spec)
            if initial['policy']!={'state':True,'profileId':spec['expected_profile']} or initial['owned_forward_steps']:raise ValueError('Workflow initial state changed')
            if self.site_binding(box)!=binding:raise ValueError('Box configuration changed')
            plan={'plan_id':secrets.token_hex(16),'box':box,'spec':spec,'steps':steps,'initial':initial,
                  'site_binding':binding,'expires_at':min(int(time.time())+600,spec['maintenance_until']),
                  'apply_tool':'apply_network_plan','atomic':False,
                  'dependencies':[[],[0]]+[[i-1] for i in range(2,len(steps))],
                  'rollback':'No automatic compensation; inspect verified and uncertain results before a separate exact plan',
                  'risks':['Start affects all users of this VPN profile','Switch preserves configured safety/DNS settings but effective routing is not proved','No concurrent VPN/profile/policy/mapping edits during maintenance window','Provider port and firewall access are not created or verified']}
            plan['digest']=digest(plan);plan['status']='pending';self.plans[plan['plan_id']]=plan
            return {**copy.deepcopy(plan),'next_step':self.approval_next_step(plan)}

    def expected_state(self,plan,current,index):
        if current['stable']!=plan['initial']['stable']:raise ValueError('Unrelated configuration or mappings changed')
        profile=plan['spec']['expected_profile'] if index<2 else plan['spec']['destination_profile']
        if current['policy']!={'state':True,'profileId':profile}:raise ValueError('Unexpected device policy transition')
        if current['owned_forward_steps']!=list(range(max(0,index-2))):raise ValueError('Unexpected mapping transition')
        if index==0:
            if current['lifecycle']['fingerprint']!=plan['initial']['lifecycle']['fingerprint']:raise ValueError('Initial VPN state changed')
        elif current['lifecycle']['field']['observed_connected'] is not True:
            raise ValueError('VPN connectivity not verified; stop before dependent changes')

    async def apply_workflow(self,plan_id):
        self.enabled()
        if plan_id not in self.plans:raise ValueError('Unknown network plan')
        p=self.plans[plan_id]
        async with self.locks[p['box']]:
            if p['status']!='pending':return {'status':p['status'],'steps':p.get('result',[]),'replayed':True}
            self.check_plan(p)
            if time.time()>=p['expires_at']:raise ValueError('Plan expired')
            site=self.config.sites[p['box']].model_copy(deep=True)
            self.expected_state(p,await self.state(site,p['spec']),0)
            self.consume_approval(p);self.audit(plan_id,'workflow_host_requested_attempt',p['box'])
            p['status']='uncertain';p['result']=[]
            for index,step in enumerate(p['steps']):
                try:
                    if time.time()>=p['expires_at']:raise ValueError('Plan expired during execution')
                    self.check_plan(p);current=await self.state(site,p['spec']);self.expected_state(p,current,index)
                    observation=await self.remote_write(site,step,'preview')
                    if observation.get('status')!='ok':raise ValueError('Step preview unavailable')
                    before=observation['data']
                    self.expected_state(p,await self.state(site,p['spec']),index)
                    if index==0 and before['present']:
                        result={'outcome':'already_connected','changed':False}
                    else:
                        if before['present']:raise ValueError('Unexpected duplicate/desired state')
                        r=await self.remote_write(site,step,'apply',before['fingerprint'],expires_at=p['expires_at'])
                        result=r.get('data',{'outcome':'uncertain'}) if r.get('status')=='ok' else {'outcome':'uncertain'}
                    p['result'].append({'index':index,'result':result})
                    if result.get('outcome') not in ('applied','already_connected'):raise ValueError('Step not verified')
                    self.expected_state(p,await self.state(site,p['spec']),index+1)
                    self.audit(plan_id,'workflow_step_'+str(index)+'_verified',p['box'])
                except Exception:
                    p['status']='partial' if p['result'] else 'uncertain'
                    return {'status':p['status'],'steps':copy.deepcopy(p['result']),'stopped_at':index,
                            'resume':'Inspect uncertain outcome. No automatic rollback/retry; new exact remaining plan and confirmation required.'}
            p['status']='applied';return {'status':'applied','steps':copy.deepcopy(p['result']),'atomic':False,'enforcement':'Configured state and observed VPN/kernel checks only; external reachability unverified'}
