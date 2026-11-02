"""Candidate native adapter for a single scoped WAN forwarding maintenance plan.

Not registered or deployed. Uses existing guarded management requests, never raw
Redis writes. The transaction coordinator owns approval, journal and recovery.
"""
import copy
import hashlib
import json
import re
import time
from . import remote
from .forward_policy import native_allow, read_projection, reject_duplicate, IDENTITY_FIELDS
from .forward_enforcement import verify_policy
from .forward_dependencies import require_mapping_removal, hairpin_evidence
from .forward_transaction import transition, bind_created_instance
from .writes import digest

BLOCK_HASH='f7c04a8835b619f9ea06441d671c7ebdbb83d1db621d915de05902046dea9d9a'


class NativeForwardAdapter:
    def __init__(self,revision,template):
        remote.validate_managed(template)
        if template['kind']!='managed_interface_forward':raise ValueError('WAN lifecycle only')
        self.revision=revision;self.template=copy.deepcopy(template)
        self.policies=[]

    def guard(self):
        remote.management_guard(self.revision,'managed_interface_forward')
        remote.policy_source_guard(self.revision)
        if hashlib.sha256(remote.contract_file('/home/pi/firewalla','control/Block.js')).hexdigest()!=BLOCK_HASH:
            raise ValueError('Native policy enforcement source drift')

    def mapping_spec(self,value):
        if set(value)-{'_type'}!={'active','description','dport','enabled','protocol','state','toIP','toMac','toPort','wanUUID'}:
            raise ValueError('Unsupported mapping shape')
        if any(value[k] is not True for k in ('active','enabled','state')) or value.get('_type','port_forward')!='port_forward':raise ValueError('Mapping state')
        if not re.fullmatch('mcp:[a-f0-9]{32}',value['description']):raise ValueError('Mapping provenance')
        spec={**self.template,'protocol':value['protocol'],'external_port':int(value['dport']),
              'destination_port':int(value['toPort']),'owner_token':value['description'][4:]}
        remote.validate_managed(spec)
        if {k:v for k,v in value.items() if k!='_type'}!={**remote.forward_value(spec),'active':True}:raise ValueError('Mapping scope changed')
        return spec

    def policy_value(self,row):
        if any(row.get(k) not in (None,'') for k in ('purpose','updatedTime')):raise ValueError('Unreviewed managed policy metadata')
        if 'identity_complete' in row and row['identity_complete'] is not True:raise ValueError('Incomplete policy identity')
        scope=row.get('scope')
        if isinstance(scope,str):scope=json.loads(scope)
        if scope!=[self.template['device']]:raise ValueError('Policy device scope')
        desc=row.get('description','')
        if not isinstance(desc,str) or not re.fullmatch('mcp:[a-f0-9]{32}',desc):raise ValueError('Policy ownership')
        value=native_allow(scope[0],self.template['interface_uuid'],row['target'],row['protocol'],int(row['origDport']),int(row['localPort']),desc[4:])
        # Reject unexpected semantics; false native constructor defaults and
        # empty arrays are the only accepted auxiliary identity fields.
        for field in IDENTITY_FIELDS:
            actual=row.get(field)
            if field=='scope':actual=scope
            expected=value.get(field)
            if actual==expected:continue
            if field not in value and actual in (None,False,'','false','[]'):continue
            if field=='seq' and actual in (3,'3'):continue
            raise ValueError('Unexpected policy identity field')
        if row.get('duration') not in (None,False,'') or row.get('idleTs') not in (None,False,''):raise ValueError('Timed policy unsupported')
        return value

    async def snapshot(self):
        self.guard()
        snap=remote.forward_snapshot(self.template)
        objects={}
        for row in snap['maps']:
            desc=row.get('description','')
            key='mapping:'+desc if isinstance(desc,str) and re.fullmatch('mcp:[a-f0-9]{32}',desc) else 'mapping:'+digest(row)
            if key in objects:raise ValueError('Ambiguous mapping identity')
            objects[key]={'kind':'mapping','value':copy.deepcopy(row),'enabled':row.get('enabled') is True}
        self.policies=read_projection(remote.run)
        for row in self.policies:
            pid=row['pid']
            try:value=self.policy_value(row);key='policy:'+value['description']
            except (ValueError,KeyError,TypeError):
                value={'policy_fingerprint':row['full_fingerprint']};key='policy:'+pid
            if key in objects:raise ValueError('Ambiguous policy ownership')
            objects[key]={'kind':'allow_policy','value':value,'enabled':row.get('disabled') not in ('1',1,True),
                          'instance':{'id':pid,'birth':str(row.get('timestamp') or '')}}
        return {'objects':objects,'environment':{'forward_environment':snap['environment_fingerprint'],
                'revision':self.revision,'device':self.template['device'],'destination':self.template['destination_ip'],
                'interface_uuid':self.template['interface_uuid']}}

    async def verify(self,state,removed=()):
        if await self.snapshot()!=state:return False
        for key,row in state['objects'].items():
            if key.startswith('mapping:mcp:'):
                try:spec=self.mapping_spec(row['value'])
                except ValueError:continue  # unrelated mappings are preserved, not asserted
                evidence=remote.forward_kernel_evidence(spec)
                if not evidence['nat_rule_observed'] or not evidence['vpn_ingress_link_observed'] or not hairpin_evidence(remote.run,row['value']):return False
            if key.startswith('policy:mcp:'):
                value=row['value'];pid=row['instance']['id'];sets={}
                if row['enabled']:
                    for name in ('c_bd_'+pid+'_set','c_bd_'+pid+'_set6','c_bp_'+pid+'_local_port'):
                        sets[name]=remote.run(['sudo','-n','ipset','save',name])
                rules=[remote.run(['sudo','-n',exe,'-t','filter','-S']).splitlines() for exe in ('iptables','ip6tables')]
                if not verify_policy(value,pid,*rules,sets,row['enabled']):return False
        if not isinstance(removed,(list,tuple)) or len(removed)>64:raise ValueError('Removed proof bound')
        for item in removed:
            if set(item)!={'key','before'}:raise ValueError('Removed proof identity')
            row=item['before']
            if row['kind']=='mapping':
                if item['key'] in state['objects']:raise ValueError('Removed mapping still present')
                spec=self.mapping_spec(row['value'])
                # A later verified replacement may intentionally recreate the
                # same kernel tuple under a new stored ownership identity. The
                # previous dispatch must already have proved absence; now bind
                # the tuple to exactly one strictly typed current replacement.
                replacements=[]
                for current_key,current in state['objects'].items():
                    if not current_key.startswith('mapping:mcp:') or current['kind']!='mapping':continue
                    if {k:v for k,v in current['value'].items() if k not in ('description','_type')}=={k:v for k,v in row['value'].items() if k not in ('description','_type')}:
                        self.mapping_spec(current['value']);replacements.append(current)
                if len(replacements)>1:return False
                if not replacements and (remote.forward_kernel_evidence(spec)['nat_rule_observed'] or hairpin_evidence(remote.run,row['value'])):return False
            else:
                value=self.policy_value(row['value']);pid=row['instance']['id']
                if any(r.get('instance',{}).get('id')==pid for r in state['objects'].values()):return False
                rules=[remote.run(['sudo','-n',exe,'-t','filter','-S']).splitlines() for exe in ('iptables','ip6tables')]
                if not verify_policy(value,pid,*rules,{},False):return False
        return True

    async def mutate(self,step,expected,expires_at):
        self.guard()
        before=await self.snapshot()
        if digest(before)!=expected:raise ValueError('State drift')
        projected=transition(before,step)
        value=(step['after'] or step['before'])['value'];kind=(step['after'] or step['before'])['kind'];op=step['operation']
        def deadline():
            if not time.time()<min(expires_at,self.template['maintenance_until'])<=time.time()+600:raise ValueError('Maintenance/approval expired')
        allocated_pid=None
        if kind=='mapping':
            spec=self.mapping_spec(value)
            snapshot=remote.forward_snapshot(spec)
            if op in ('create','restore'):
                if snapshot['collisions'] or snapshot['owned']:raise ValueError('Mapping conflict')
            elif op=='remove':
                require_mapping_removal(value,snapshot['maps'])
                if not hairpin_evidence(remote.run,value):raise ValueError('Native hairpin rule missing before removal')
                if snapshot['collisions']!=[value]:raise ValueError('Mapping identity drift')
            else:raise ValueError('Mapping operation')
            deadline()
            remote.management_request('set','policy','0.0.0.0',{'portforward':{**value,'state':op!='remove'}})
        else:
            if not step['key'].startswith('policy:mcp:') or self.policy_value(value)!=value:raise ValueError('Unsupported policy')
            if op in ('create_disabled','restore'):
                if step['after']['enabled']:raise ValueError('Create disabled only')
                reject_duplicate(self.policies,value)
                known={p['pid'] for p in self.policies}
                deadline()
                pid=remote.management_request('cmd','policy:create','0.0.0.0',{**value,'disabled':'1'},True)
                if pid in known:raise ValueError('Native create returned existing policy')
                allocated_pid=pid
            else:
                current=before['objects'][step['key']]
                pid=current['instance']['id']
                if op not in ('enable','disable','remove'):raise ValueError('Policy operation')
                deadline()
                remote.management_request('cmd','policy:'+{'enable':'enable','disable':'disable','remove':'delete'}[op],
                                          '0.0.0.0',{'policyID':pid})
        # Observe asynchronous completion, never issue an automatic retry or undo.
        end=min(time.monotonic()+4,time.monotonic()+max(0,expires_at-time.time()))
        while time.monotonic()<end:
            await __import__('asyncio').sleep(.2)
            after=await self.snapshot()
            try:bind_created_instance(before,projected,after,step)
            except ValueError:continue
            if allocated_pid is not None and after['objects'].get(step['key'],{}).get('instance',{}).get('id')!=allocated_pid:continue
            if op=='remove':
                if kind=='mapping':
                    if remote.forward_kernel_evidence(spec)['nat_rule_observed'] or hairpin_evidence(remote.run,value):continue
                else:
                    remaining=[remote.run(['sudo','-n',exe,'-t','filter','-S']).splitlines() for exe in ('iptables','ip6tables')]
                    if not verify_policy(value,pid,*remaining,{},False):continue
            if await self.verify(after):return {'verified':True}
        return {'verified':False}
