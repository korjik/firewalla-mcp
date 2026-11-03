"""Guarded native IPv6 policy-only adapter; no NAT calls or implicit adoption."""
import asyncio
import copy
import hashlib
import ipaddress
import json
import re
import time

from . import remote
from .forward_native import BLOCK_HASH
from .forward_policy import IDENTITY_FIELDS, read_projection, reject_duplicate
from .forward_dependencies import array
from .forward_transaction import transition, bind_created_instance
from .ipv6_policy import native_allow, validate, verify_policy
from .writes import digest


def template_checked(template):
    if not isinstance(template,dict) or set(template)!={'kind','device','interface_uuid','maintenance_until'} or template['kind']!='ipv6_device_policy':
        raise ValueError('IPv6 policy template')
    native_allow(template['device'],template['interface_uuid'],'::/0','tcp',1,'0'*32)
    if template['device']!=template['device'].upper() or type(template['maintenance_until']) is not int:
        raise ValueError('Canonical template')
    return copy.deepcopy(template)


def instance_checked(instance):
    if not isinstance(instance,dict) or set(instance)!={'id','birth'} or not isinstance(instance['id'],str) or not re.fullmatch('[1-9][0-9]{0,4}',instance['id']) or int(instance['id'])>65535:
        raise ValueError('Native policy identity')
    if not isinstance(instance['birth'],str) or not re.fullmatch(r'[0-9]{1,16}(?:\.[0-9]{1,9})?',instance['birth']) or float(instance['birth'])<=0:
        raise ValueError('Native policy birth')
    return copy.deepcopy(instance)


def normalized(row):
    if row.get('identity_complete') is not True or row.get('legacy_identity') or row.get('unknown_fields'):
        raise ValueError('Incomplete policy identity')
    if any(row.get(k) not in (None,'') for k in ('purpose','updatedTime','duration','idleTs')):
        raise ValueError('Unreviewed policy metadata')
    scope=array(row.get('scope'));description=row.get('description','')
    if len(scope)!=1 or not isinstance(description,str) or not re.fullmatch('mcp:[a-f0-9]{32}',description):
        raise ValueError('IPv6 policy shape')
    port=row.get('localPort')
    if not isinstance(port,str) or not re.fullmatch('[1-9][0-9]{0,4}',port):raise ValueError('Policy port')
    value=native_allow(scope[0],row.get('owanUUID'),row.get('target'),row.get('protocol'),int(port),description[4:])
    booleans={'upnp','dnsmasq_only','trust','ipOnly','flowIsolation','useBf'}
    arrays={'tag','targets','guids','affectedPids'}
    for field in IDENTITY_FIELDS:
        actual=scope if field=='scope' else row.get(field)
        if field in value:
            if actual!=value[field]:raise ValueError('Policy selector drift')
        elif field=='seq' and actual in (3,'3'):continue
        elif field in booleans:
            if actual is not None and actual is not False and actual not in ('','false'):raise ValueError('Policy boolean selector')
        elif field in arrays:
            if array(actual):raise ValueError('Policy array selector')
        elif actual not in (None,''):raise ValueError('Unexpected policy selector')
    disabled=row.get('disabled')
    if not (disabled is None or type(disabled) is bool or type(disabled) is int and disabled in (0,1) or type(disabled) is str and disabled in ('','0','1')):
        raise ValueError('Unknown disabled state')
    instance_checked({'id':row['pid'],'birth':str(row.get('timestamp',''))})
    return value


class IPv6Adapter:
    def __init__(self,revision,template,owned=()):
        self.revision=revision;self.template=template_checked(template);self.policies=[];self.owned=[]
        if not isinstance(owned,(list,tuple)) or len(owned)>256:raise ValueError('Ownership bound')
        for record in owned:self.add_owned(record)

    def add_owned(self,record):
        if set(record)!={'key','value','instance'}:raise ValueError('Ownership receipt shape')
        value=validate(record['value']);instance=instance_checked(record['instance'])
        if record['key']!='policy:ipv6:'+value['description'][4:]:raise ValueError('Ownership key')
        if value['scope']!=[self.template['device']] or value['owanUUID']!=self.template['interface_uuid']:
            raise ValueError('Ownership target')
        if any(r['instance']==instance and r!=record or r['key']==record['key'] and r['value']!=value for r in self.owned):raise ValueError('Ownership collision')
        if record not in self.owned:self.owned.append(copy.deepcopy(record))

    def guard(self):
        remote.management_guard(self.revision,'managed_rule')
        remote.policy_source_guard(self.revision)
        if hashlib.sha256(remote.contract_file('/home/pi/firewalla','control/Block.js')).hexdigest()!=BLOCK_HASH:
            raise ValueError('IPv6 enforcement source drift')

    def environment(self):
        device=self.template['device'];key='host:mac:'+device
        if remote.run(['redis-cli','--raw','EXISTS',key]).strip()!='1':raise ValueError('Known device required')
        raw=remote.run(['redis-cli','--raw','HGET',key,'ipv6Addr']).strip()
        if len(raw)>8192:raise ValueError('Device address bound')
        addresses=json.loads(raw) if raw else []
        if not isinstance(addresses,list) or len(addresses)>64:raise ValueError('Device IPv6 schema')
        for address in addresses:
            if not isinstance(address,str) or '%' in address:raise ValueError('Unscoped IPv6 address')
        addresses=sorted({str(ipaddress.IPv6Address(a)) for a in addresses})
        networks=remote.forward_networks()
        selected=[r for r in networks if r['uuid']==self.template['interface_uuid'] and r['type']=='wan']
        if len(selected)!=1 or sum(r['uuid'][:13]==self.template['interface_uuid'][:13] for r in networks)!=1:
            raise ValueError('Unambiguous current WAN required')
        return {'revision':self.revision,'device':device,'ipv6_addresses':addresses,
                'wan':selected[0],'network_bindings':[{'uuid':r['uuid'],'interface':r['interface'],'type':r['type']} for r in networks]}

    async def snapshot(self):
        self.guard();environment=self.environment();self.policies=read_projection(remote.run);objects={}
        for row in self.policies:
            instance={'id':row['pid'],'birth':str(row.get('timestamp') or '')}
            matches=[r for r in self.owned if r['instance']==instance]
            if len(matches)>1:raise ValueError('Ambiguous policy ownership')
            if matches:
                record=matches[0];value=normalized(row)
                if value!=record['value']:raise ValueError('Owned policy changed')
                key=record['key']
            else:key='policy:'+row['pid'];value={'policy_fingerprint':row['full_fingerprint']}
            if key in objects:raise ValueError('Duplicate logical policy')
            objects[key]={'kind':'allow_policy','value':value,'enabled':row.get('disabled') not in ('1',1,True),'instance':instance}
        return {'objects':objects,'environment':environment}

    def proof(self,row,enabled=None):
        value=validate(row['value']);pid=instance_checked(row['instance'])['id']
        enabled=row['enabled'] if enabled is None else enabled;sets={}
        if enabled:
            for name in ('c_bd_'+pid+'_set','c_bd_'+pid+'_set6','c_bp_'+pid+'_local_port'):
                sets[name]=remote.run(['sudo','-n','ipset','save',name])
        rules=[remote.run(['sudo','-n',exe,'-t','filter','-S']).splitlines() for exe in ('iptables','ip6tables')]
        return verify_policy(value,pid,*rules,sets,enabled)

    async def verify(self,state,removed=()):
        if await self.snapshot()!=state:return False
        for key,row in state['objects'].items():
            if key.startswith('policy:ipv6:') and not self.proof(row):return False
        if not isinstance(removed,(list,tuple)) or len(removed)>64:raise ValueError('Absence proof bound')
        for item in removed:
            if set(item)!={'key','before'} or not item['key'].startswith('policy:ipv6:'):raise ValueError('IPv6 removal proof')
            before=item['before'];pid=instance_checked(before['instance'])['id']
            if any(r.get('instance',{}).get('id')==pid for r in state['objects'].values()):return False
            if not self.proof(before,False):return False
        return True

    def references(self,pid):
        for row in self.policies:
            if row.get('parentRgId') or row.get('targetRgId'):raise ValueError('Unresolved policy group reference')
            if pid in array(row.get('affectedPids')):raise ValueError('Referenced policy')

    async def mutate(self,step,expected,expires_at):
        self.guard();before=await self.snapshot()
        if digest(before)!=expected:raise ValueError('State drift')
        projected=transition(before,step);row=step['after'] or step['before'];value=validate(row['value'])
        if row['kind']!='allow_policy' or step['key']!='policy:ipv6:'+value['description'][4:]:raise ValueError('IPv6 policy only')
        if value['scope']!=[self.template['device']] or value['owanUUID']!=self.template['interface_uuid']:raise ValueError('Target drift')
        op=step['operation'];allocated=None
        if op in ('create_disabled','restore'):
            if step['after']['enabled']:raise ValueError('Create disabled only')
            reject_duplicate(self.policies,value);known={p['pid'] for p in self.policies}
            command='policy:create';payload={**value,'disabled':'1'}
        else:
            if op not in ('enable','disable','remove'):raise ValueError('Policy operation')
            current=before['objects'][step['key']];pid=instance_checked(current['instance'])['id'];self.references(pid)
            if not any(r['key']==step['key'] and r['instance']==current['instance'] and r['value']==value for r in self.owned):raise ValueError('Unowned policy')
            command='policy:'+{'enable':'enable','disable':'disable','remove':'delete'}[op];payload={'policyID':pid}
        if not time.time()<min(expires_at,self.template['maintenance_until'])<=time.time()+600:raise ValueError('Maintenance expired')
        result=remote.management_request('cmd',command,'0.0.0.0',payload,command=='policy:create')
        if command=='policy:create':
            if result in known:raise ValueError('Existing identity returned')
            allocated=result
        end=min(time.monotonic()+4,time.monotonic()+max(0,expires_at-time.time()))
        while time.monotonic()<end:
            await asyncio.sleep(.2)
            if allocated is not None:
                matches=[p for p in read_projection(remote.run) if p['pid']==allocated]
                if len(matches)==1 and normalized(matches[0])==value:
                    self.add_owned({'key':step['key'],'value':value,'instance':{'id':allocated,'birth':str(matches[0]['timestamp'])}})
            observed=await self.snapshot()
            try:bind_created_instance(before,projected,observed,step)
            except ValueError:continue
            if allocated is not None and observed['objects'].get(step['key'],{}).get('instance',{}).get('id')!=allocated:continue
            removed=[{'key':step['key'],'before':step['before']}] if op=='remove' else []
            if await self.verify(observed,removed):
                response={'verified':True}
                if allocated is not None:response['allocated_instance']={'key':step['key'],'value':value,'instance':observed['objects'][step['key']]['instance']}
                return response
        return {'verified':False}
