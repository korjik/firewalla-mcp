"""Opt-in exact TCP diagnostic grants; trusted host confirmation, no router writes."""
import copy
import ipaddress
import secrets
import math
import re
from pathlib import Path
import time
from .forward_journal import ForwardJournal
from .writes import digest

JOURNAL_ID='d'*32
PRIVATE=tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
METADATA={'169.254.169.254','100.100.100.200','168.63.129.16'}

class ProbeGrants:
    def __init__(self,writes):
        self.writes=writes;self.config=writes.config;self.plans={}
        self.enabled()
    def enabled(self):
        self.writes.enabled()
        if not self.config.diagnostic_grants_enabled or not self.config.diagnostic_grants_directory:
            raise ValueError('Diagnostic grant management disabled')
        root=Path(self.config.diagnostic_grants_directory).resolve()
        if root in {Path(p).resolve() for p in (self.config.approval_consumed_directory,self.config.forwarding_recovery_directory) if p}:raise ValueError('Diagnostic grants require separate persistent storage')
        self.journal=ForwardJournal(self.config.diagnostic_grants_directory)
        self.journal.root.root()
    def binding(self,box):
        return digest({'box':self.writes.site_binding(box),'directory':self.config.diagnostic_grants_directory,
                       'enabled':self.config.diagnostic_grants_enabled,'deny':self.config.diagnostic_grants_deny_addresses})
    def target(self,box,address,ports):
        box=self.config.resolve(box)
        if box not in self.config.sites:raise ValueError('Unknown source box')
        if not isinstance(address,str) or '%' in address or '/' in address:raise ValueError('Literal IPv4 only; hostnames and networks unsupported')
        ip=ipaddress.IPv4Address(address)
        if str(ip)!=address:raise ValueError('Canonical IPv4 required')
        if address in METADATA or address in self.config.diagnostic_grants_deny_addresses or address in {s.host for s in self.config.sites.values()}:
            raise ValueError('Protected diagnostic destination')
        if not (ip.is_global or any(ip in n for n in PRIVATE)) or ip.is_multicast or ip.is_reserved:
            raise ValueError('Destination must be public unicast or RFC1918; special-use destinations denied')
        if not isinstance(ports,list) or not 1<=len(ports)<=8 or any(type(p) is not int or not 1<=p<=65535 for p in ports) or len(set(ports))!=len(ports):
            raise ValueError('One to eight distinct exact TCP ports required')
        return box,address,sorted(ports)
    def state(self,session):
        if not session.events:session.append({'plan':{'plan_id':JOURNAL_ID},'kind':'init'})
        if len(session.events)>1024:raise ValueError('Diagnostic journal capacity')
        state={}
        for event in session.events[1:]:
            d=event['data'];ident=d['grant_id']
            if not isinstance(ident,str) or not re.fullmatch('[a-f0-9]{32}',ident):raise ValueError('Durable grant ID')
            if set(d)!=({'kind','grant_id','grant'} if d['kind']=='grant' else {'kind','grant_id'}):raise ValueError('Durable grant event fields')
            if d['kind']=='grant':
                if ident in state:raise ValueError('Duplicate durable grant')
                g=d['grant']
                if set(g)!={'box','address','ports','protocol','expires_at','max_probes','binding'} or g['protocol']!='tcp' or type(g['max_probes']) is not int or g['max_probes']!=16:raise ValueError('Durable grant shape')
                if type(g['expires_at']) not in (int,float) or not math.isfinite(g['expires_at']) or not isinstance(g['binding'],str) or not re.fullmatch('[a-f0-9]{64}',g['binding']):raise ValueError('Durable grant expiry/binding')
                # Scope validation below is syntax-only for history: changing a
                # deny list must invalidate use, not prevent revocation/history.
                if not isinstance(g['box'],str) or str(ipaddress.IPv4Address(g['address']))!=g['address'] or not isinstance(g['ports'],list) or not 1<=len(g['ports'])<=8 or any(type(p) is not int or not 1<=p<=65535 for p in g['ports']) or len(set(g['ports']))!=len(g['ports']):raise ValueError('Durable grant scope')
                state[ident]={**g,'used':0,'revoked':False}
            elif d['kind']=='revoke':state[ident]['revoked']=True
            elif d['kind']=='probe':state[ident]['used']+=1
            else:raise ValueError('Unknown diagnostic event')
        return state
    def remember(self,box,operation,grant_id,grant,state):
        now=time.time();self.plans={k:v for k,v in self.plans.items() if v['expires_at']>now}
        if len(self.plans)>=64:raise ValueError('Diagnostic plan capacity')
        p={'plan_id':secrets.token_hex(16),'box':box,'operation':operation,'grant_id':grant_id,'grant':grant,
           'expected':digest(state),'binding':self.binding(box),'expires_at':now+120,
           'confirmation':'Trusted host must obtain explicit owner confirmation; backend does not attest human consent.'}
        p['digest']=digest(p);self.plans[p['plan_id']]=copy.deepcopy(p)
        return p
    def preview_grant(self,box,address,ports,ttl_seconds):
        self.enabled();box,address,ports=self.target(box,address,ports)
        if type(ttl_seconds) is not int or not 60<=ttl_seconds<=3600:raise ValueError('Grant lifetime must be 60–3600 seconds')
        with self.journal.locked(JOURNAL_ID) as session:
            state=self.state(session)
            if sum(not g['revoked'] and g['expires_at']>time.time() for g in state.values())>=64:raise ValueError('Active grant capacity')
            grant={'box':box,'address':address,'ports':ports,'protocol':'tcp','expires_at':time.time()+ttl_seconds,
                   'max_probes':16,'binding':self.binding(box)}
            return self.remember(box,'grant',secrets.token_hex(16),grant,state)
    def preview_revoke(self,grant_id):
        self.enabled()
        with self.journal.locked(JOURNAL_ID) as session:
            state=self.state(session)
            if grant_id not in state:raise ValueError('Unknown diagnostic grant')
            return self.remember(state[grant_id]['box'],'revoke',grant_id,None,state)
    def apply(self,plan_id):
        self.enabled()
        if plan_id not in self.plans:raise ValueError('Unknown diagnostic plan; preview again after restart')
        p=copy.deepcopy(self.plans[plan_id])
        if digest({k:v for k,v in p.items() if k!='digest'})!=p['digest'] or p['binding']!=self.binding(p['box']):raise ValueError('Diagnostic plan or configuration changed')
        if time.time()>=p['expires_at']:raise ValueError('Diagnostic plan expired')
        with self.journal.locked(JOURNAL_ID) as session:
            state=self.state(session)
            if digest(state)!=p['expected']:raise ValueError('Diagnostic grant state changed; preview again')
            if p['operation']=='grant':
                g=p['grant'];self.target(g['box'],g['address'],g['ports'])
                if time.time()>=g['expires_at']:raise ValueError('Grant expired')
            elif p['operation']!='revoke':raise ValueError('Unsupported diagnostic operation')
            self.writes.consume_approval(p);self.writes.audit(plan_id,'diagnostic_'+p['operation'],p['box'])
            if time.time()>=p['expires_at']:raise ValueError('Diagnostic plan expired before persistence')
            session.append({'kind':p['operation'],'grant_id':p['grant_id'],**({'grant':p['grant']} if p['operation']=='grant' else {})})
            return {'status':'applied','operation':p['operation'],'grant_id':p['grant_id'],
                    'scope':p['grant'],'note':'No probe performed. Existing probe_networks is unchanged; revocation removes only this additional grant.'}
    def inventory(self):
        self.enabled()
        with self.journal.locked(JOURNAL_ID) as session:
            return {'grants':[{'grant_id':k,**v,'active':not v['revoked'] and v['expires_at']>time.time() and v['used']<v['max_probes'] and v['box'] in self.config.sites and v['binding']==self.binding(v['box'])} for k,v in self.state(session).items()],
                    'legacy_networks_unchanged':True,'limits':'At most 16 TCP handshakes per grant; expiry/revocation prevents new attempts, not an already-dispatched handshake.'}
    async def probe(self,box,address,port):
        self.enabled();box,address,ports=self.target(box,address,[port])
        # Hold an interprocess lock until the bounded handshake completes. A
        # concurrent grant/revoke fails busy rather than racing a stale permit.
        with self.journal.locked(JOURNAL_ID) as session:
            state=self.state(session)
            matches=[(k,g) for k,g in state.items() if g['box']==box and g['address']==address and port in g['ports'] and not g['revoked']
                     and g['expires_at']>time.time() and g['used']<g['max_probes'] and g['binding']==self.binding(box)]
            if not matches:raise ValueError('No active exact diagnostic grant for source, address and TCP port')
            ident,grant=min(matches,key=lambda item:item[1]['expires_at'])
            self.writes.audit(ident,'diagnostic_probe_dispatched',box)
            session.append({'kind':'probe','grant_id':ident})
            # Failure/timeout consumes the attempt; never automatically refund.
            if time.time()>=grant['expires_at']:raise ValueError('Diagnostic grant expired before dispatch')
            return await self.writes.transport.run(self.config.sites[box].model_copy(deep=True),'tcp',{'address':address,'port':port},dispatch_deadline=grant['expires_at'])
