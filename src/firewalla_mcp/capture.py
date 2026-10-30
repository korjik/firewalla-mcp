"""Host-confirmed bounded capture jobs; SSH and transient packet bytes stay internal."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import time
from .capture_helper import validate
from .transport import ssh_argv
from .writes import digest,WriteManager
from .host_confirmation import claim,validate_ledger


def capture_command():
    source=Path(__file__).with_name('capture_helper.py').read_text()
    return shlex.join(['sudo','-n','timeout','--signal=TERM','--kill-after=3','22','python3','-I','-c',source])


class CaptureTransport:
    async def run(self,site,spec,ready,cancel):
        proc=None
        async def stop():
            await cancel.wait()
            if proc and proc.stdin and not proc.stdin.is_closing():
                proc.stdin.write(b'cancel\n')
                await proc.stdin.drain()
        stopper=None
        try:
            proc=await asyncio.create_subprocess_exec(*ssh_argv(site,capture_command()),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            proc.stdin.write(json.dumps(spec).encode()+b'\n');await proc.stdin.drain();stopper=asyncio.create_task(stop());size=0
            async with asyncio.timeout(spec['duration']+12):
                while True:
                    line=await proc.stdout.readline()
                    if not line:break
                    size+=len(line)
                    if size>65536:raise ValueError('metadata output bound')
                    event=json.loads(line)
                    if event.get('event')=='ready':
                        if not ready.done():ready.set_result({'status':'ready',**{k:event[k] for k in ('started_at','duration_limit','packet_limit')}})
                    elif event.get('event')=='completed':return event
                return {'status':'transport_failed','ready':False,'metadata':[],'meaning':'No completed capture evidence; do not interpret as zero traffic'}
        except (OSError,ValueError,asyncio.TimeoutError,asyncio.CancelledError):
            return {'status':'transport_timeout_or_cancelled','metadata':[],'meaning':'Capture result incomplete; no absence inference. Remote forced timeout bounds cleanup.'}
        finally:
            if stopper:stopper.cancel()
            if proc:
                if proc.stdin and not proc.stdin.is_closing():proc.stdin.close()
                if proc.returncode is None:
                    try:await asyncio.wait_for(proc.wait(),3)
                    except asyncio.TimeoutError:
                        proc.kill();await proc.wait()
            if not ready.done():ready.set_result({'status':'not_ready'})


class CaptureManager:
    def __init__(self,config,transport=None):self.config=config;self.transport=transport or CaptureTransport();self.plans={};self.jobs={}
    def enabled(self):
        if not self.config.capture_enabled:raise ValueError('Capture disabled; deployment opt-in required')
        validate_ledger(self.config)
        if not self.config.audit_file or not Path(self.config.audit_file).is_absolute():raise ValueError('Capture audit path required')
    def binding(self,box):return digest({'site':self.config.sites[box].model_dump(),'capture_enabled':self.config.capture_enabled,'ledger':self.config.approval_consumed_directory})
    def preview(self,box,spec):
        self.enabled();box=self.config.resolve(box)
        if box not in self.config.sites:raise ValueError('Unknown box')
        spec=validate(copy.deepcopy(spec));now=int(time.time())
        self.plans={k:v for k,v in self.plans.items() if v['expires_at']>now}
        self.jobs={k:v for k,v in self.jobs.items() if v['status'] in ('starting','ready') or v['expires_at']>now}
        if len(self.plans)>=16 or len(self.jobs)>=16:raise ValueError('Capture job capacity reached')
        plan={'plan_id':secrets.token_hex(16),'box':box,'spec':spec,'expires_at':now+120,'binding':self.binding(box),
              'privacy':'Observe only this interface/target/filter for the declared time/count. Headers expose network addresses/ports. Up to96packet bytes may enter router memory; no payload, raw PCAP, DNS names or credentials returned/stored.',
              'coordination':'After exact host confirmation call start_capture, wait for ready, then independently authorize/run an external probe. This tool sends no probe.',
              'confirmation':'Authenticated MCP host must obtain exact scope confirmation; server does not attest human consent.'}
        plan['digest']=digest(plan);self.plans[plan['plan_id']]=plan
        return copy.deepcopy(plan)
    async def start(self,plan_id):
        self.enabled()
        if plan_id in self.jobs:return self.status(plan_id)
        if plan_id not in self.plans:raise ValueError('Unknown capture plan')
        plan=self.plans[plan_id]
        if digest({k:v for k,v in plan.items() if k!='digest'})!=plan['digest'] or plan['binding']!=self.binding(plan['box']):raise ValueError('Capture scope/configuration changed')
        if time.time()>=plan['expires_at']:raise ValueError('Capture plan expired')
        active=[j for j in self.jobs.values() if j['status'] in ('starting','ready')]
        if len(active)>=2 or any(j['box']==plan['box'] for j in active):raise ValueError('Capture concurrency limit')
        claim(self.config,plan);WriteManager(self.config,None).audit(plan_id,'capture_host_requested',plan['box'])
        ready=asyncio.get_running_loop().create_future();cancel=asyncio.Event()
        job={'box':plan['box'],'status':'starting','expires_at':int(time.time())+600,'ready':ready,'cancel':cancel,'result':None};self.jobs[plan_id]=job
        async def execute():
            try:
                result=await self.transport.run(self.config.sites[plan['box']].model_copy(deep=True),copy.deepcopy(plan['spec']),ready,cancel)
                job['result']=result;job['status']='completed'
            except Exception:
                job['result']={'status':'capture_failed','metadata':[]};job['status']='completed'
            finally:
                if not ready.done():ready.set_result({'status':'not_ready'})
        job['task']=asyncio.create_task(execute())
        asyncio.get_running_loop().call_later(600,self.jobs.pop,plan_id,None)
        try:state=await asyncio.wait_for(asyncio.shield(ready),10)
        except asyncio.TimeoutError:state={'status':'starting'}
        if job['status']!='completed':job['status']=state['status'] if state['status']=='ready' else 'starting'
        return self.status(plan_id)
    def status(self,plan_id):
        if plan_id not in self.jobs:raise ValueError('Unknown capture job')
        j=self.jobs[plan_id]
        if time.time()>j['expires_at']:
            del self.jobs[plan_id];raise ValueError('Capture result expired')
        return {'plan_id':plan_id,'box':j['box'],'status':j['status'],
            'capture_status':j['result'].get('status') if j['result'] else j['status'],
            'ready':j['ready'].result() if j['ready'].done() else None,'result':copy.deepcopy(j['result']),
            'retention':'In memory only; expires within ten minutes, no PCAP file'}
    def cancel(self,plan_id):
        if plan_id not in self.jobs:raise ValueError('Unknown capture job')
        self.jobs[plan_id]['cancel'].set();return {'plan_id':plan_id,'status':'cancellation_requested','note':'Poll status; remote forced deadline remains a cleanup backstop'}
