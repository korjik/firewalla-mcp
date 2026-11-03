"""Internal SSH transport for the separately pinned lifecycle helper."""
import asyncio
import json
from .transport import ssh_argv,bounded_read
from .forward_errors import ERROR_CODES


def decode_response(raw, code):
    # Exit status takes precedence: failed SSH/gates may return no JSON at all.
    if code:
        raise ValueError('Lifecycle SSH/helper process failed; no retry')
    try:
        data=json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError('Lifecycle response protocol failed; no retry') from None
    if not isinstance(data,dict):
        raise ValueError('Lifecycle response protocol failed; no retry')
    if data.get('status') in ('unsupported','uncertain'):
        diagnostic=data.get('error_code')
        if not isinstance(diagnostic,str) or diagnostic not in ERROR_CODES:
            diagnostic='unspecified'
        status=data['status']
        raise ValueError(f'Lifecycle helper reported {status} ({diagnostic}); no retry')
    if data.get('status')!='ok' or not isinstance(data.get('data'),dict):
        raise ValueError('Lifecycle response protocol failed; no retry')
    return data['data']

class LifecycleSSH:
    def __init__(self,site,template):self.site=site;self.template=template;self.policies=[];self.receipts=[];self.adoptions=None
    async def request(self,operation,arguments):
        if self.receipts:arguments={**arguments,'receipts':self.receipts}
        if self.adoptions:arguments={**arguments,'adoptions':self.adoptions}
        raw=json.dumps({'operation':operation,'revision':self.site.management_revision,'template':self.template,'arguments':arguments}).encode()
        if len(raw)>524288:raise ValueError('Lifecycle request bound')
        proc=await asyncio.create_subprocess_exec(*ssh_argv(self.site,'firewalla-forward-lifecycle-v1'),
              stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        try:
            async with asyncio.timeout(115):
                proc.stdin.write(raw);await proc.stdin.drain();proc.stdin.close()
                raw=await bounded_read(proc.stdout,524288);code=await proc.wait()
                return decode_response(raw,code)
        finally:
            if proc.returncode is None:proc.kill();await proc.wait()
    async def snapshot(self):
        data=await self.request('snapshot',{});self.policies=data['policies'];return data['state']
    async def mutate(self,step,expected,expires_at):
        result=await self.request('mutate',{'step':step,'expected':expected,'expires_at':expires_at})
        if result.get('allocated_instance'):
            if not self.adoptions or result['allocated_instance'].get('key')!=step['key']:raise ValueError('Unexpected allocated identity')
            self.adoptions.setdefault('policy_instances',[]).append(result['allocated_instance'])
        return result
    async def verify(self,state,removed=()):return (await self.request('verify',{'state':state,'removed':list(removed)}))['verified'] is True
    def mapping_spec(self,value):
        if self.adoptions:
            from .forward_app_adapter import AppForwardAdapter
            return AppForwardAdapter(self.site.management_revision,self.template,self.receipts,self.adoptions).mapping_spec(value)
        if self.receipts:
            from .forward_provenance import ReceiptNativeAdapter
            return ReceiptNativeAdapter(self.site.management_revision,self.template,self.receipts).mapping_spec(value)
        from .forward_native import NativeForwardAdapter
        return NativeForwardAdapter.mapping_spec(self,value)
    def policy_value(self,value):
        if self.adoptions:
            from .forward_app_adapter import AppForwardAdapter
            return AppForwardAdapter(self.site.management_revision,self.template,self.receipts,self.adoptions).policy_value(value)
        from .forward_native import NativeForwardAdapter
        return NativeForwardAdapter.policy_value(self,value)
