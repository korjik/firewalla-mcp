"""Pinned router helper protocol; stdin is bounded JSON, never shell text."""
import asyncio
import json
import sys
import time
from .forward_native import NativeForwardAdapter
from . import remote
from .forward_errors import failure_code

async def handle(request):
    if not isinstance(request,dict) or set(request)!={'operation','revision','template','arguments'}:raise ValueError('request shape')
    operation=request['operation'];args=request['arguments']
    if not isinstance(args,dict):raise ValueError('arguments')
    args=dict(args);receipts=args.pop('receipts',[]);adoptions=args.pop('adoptions',None)
    if isinstance(request['template'],dict) and request['template'].get('kind')=='ipv6_device_policy':
        if receipts or adoptions:raise ValueError('IPv6 policy cannot adopt forwarding objects')
        from .ipv6_adapter import IPv6Adapter
        adapter=IPv6Adapter(request['revision'],request['template'],args.pop('ipv6_owned',[]))
    elif adoptions:
        from .forward_app_adapter import AppForwardAdapter
        adapter=AppForwardAdapter(request['revision'],request['template'],receipts,adoptions)
    elif receipts:
        from .forward_provenance import ReceiptNativeAdapter
        adapter=ReceiptNativeAdapter(request['revision'],request['template'],receipts)
    else:adapter=NativeForwardAdapter(request['revision'],request['template'])
    if operation=='snapshot' and not args:return {'state':await adapter.snapshot(),'policies':adapter.policies}
    if operation=='verify' and set(args)=={'state','removed'}:return {'verified':await adapter.verify(args['state'],removed=args['removed'])}
    if operation=='mutate' and set(args)=={'step','expected','expires_at'}:
        return await adapter.mutate(args['step'],args['expected'],args['expires_at'])
    raise ValueError('operation outside lifecycle contract')

def main():
    request={}
    try:
        raw=sys.stdin.buffer.read(524289)
        if len(raw)>524288:raise ValueError('input bound')
        request=json.loads(raw)
        remote.COMMAND_DEADLINE=time.monotonic()+105
        data=asyncio.run(handle(request))
        output=json.dumps({'status':'ok','data':data},separators=(',',':'))
        if len(output.encode())>524288:raise ValueError('output bound')
    except Exception as error:
        output=json.dumps({'status':'uncertain' if isinstance(request,dict) and request.get('operation')=='mutate' else 'unsupported',
                           'error_code':failure_code(error),
                           'reason':'Lifecycle contract, permission, state or bounded operation failed; inspect before any retry.'})
    print(output)

if __name__=='__main__':main()
