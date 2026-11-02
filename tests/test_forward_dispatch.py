import json
import pytest
from firewalla_mcp import forward_dispatch as dispatch
from firewalla_mcp.forward_policy import projection_script

@pytest.mark.parametrize('payload',[{},[],{'operation':'shell','revision':'x','template':{},'arguments':{}}])
async def test_invalid_dispatch_no_native_execution(payload):
    with pytest.raises((ValueError,KeyError)):await dispatch.handle(payload)

async def test_large_complete_inventory_within_bounded_protocol(monkeypatch):
    rows=[{'pid':str(i+1),'type':'dns','target':f'host{i}.example.org','scope':'["02:00:00:00:00:01"]',
           'action':'block','direction':'outbound','timestamp':'1700000000','identity_complete':True,'full_fingerprint':'a'*40} for i in range(398)]
    assert len(json.dumps(rows).encode())<131072
    class Adapter:
        def __init__(self,*args):self.policies=rows
        async def snapshot(self):
            return {'objects':{'policy:'+r['pid']:{'kind':'allow_policy','enabled':True,'value':{'policy_fingerprint':r['full_fingerprint']},
                    'instance':{'id':r['pid'],'birth':r['timestamp']}} for r in rows},'environment':{}}
    monkeypatch.setattr(dispatch,'NativeForwardAdapter',Adapter)
    data=await dispatch.handle({'operation':'snapshot','revision':'x','template':{},'arguments':{}})
    assert len(data['state']['objects'])==398 and len(data['policies'])==398
    assert len(json.dumps({'status':'ok','data':data}).encode())<524288
    assert len(json.dumps({'operation':'verify','revision':'x','template':{},'arguments':{'state':data['state']}}).encode())<524288

def test_projection_omits_missing_fields_and_observed_flow_values():
    script,fields=projection_script()
    assert 'if v then row[f]=v end' in script
    assert 'lastHitFlow' not in json.loads(fields)
    assert 'observational[f]' in script
