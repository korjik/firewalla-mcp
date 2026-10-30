import io
import json
import os
import time
import zipfile
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp.models import Config, Site
from firewalla_mcp.server import build_server
from firewalla_mcp.vpn_writes import VPNWriteManager
from firewalla_mcp.vpn_import_mcp import ImportManager
from firewalla_mcp.vpn_import_dispatch import ImportDispatcher
from firewalla_mcp.vpn_import import digest, ImportBlocked
from test_vpn_import import profile, sandbox


@pytest.fixture
def config(tmp_path):
    approvals=tmp_path/'approvals'; approvals.mkdir(mode=0o700)
    return Config(sites={'router-a':Site(host='192.0.2.1', identity_file='/secrets/key',known_hosts_file='/secrets/known_hosts',
        vantage_group='a', vpn_import_sources=['source'], vpn_import_archives=['sample'])},aliases={'Router A':'router-a'},
        vpn_writes_enabled=True,approval_consumed_directory=str(approvals),write_confirmation_mode="host_confirmed",vpn_confirmation_mode="host_confirmed",vpn_target_policy="approval_bound",audit_file=str(tmp_path/'audit'))


class Observer:
    def __init__(self,ids,runner): self.ids=ids
    def collision_check(self,path): return {}
    def __call__(self,ids):
        return {i:dict(unreferenced=True,reference_enumeration_complete=True,
            runtime_observation='no_interface_inactive_unit_cache_not_true',administrative_intent='unknown') for i in ids}


@pytest.fixture
def dispatcher(sandbox,tmp_path,monkeypatch):
    monkeypatch.setattr("firewalla_mcp.vpn_import_dispatch.vpn_source_guard",lambda *args: None)
    root,_,target,values=sandbox
    registry=root/'.mcp-import-inputs'; registry.mkdir(mode=0o700)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:z.writestr('sample.ovpn',values['ovpn'])
    raw=buf.getvalue()
    manifest=dict(sha256=digest(raw),profiles=[dict(filename='sample.ovpn',display_name='Example VPN',endpoint=target['endpoint'],sha256=target['sha256'])])
    for suffix,content in [('zip',raw),('json',json.dumps(manifest).encode())]:
        file=registry/('sample.'+suffix);file.write_bytes(content);file.chmod(0o600)
    secure=tmp_path/'ssh';secure.mkdir(mode=0o700)
    policy=secure/'policy.json';policy.write_text(json.dumps(dict(revision='a'*40,target_policy='approval_bound',source_permission_modes=['owner_only','existing_0644'],sources={'source':False},archives=['sample'],destination_modes=['0600','0644'],provider_features=False)));policy.chmod(0o600)
    d=ImportDispatcher(root,policy,runner=lambda argv:'a'*40 if 'rev-parse' in argv else '',observer=Observer)
    return d,root,values


class LocalRPC:
    def __init__(self,dispatcher): self.dispatcher=dispatcher;self.calls=[]
    async def request(self,site,request):
        self.calls.append(request)
        return self.dispatcher.execute(request)




async def test_real_transaction_through_mcp(config,dispatcher):
    d,root,values=dispatcher;rpc=LocalRPC(d)
    server=build_server(config,AsyncMock(),vpn_write_catalog=True,import_transport=rpc)
    result=await server.call_tool('preview_vpn_import',dict(box_name='Router A',source_profile='source',archive_id='sample',maintenance_until=int(time.time())+300))
    plan=result[1] if isinstance(result,tuple) else result
    # FastMCP returns (content, structuredContent).
    assert plan['box']=='router-a' and plan['preview']['destination_mode']=='0644'
    assert 'synthetic-password' not in json.dumps(plan)
    assert digest(values['userpass']) not in json.dumps(plan)
    applied=await server.call_tool('apply_vpn_import',dict(plan_id=plan['plan_id']))
    data=applied[1]['data']; assert data['state']=='imported_unassigned_passive_checks'
    for pid in data['profiles']:
        assert (root/(pid+'.userpass')).read_bytes()==values['userpass']
        assert (root/(pid+'.userpass')).stat().st_mode&0o777==0o644
    verified=await server.call_tool('verify_vpn_import',dict(box_name='router-a',transaction=data['transaction']))
    assert verified[1]['data']['state']=='files_verified_passive_checks'
    count=len(rpc.calls)
    replay=await server.call_tool('apply_vpn_import',dict(plan_id=plan['plan_id']))
    assert replay[1]['replayed'] and len(rpc.calls)==count
    assert 'synthetic-password' not in json.dumps([applied[1],verified[1]])


async def test_catalog_isolation(config):
    server=build_server(config,AsyncMock(),vpn_write_catalog=True)
    names={v.name for v in await server.list_tools()}
    assert len(names)==43
    assert {'preview_vpn_import','apply_vpn_import','verify_vpn_import','apply_vpn_change','preview_vpn_lifecycle','preview_managed_vpn_switch','preview_vpn_change_rollback'}<=names
    assert not names & {'apply_change','preview_route_change','preview_firewall_rule','preview_managed_device_control','preview_port_forward'}
    readonly=build_server(config.model_copy(update={'vpn_writes_enabled':False}),AsyncMock(),readonly_catalog=True)
    assert len(await readonly.list_tools())==36
    with pytest.raises(ValueError): build_server(config,readonly_catalog=True)
    with pytest.raises(ValueError): build_server(config.model_copy(update={'writes_enabled':True}),vpn_write_catalog=True)


async def test_vpn_manager_rejects_non_vpn_and_wrong_revision(config):
    manager=VPNWriteManager(config,AsyncMock())
    with pytest.raises(ValueError,match='outside VPN'): await manager.preview('Router A',dict(kind='route'))
    with pytest.raises(ValueError,match='revision'): await manager.preview('Router A',dict(kind='managed_lifecycle',profile='example',vpn_type='openvpn',desired='connect'))
    manager.transport.run.assert_not_called()


async def test_approval_required_and_expired_window(config,dispatcher):
    d,_,_=dispatcher;rpc=LocalRPC(d); manager=ImportManager(config,rpc)
    with pytest.raises(ValueError,match='deadline'): await manager.preview_import('router-a','source','sample','0644',int(time.time())-1)
    plan=await manager.preview_import('router-a','source','sample','0600',int(time.time())+300)
    manager.plans[plan['plan_id']]['expires_at']=0
    with pytest.raises(ValueError,match='expired'): await manager.apply_import(plan['plan_id'])
    assert len(rpc.calls)==1


@pytest.mark.parametrize('field,value',[('source','../source'),('archive','../../etc/passwd'),('destination_mode','0666')])
def test_dispatch_rejects_unregistered(config,dispatcher,field,value):
    d,_,_=dispatcher
    request=dict(operation='preview',target_policy='approval_bound',source='source',archive='sample',destination_mode='0644',maintenance_until=int(time.time())+300)
    request[field]=value
    with pytest.raises(ImportBlocked):d.execute(request)


@pytest.mark.parametrize('change',['source','archive','policy','reference','password_appears'])
async def test_stale_after_preview(config,dispatcher,change):
    d,root,_=dispatcher;rpc=LocalRPC(d);manager=ImportManager(config,rpc)
    plan=await manager.preview_import('router-a','source','sample','0644',int(time.time())+300)
    if change=='source':(root/'source.userpass').write_text('changed\ncredential')
    if change=='archive':(root/'.mcp-import-inputs/sample.zip').write_bytes(b'bad')
    if change=='policy':d.policy_file.write_text(d.policy_file.read_text().replace('"0644"','"0640"'))
    if change=='reference':
        class Changed(Observer):
            def __call__(self,ids):return {i:dict(unreferenced=False) for i in ids}
        d.observer=Changed
    if change=='password_appears':
        # Existing source password is present in this fixture: mutate it to prove source binding.
        (root/'source.password').write_bytes(b'changed')
    with pytest.raises((ImportBlocked,ValueError)):await manager.apply_import(plan['plan_id'])
    assert manager.plans[plan['plan_id']]['status']=='uncertain'
    assert not any((root/(t['id']+'.ovpn')).exists() for t in plan['preview']['targets'])
    assert (await manager.apply_import(plan['plan_id']))['replayed']


async def test_transport_failure_never_retried(config,dispatcher):
    d,_,_=dispatcher;rpc=LocalRPC(d);manager=ImportManager(config,rpc)
    plan=await manager.preview_import('router-a','source','sample','0644',int(time.time())+300)
    rpc.request=AsyncMock(return_value={'status':'unavailable'})
    await manager.apply_import(plan['plan_id']);again=await manager.apply_import(plan['plan_id'])
    assert again['status']=='uncertain';rpc.request.assert_awaited_once()


def test_verify_detects_another_actor_change(dispatcher):
    d,root,_=dispatcher
    plan=d.execute(dict(operation='preview',target_policy='approval_bound',source='source',archive='sample',destination_mode='0644',maintenance_until=int(time.time())+300))['data']
    d.execute(dict(operation='apply',transaction=plan['transaction'],approval_digest=plan['approval_digest']))
    (root/(plan['targets'][0]['id']+'.settings')).write_text('{}')
    with pytest.raises(ImportBlocked,match='changed'):d.execute(dict(operation='verify',transaction=plan['transaction']))
    assert (root/(plan['targets'][0]['id']+'.ovpn')).exists()

async def test_real_vpn_stdio_catalog(config,tmp_path):
    import sys
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    path=tmp_path/'config.json';path.write_text(config.model_dump_json())
    params=StdioServerParameters(command=sys.executable,args=['-m','firewalla_mcp.server','--vpn-write-catalog'],env={'FIREWALLA_MCP_CONFIG':str(path)})
    async with stdio_client(params) as (read,write):
        async with ClientSession(read,write) as session:
            await session.initialize()
            tools={t.name:t for t in (await session.list_tools()).tools}
            assert len(tools)==43 and 'apply_change' not in tools
            assert tools['preview_vpn_import'].inputSchema['properties']['destination_mode']['enum']==['0600','0644']
            result=await session.call_tool('write_capabilities',{})
            assert result.structuredContent['catalog_mode']=='vpn_only'
            result=await session.call_tool('apply_vpn_import',{'plan_id':'missing'})
            assert result.isError


def test_rpc_command_never_contains_payload(config,monkeypatch):
    import asyncio
    from firewalla_mcp.vpn_import_rpc import ImportTransport,COMMAND
    class Writer:
        def write(self,data):self.data=data
        async def drain(self):pass
        def close(self):pass
    class Process:
        def __init__(self):
            self.stdin=Writer();self.stdout=asyncio.StreamReader()
            self.stdout.feed_data(b'{"status":"ok","data":{}}');self.stdout.feed_eof();self.returncode=0
        async def wait(self):return 0
    async def scenario():
        process=Process();create=AsyncMock(return_value=process)
        monkeypatch.setattr(asyncio,'create_subprocess_exec',create)
        request={'operation':'verify','transaction':'a'*32}
        result=await ImportTransport().request(config.sites['router-a'],request)
        assert result['status']=='ok'
        argv=create.call_args.args
        assert argv[-1]==COMMAND and 'StrictHostKeyChecking=yes' in argv
        assert 'a'*32 not in ' '.join(argv)
        assert json.loads(process.stdin.data)==request
    asyncio.run(scenario())


def test_registry_symlink_and_permissions(dispatcher):
    d,root,_=dispatcher
    path=root/'.mcp-import-inputs/sample.zip'
    path.chmod(0o644)
    with pytest.raises(ImportBlocked,match='Unsafe registry'):d.inputs('sample')
    path.chmod(0o600);data=path.read_bytes();path.unlink()
    other=root/'other';other.write_bytes(data);other.chmod(0o600);path.symlink_to(other)
    with pytest.raises(OSError):d.inputs('sample')


def test_vpn_http_protocol_schema_and_unapproved_rejection(config,tmp_path):
    from starlette.testclient import TestClient
    from firewalla_mcp.http import http_app
    token=tmp_path/'token';token.write_text('x'*48)
    app=http_app(build_server(config,AsyncMock(),vpn_write_catalog=True),str(token),['testserver'])
    with TestClient(app) as client:
        headers={'Authorization':'Bearer '+'x'*48,'Accept':'application/json, text/event-stream'}
        initialized=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'vpn-test','version':'1'}}})
        assert initialized.status_code==200
        headers['MCP-Protocol-Version']=initialized.json()['result']['protocolVersion']
        listed=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}).json()['result']['tools']
        assert len(listed)==43 and all(t.get('outputSchema',{}).get('type')=='object' for t in listed)
        for name in ('apply_vpn_import','apply_vpn_change','apply_change'):
            called=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':name,'arguments':{'plan_id':'missing'}}})
            assert called.json()['result']['isError']
