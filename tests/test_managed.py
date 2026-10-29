"""Contract fixtures derived from reviewed netbot/Monitorable/Policy contracts.
No production device records or profile contents are used.
"""
import copy
import json
from unittest.mock import AsyncMock
from pathlib import Path
import pytest
from firewalla_mcp import remote
from firewalla_mcp.models import Config,Site
from firewalla_mcp.writes import WriteManager

MAC='02:00:00:00:00:01'
FEATURE=dict(kind='managed_feature',device=MAC,feature='unbound',desired='enable')
VPN=dict(kind='managed_vpn',device=MAC,expected_profile='vpn-a',destination_profile='vpn-b')
RULE=dict(kind='managed_rule',device=MAC,rule_type='category',target='av')

@pytest.fixture
def appliance(monkeypatch):
    state={'feature':{'state':False},'vpn':{'state':True,'profileId':'vpn-a'},'rules':[],'requests':[]}
    monkeypatch.setattr(remote,'management_guard',lambda revision:None)
    def run(argv,*a,**k):
        if 'EXISTS' in argv:return '1\n'
        if 'HGET' in argv:return json.dumps(state['vpn'] if argv[-1]=='vpnClient' else state['feature'])
        raise AssertionError(argv)
    monkeypatch.setattr(remote,'run',run)
    monkeypatch.setattr(remote,'managed_rule_snapshot',lambda:copy.deepcopy(state['rules']))
    monkeypatch.setattr(remote,'managed_vpn_safety',lambda p:({'strictVPN':True,'routeDNS':True},p))
    def request(command,item,target,value,want_pid=False):
        state['requests'].append((command,item,target,copy.deepcopy(value)))
        if item=='policy':
            key=next(iter(value));state['vpn' if key=='vpnClient' else 'feature']=copy.deepcopy(value[key])
        elif item=='policy:create':
            state['rules'].append(['123',value['type'],value['target'],value['action'],value['direction'],json.dumps(value.get('scope',[])),value.get('disabled','0'),value.get('cronTime',False),False,str(value.get('duration','')),value.get('resolver',False),str(value.get('domainExactMatch','')).lower(),str(value.get('ipOnly','')).lower()])
            return '123'
        elif item=='policy:enable':
            assert value=={'policyID':'123'}
            state['rules'][0][6]='0'
        elif item=='policy:delete':
            assert value=={'policyID':'123'}
            state['rules']=[]
        else:raise AssertionError(item)
    monkeypatch.setattr(remote,'management_request',request)
    return state


def preview(spec):
    return remote.managed_write(dict(mode='preview',revision=remote.MANAGEMENT_REVISION,spec=spec))

def apply(spec,state,mode='apply',context=None):
    return remote.managed_write(dict(mode=mode,revision=remote.MANAGEMENT_REVISION,spec=spec,expected=state['fingerprint'],context=context))

@pytest.mark.parametrize('feature',['adblock','safeSearch','unbound','doh'])
@pytest.mark.parametrize('desired,expected',[('enable',True),('disable',None),('inherit',False)])
def test_feature_persistent_apply_and_exact_restore(appliance,feature,desired,expected):
    old=True if expected is not True else False
    appliance['feature']=old if feature=='adblock' else {'state':old}
    spec={**FEATURE,'feature':feature,'desired':desired}
    before=preview(spec);result=apply(spec,before)
    assert result['outcome']=='applied' and result['persistent_state_verified']
    assert result['enforcement']=='unverified_async'
    assert appliance['feature']==(expected if feature=='adblock' else {'state':expected})
    restored=apply(spec,result['state'],'rollback',result['context'])
    assert restored['outcome']=='rolled_back'
    assert appliance['feature']==before['field']
    assert appliance['requests'][0][:3]==('set','policy',MAC)


def test_vpn_switch_preserves_enabled_state_and_rollback(appliance):
    result=apply(VPN,preview(VPN))
    assert result['outcome']=='applied'
    assert appliance['vpn']=={'state':True,'profileId':'vpn-b'}
    assert result['effective_device_path']=='unverified'
    assert apply(VPN,result['state'],'rollback',result['context'])['outcome']=='rolled_back'
    assert appliance['vpn']['profileId']=='vpn-a'

@pytest.mark.parametrize('value',[{'state':False,'profileId':'vpn-a'},{'state':True,'profileId':'vpn-c'},{'state':True,'profileId':'vpn-a','password':'secret'}])
def test_vpn_rejects_unexpected_state(appliance,value):
    appliance['vpn']=value
    with pytest.raises(remote.Unsupported):preview(VPN)
    assert not appliance['requests']


def test_vpn_safety_mismatch(appliance,monkeypatch):
    monkeypatch.setattr(remote,'managed_vpn_safety',lambda p:({'strictVPN':p=='vpn-a'},p))
    with pytest.raises(remote.Unsupported):preview(VPN)
    assert not appliance['requests']


def test_vpn_safety_changed_since_preview(appliance,monkeypatch):
    before=preview(VPN)
    monkeypatch.setattr(remote,'managed_vpn_safety',lambda p:({'strictVPN':True,'routeDNS':True},p+'changed'))
    assert apply(VPN,before)['outcome']=='stale'
    assert not appliance['requests']

@pytest.mark.parametrize('rule_type,target',[('internet','internet'),('category','games'),('category','av'),('ip','192.0.2.2'),('dns','example.org')])
def test_managed_rules_create_and_delete(appliance,rule_type,target):
    spec={**RULE,'rule_type':rule_type,'target':target}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    assert appliance['requests'][0][1]=='policy:create'
    assert result['context']['pid']=='123'
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'
    assert appliance['requests'][-1][1]=='policy:delete'


def test_dynamic_app_target(appliance,monkeypatch):
    monkeypatch.setattr(remote,'app_catalog',lambda args:{'apps':[{'id':'sample','ordinary_block_target':'TLX-fw-sample'}],'truncated':False})
    spec={**RULE,'rule_type':'app','target':'sample'}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    assert appliance['requests'][0][3]['target']=='TLX-fw-sample'


def test_unsupported_app(appliance,monkeypatch):
    monkeypatch.setattr(remote,'app_catalog',lambda args:{'apps':[],'truncated':False})
    with pytest.raises(remote.Unsupported):preview({**RULE,'rule_type':'app','target':'unknown'})
    assert not appliance['requests']


def test_duplicate_rule_rejected(appliance):
    appliance['rules']=[['3','category','av','block','outbound','[]','1',False,False]]
    state=preview(RULE)
    assert state['present']
    assert apply(RULE,state)['outcome']=='stale'
    assert not appliance['requests']


def test_rule_stale_rollback(appliance):
    result=apply(RULE,preview(RULE))
    appliance['rules'][0][6]='1'
    assert apply(RULE,result['state'],'rollback',result['context'])['outcome']=='stale'
    assert len(appliance['requests'])==2


def test_uncertain_not_success(appliance,monkeypatch):
    before=preview(FEATURE)
    def fail(*args,**kwargs):raise TimeoutError('secret')
    monkeypatch.setattr(remote,'management_request',fail)
    result=apply(FEATURE,before)
    assert result['outcome']=='uncertain' and 'secret' not in json.dumps(result)

@pytest.mark.parametrize('spec',[{**FEATURE,'device':'02:00:00:00:00:01;id'},{**FEATURE,'feature':'ssh'},{**FEATURE,'desired':'true'},{**RULE,'target':'video'},{**RULE,'rule_type':'dns','target':'x;id'},{**VPN,'destination_profile':'../key'},{**FEATURE,'extra':'ignored'}])
def test_invalid_managed_arguments(spec,appliance):
    with pytest.raises(ValueError):preview(spec)
    assert not appliance['requests']


def test_guard_rejects_version_without_api(monkeypatch):
    calls=[]
    monkeypatch.setattr(remote,'management_request',lambda *a,**k:calls.append(a))
    monkeypatch.setattr(remote,'run',lambda *a,**k:'other-revision')
    with pytest.raises(remote.Unsupported):remote.management_guard(remote.MANAGEMENT_REVISION)
    assert not calls


def test_guard_rejects_dirty_tree(monkeypatch):
    monkeypatch.setattr(remote,'run',lambda a:remote.MANAGEMENT_REVISION if 'rev-parse' in a else ' M controllers/netbot.js')
    monkeypatch.setattr(remote,'management_request',lambda *a,**k:pytest.fail('must not probe API'))
    with pytest.raises(remote.Unsupported):remote.management_guard(remote.MANAGEMENT_REVISION)


def test_http_set_never_reads_response_policy(monkeypatch):
    import http.client
    class Response:
        status=200
        def read(self,*a):pytest.fail('policy response must not be read')
    class Connection:
        def __init__(self,*a,**k):assert a==('127.0.0.1',8834)
        def request(self,method,path,body,headers):
            assert method=='POST' and 'command=set' in path and 'target=02%3A' in path
            assert json.loads(body)=={'unbound':{'state':True}}
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(http.client,'HTTPConnection',Connection)
    remote.management_request('set','policy',MAC,{'unbound':{'state':True}})


@pytest.mark.parametrize('code',[301,302,404,500])
def test_management_no_redirect_or_error_body(monkeypatch,code):
    import http.client
    class Response:
        status=code
        def read(self,*a):pytest.fail('error body must not be read')
    class Connection:
        def __init__(self,*a,**k):pass
        def request(self,*a,**k):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(http.client,'HTTPConnection',Connection)
    with pytest.raises(remote.Unsupported):remote.management_request('set','policy',MAC,{})


async def test_manager_approval_and_rollback_binding(tmp_path):
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',management_revision=remote.MANAGEMENT_REVISION,managed_devices=[MAC])
    config=Config(sites={'router-a':site},writes_enabled=True,approval_directory=str(tmp_path),audit_file=str(tmp_path/'audit'))
    transport=AsyncMock();transport.run.return_value={'status':'ok','data':{'fingerprint':'a'*64,'present':False,'field':{'state':False}}}
    manager=WriteManager(config,transport)
    plan=await manager.preview('router-a',dict(FEATURE))
    assert plan['scope']=='persistent_managed' and plan['diff']['before']=={'state':False}
    with pytest.raises(ValueError,match='approval'):await manager.apply(plan['plan_id'])
    Path(plan['approval_file']).write_text(json.dumps(plan['approval_document']))
    transport.run.return_value={'status':'ok','data':{'outcome':'applied','state':{'fingerprint':'b'*64,'present':True},'context':{'before':{'state':False}}}}
    await manager.apply(plan['plan_id'])
    assert transport.run.call_args.args[1]=='managed_write'
    transport.run.return_value={'status':'ok','data':{'fingerprint':'b'*64,'present':True,'field':{'state':True}}}
    rollback=await manager.rollback_preview(plan['plan_id'])
    assert rollback['context']=={'before':{'state':False}}
    assert rollback['digest']!=plan['digest']


async def test_managed_gate_requires_revision_and_device(tmp_path):
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a')
    config=Config(sites={'router-a':site},writes_enabled=True,approval_directory=str(tmp_path),audit_file=str(tmp_path/'audit'))
    transport=AsyncMock();manager=WriteManager(config,transport)
    with pytest.raises(ValueError,match='revision'):await manager.preview('router-a',dict(FEATURE))
    site.management_revision=remote.MANAGEMENT_REVISION
    with pytest.raises(ValueError,match='allowlist'):await manager.preview('router-a',dict(FEATURE))
    transport.run.assert_not_called()

@pytest.mark.parametrize('payload',[
    {'code':200,'data':{'pid':'123','config':'DO-NOT-RETURN'}},
    {'code':200,'data':{'pid':123,'password':'DO-NOT-RETURN'}}])
def test_create_response_projects_id_only(monkeypatch,payload):
    import http.client
    class Response:
        status=200
        def read(self,n):return json.dumps(payload).encode()
    class Connection:
        def __init__(self,*a,**k):pass
        def request(self,*a,**k):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(http.client,'HTTPConnection',Connection)
    assert remote.management_request('cmd','policy:create','0.0.0.0',{},True)=='123'


def test_profile_metadata_never_opens_config(tmp_path,monkeypatch):
    import os
    settings=tmp_path/'settings'
    settings.write_text(json.dumps({'strictVPN':True,'routeDNS':True,'overrideDefaultRoute':True,'c2sSNATDisabled':False,'unrecognized_secret':'DO-NOT-RETURN'}))
    monkeypatch.setattr(remote.os.path,'isfile',lambda p:p.endswith('/ovpn_profile/vpn-a.ovpn'))
    original_open=os.open
    paths=[]
    def mapped_open(path,flags):
        paths.append(path)
        assert path=='/home/pi/.firewalla/run/ovpn_profile/vpn-a.settings'
        assert flags & os.O_NOFOLLOW
        return original_open(settings,flags)
    monkeypatch.setattr(remote.os,'open',mapped_open)
    projected,fingerprint=remote.managed_vpn_safety('vpn-a')
    assert projected=={'strictVPN':True,'routeDNS':True,'overrideDefaultRoute':True,'c2sSNATDisabled':False}
    assert len(fingerprint)==64 and 'DO-NOT-RETURN' not in json.dumps((projected,fingerprint))
    assert len(paths)==1


def test_rule_projection_hashes_other_fields_on_router(monkeypatch):
    calls=[]
    def run(argv):
        calls.append(argv)
        if 'ZRANGE' in argv:return '123\n'
        assert 'EVAL' in argv
        script=argv[3]
        assert 'redis.sha1hex' in script and "redis.call('HGETALL',k)" in script
        return json.dumps([['category','av','block','outbound','[]','0',False,False,False,False,False,False,'opaquehash']])
    monkeypatch.setattr(remote,'run',run)
    rows=remote.managed_rule_snapshot()
    assert rows[0][-1]=='opaquehash' and rows[0][0]=='123'
    assert len(calls)==2
