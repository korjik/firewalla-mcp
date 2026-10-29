import json
import pytest
from firewalla_mcp import remote
from firewalla_mcp.analysis import summarize_page

@pytest.mark.parametrize('feature',['adblock','safeSearch','unbound'])
@pytest.mark.parametrize('value,meaning',[(True,'enable'),(False,'inherit'),(None,'explicit_disable')])
def test_tristate(feature,value,meaning):
    raw=json.dumps(value if feature=='adblock' else {'state':value,'secret':'hidden'})
    result=remote.policy_feature(raw,feature)
    assert result['meaning']==meaning and result['raw_state'] is value
    assert 'hidden' not in json.dumps(result)

def test_global_false_distinct():
    assert remote.policy_feature('false','adblock',True)['meaning']=='disable'
    assert remote.policy_feature('','adblock')['raw_state']=='missing'

def test_app_acl_not_usage(monkeypatch):
    config={'appConfs':{'example_app':{'features':{'acl':True,'timeUsage':False},'includedDomains':['private.example']},'usage_only':{'features':{'timeUsage':True}}},'secret':'hidden'}
    monkeypatch.setattr(remote,'run',lambda a:json.dumps(config))
    result=remote.app_catalog({})
    assert result['apps'][0]['ordinary_block_target']=='TLX-fw-example_app'
    assert result['apps'][1]['ordinary_block_target'] is None
    assert 'private.example' not in json.dumps(result) and 'hidden' not in json.dumps(result)

def make_flow(**kwargs):
    return dict(ts=1700000000,lh='192.0.2.2',sh='192.0.2.2',dh='203.0.113.2',sp=[12345],dp=443,pr='tcp',ob=10,rb=20,c=4,af={'example.test':{},'https://secret/?token=x':{}},**kwargs)

def test_flow_projection_and_direction():
    result=remote.project_flow(make_flow(),False,{'4':'av'})
    assert result['direction']=='outbound' and result['category']=='av'
    assert result['domains']==['example.test'] and result['destination_port']==443
    assert 'token' not in json.dumps(result)
    f=make_flow();f['sh']='203.0.113.2';f['dh']='192.0.2.2';f['sp']=[444]
    result=remote.project_flow(f,False,{})
    assert result['direction']=='inbound' and result['destination_port']==444 and result['upload_bytes']==20

@pytest.mark.parametrize('fd,direction',[('in','outbound'),('out','inbound')])
def test_blocked_direction(fd,direction):
    f=make_flow(type='ip',fd=fd);del f['ob'];del f['rb']
    result=remote.project_flow(f,True,{})
    assert result['direction']==direction and result['upload_bytes'] is None

def test_page_filters_and_collisions(monkeypatch):
    calls=[]
    f=make_flow();f2=make_flow();f2['c']=5
    def read(argv):
        calls.append(argv)
        if 'GET' in argv:return '{"av":4,"social":5}'
        if 'TYPE' in argv:return 'zset'
        if 'ZCOUNT' in argv:return '3'
        return json.dumps(f)+'\n1700000000\n'+json.dumps(f2)+'\n1700000000\n'
    monkeypatch.setattr(remote,'run',read)
    args=dict(mac='02:00:00:00:00:01',start=1699999999,end=1700000100,offset=0,limit=2,verdict='connections',direction='all',include_categories=['av'],exclude_categories=[])
    result=remote.device_flow_page(args)
    assert len(result['records'])==2 and all(r['category']=='av' for r in result['records'])
    assert result['next_offset']==2
    queries=[x for x in calls if 'ZREVRANGEBYSCORE' in x]
    assert all(x[-4:]==['LIMIT','0','2','WITHSCORES'] for x in queries)
    args['offset']=2;remote.device_flow_page(args)
    assert any('2'==x[-3] for x in calls if 'ZREVRANGEBYSCORE' in x)

def test_pattern_no_inference():
    rows=[]
    for offset in (0,3600,7200):
        f=make_flow();f['ts']+=offset;rows.append(remote.project_flow(f,False,{}))
    result=summarize_page({'records':rows,'next_offset':20,'index_counts_before_filters':{'connection_in':100}})
    assert result['page_totals']['upload_bytes']==30
    assert result['repeated_destinations'][0]['distinct_utc_hours']==3
    assert result['anomaly_verdict']=='not_assessed_without_baseline'

@pytest.mark.parametrize('operation,args',[('control_state',{'target_kind':'device','target':';id'}),('control_rules',{'target_kind':'group','target':'$(id)','offset':0,'limit':3}),('device_flows',{'mac':';id'})])
def test_inspection_injection(operation,args,monkeypatch):
    monkeypatch.setattr(remote,'run',lambda a:pytest.fail('no remote command'))
    assert remote.execute(operation,args)['status']=='unsupported'

async def test_staged_control_and_vpn_are_not_apply_plans():
    from unittest.mock import AsyncMock
    from firewalla_mcp.models import Config,Site
    from firewalla_mcp.server import build_server
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known_hosts',vantage_group='a')
    transport=AsyncMock();transport.run.return_value={'status':'ok','data':{'explicit_policy':{'state':True,'profile_id':'vpn-m'}}}
    server=build_server(Config(sites={'router-a':site}),transport)
    result=await server.call_tool('stage_vpn_switch',dict(box_name='router-a',mac='02:00:00:00:00:01',expected_profile='vpn-m',destination_profile='vpn-n'))
    assert 'unsupported_write' in str(result) and 'executable' in str(result)
    result=await server.call_tool('stage_device_control',dict(box_name='router-a',target_kind='device',target='02:00:00:00:00:01',control='video',desired='enable'))
    assert 'av' in str(result) and 'unsupported_write' in str(result)
    assert all(call.args[1] != 'write' for call in transport.run.await_args_list)

def test_service_projection_no_secrets(monkeypatch):
    commands=[]
    def read(argv):
        commands.append(argv)
        if 'HMGET' in argv:return '"udp"\ntrue\ntrue\n{"state":true,"profileId":"vpn-test","secret":"hidden"}\n'
        if argv[-1]=='ext.dnscrypt.servers':return '["provider-a"]'
        if argv[-1]=='sys:ntp:status':return '1'
        return '1'
    monkeypatch.setattr(remote,'run',read)
    result=remote.service_features('all')
    assert result['unbound']['data']['dns_over_vpn']['profile_id']=='vpn-test'
    assert 'hidden' not in json.dumps(result)
    assert result['custom_dns']['status']=='unsupported'
    assert not any('HGETALL' in c for c in commands)
    assert not any('freeradius_server' in c and 'policy:system' in c for c in commands)

def test_radius_only_feature_flag(monkeypatch):
    commands=[]
    def read(argv):commands.append(argv);return ''
    monkeypatch.setattr(remote,'run',read)
    result=remote.service_features('radius')
    assert commands==[['redis-cli','--raw','HGET','sys:features','freeradius_server']]
    assert result['radius']['data']['dynamic_override'] is None
