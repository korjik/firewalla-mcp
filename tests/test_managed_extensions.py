import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp import remote
from firewalla_mcp.models import Site,Config
from firewalla_mcp.writes import WriteManager
from firewalla_mcp.transport import remote_command
from test_managed import appliance,MAC,RULE,preview,apply

SCHEDULE={'hour':20,'minute':30,'days':[1,3,5],'duration':3600,'timezone':'UTC'}
SCOPED={'kind':'managed_scoped','scope':'network','target':'00000000-0000-0000-0000-000000000001','feature':'doh','desired':'enable'}
LIFE={'kind':'managed_lifecycle','profile':'vpn-a','vpn_type':'wireguard','desired':'connect'}

@pytest.fixture
def scheduled(appliance,monkeypatch):
    original=remote.run
    monkeypatch.setattr(remote,'run',lambda argv,*a,**k:'UTC' if argv[-2:]==['sys:config','timezone'] else original(argv,*a,**k))
    return appliance


def test_scheduled_rule_creation_and_rollback(scheduled):
    spec={**RULE,'schedule':SCHEDULE}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    value=scheduled['requests'][0][3]
    assert value['cronTime']=='30 20 * * 1,3,5' and value['duration']==3600
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'


@pytest.mark.parametrize('key,value',[('hour',24),('minute',-1),('days',[]),('days',[0,0]),('days',[True]),('duration',86400),('duration',False),('timezone','UTC;id')])
def test_bad_schedule_rejected(scheduled,key,value):
    with pytest.raises(ValueError):preview({**RULE,'schedule':{**SCHEDULE,key:value}})
    assert not scheduled['requests']


def test_timezone_mismatch_fails_closed(scheduled):
    with pytest.raises(remote.Unsupported):preview({**RULE,'schedule':{**SCHEDULE,'timezone':'Europe/Paris'}})
    assert not scheduled['requests']


def test_schedule_update_prevents_rollback(scheduled):
    spec={**RULE,'schedule':SCHEDULE}
    result=apply(spec,preview(spec))
    scheduled['rules'][0][9]='7200'
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='stale'


@pytest.mark.parametrize('address',['192.0.2.15','2001:db8::15'])
def test_dns_override_create_delete(appliance,address):
    spec={**RULE,'rule_type':'dns_override','target':'example.org','address':address}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    value=appliance['requests'][0][3]
    assert value['action']=='address' and value['resolver']==address and value['ipOnly'] is True
    assert value['domainExactMatch'] is False  # DNS address directives include subdomains.
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'


@pytest.mark.parametrize('address',['x;id','192.0.2.1:53','$(id)'])
def test_dns_override_invalid_address(appliance,address):
    with pytest.raises(ValueError):preview({**RULE,'rule_type':'dns_override','target':'example.org','address':address})
    assert not appliance['requests']


@pytest.mark.parametrize('scope,target,api_target',[('group','123','tag:123'),('network',SCOPED['target'],'network:'+SCOPED['target'])])
@pytest.mark.parametrize('feature',['safeSearch','doh','unbound'])
def test_scoped_services_roundtrip(appliance,scope,target,api_target,feature):
    spec={**SCOPED,'scope':scope,'target':target,'feature':feature}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied' and appliance['requests'][0][2]==api_target
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'


def test_ntp_requires_enabled_healthy_service(appliance,monkeypatch):
    original=remote.run
    def run(argv,*a,**k):
        if argv[-1] in ('ntp_redirect','sys:ntp:status') and 'policy:network:'+SCOPED['target'] not in argv:return '0'
        return original(argv,*a,**k)
    monkeypatch.setattr(remote,'run',run)
    with pytest.raises(remote.Unsupported):preview({**SCOPED,'feature':'ntp_redirect'})
    assert not appliance['requests']


def test_ntp_network_override_does_not_start_daemon(appliance,monkeypatch):
    original=remote.run
    def run(argv,*a,**k):
        if 'sys:features' in argv or 'sys:ntp:status' in argv:return '1'
        assert argv[0]=='redis-cli'
        return original(argv,*a,**k)
    monkeypatch.setattr(remote,'run',run)
    spec={**SCOPED,'feature':'ntp_redirect'}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    assert appliance['requests'][0]==('set','policy','network:'+SCOPED['target'],{'ntp_redirect':{'state':True}})
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'


@pytest.mark.parametrize('spec',[{**SCOPED,'scope':'group','target':'1','feature':'ntp_redirect'},{**SCOPED,'target':'../../config'},{**SCOPED,'scope':'global'}])
def test_bad_scope_rejected(appliance,spec):
    with pytest.raises(ValueError):preview(spec)
    assert not appliance['requests']


@pytest.fixture
def lifecycle(monkeypatch):
    state={'connected':False,'unit_file':'disabled','settings':'a'*64,'calls':[]}
    monkeypatch.setattr(remote,'management_guard',lambda revision:None)
    monkeypatch.setattr(remote.os.path,'isfile',lambda p:True)
    monkeypatch.setattr(remote,'managed_vpn_safety',lambda p:({'strictVPN':True},state['settings']))
    def run(argv):
        if argv[0]=='redis-cli':return 'true' if state['connected'] else 'false'
        if argv[0]=='ip':return json.dumps([{'ifname':'vpn_vpn-a','flags':['UP']}] if state['connected'] else [])
        if argv[0]=='systemctl':return 'ActiveState='+('active' if state['connected'] else 'inactive')+'\nUnitFileState='+state['unit_file']
        raise AssertionError(argv)
    monkeypatch.setattr(remote,'run',run)
    def request(command,item,target,value,**kwargs):
        state['calls'].append((command,item,target,value,kwargs))
        state['connected']=item=='startVpnClient'
    monkeypatch.setattr(remote,'management_request',request)
    return state


@pytest.mark.parametrize('vpn_type',['openvpn','wireguard'])
def test_lifecycle_connect_disconnect_are_separate_changes(lifecycle,vpn_type):
    spec={**LIFE,'vpn_type':vpn_type}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied' and result['rollback']=='not_supported'
    assert lifecycle['calls'][0][1]=='startVpnClient'
    assert lifecycle['calls'][0][-1]=={'lifecycle':True}
    with pytest.raises(remote.Unsupported):apply(spec,result['state'],'rollback')
    stop={**spec,'desired':'disconnect'}
    assert apply(stop,preview(stop))['outcome']=='applied'
    assert lifecycle['calls'][-1][1]=='stopVpnClient'


def test_enabled_openvpn_unit_rejected(lifecycle):
    lifecycle['unit_file']='enabled'
    with pytest.raises(remote.Unsupported):preview({**LIFE,'vpn_type':'openvpn'})
    assert not lifecycle['calls']


def test_lifecycle_timeout_is_uncertain(lifecycle,monkeypatch):
    before=preview(LIFE)
    def fail(*a,**k):raise TimeoutError('credential must not escape')
    monkeypatch.setattr(remote,'management_request',fail)
    result=apply(LIFE,before)
    assert result['outcome']=='uncertain' and 'credential' not in str(result)


def test_lifecycle_changed_settings_is_uncertain(lifecycle,monkeypatch):
    original=remote.management_request
    def request(*a,**k):
        original(*a,**k);lifecycle['settings']='b'*64
    monkeypatch.setattr(remote,'management_request',request)
    assert apply(LIFE,preview(LIFE))['outcome']=='uncertain'


def test_lifecycle_conflicting_observations_rejected(lifecycle,monkeypatch):
    original=remote.run
    monkeypatch.setattr(remote,'run',lambda a:json.dumps([{'ifname':'vpn_vpn-a','flags':['UP']}]) if a[0]=='ip' else original(a))
    with pytest.raises(remote.Unsupported):preview(LIFE)
    assert not lifecycle['calls']


def test_only_lifecycle_has_extended_deadline():
    assert remote_command('managed_write',{'spec':LIFE}).startswith('timeout 110 ')
    assert remote_command('managed_write',{'spec':RULE}).startswith('timeout 20 ')


async def test_scope_and_lifecycle_allowlists(tmp_path):
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',management_revision=remote.MANAGEMENT_REVISION)
    manager=WriteManager(Config(sites={'router-a':site},writes_enabled=True,approval_directory=str(tmp_path),audit_file=str(tmp_path/'audit')),AsyncMock())
    with pytest.raises(ValueError,match='allowlist'):manager.validate('router-a',SCOPED)
    with pytest.raises(ValueError,match='allowlist'):manager.validate('router-a',LIFE)
    site.managed_scopes=['network:'+SCOPED['target']];site.managed_vpn_profiles=['vpn-a']
    assert manager.validate('router-a',SCOPED)==site and manager.validate('router-a',LIFE)==site
