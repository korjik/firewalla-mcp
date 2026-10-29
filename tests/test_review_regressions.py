"""Independent contract model of upstream target normalization and duplicate reactivation."""
import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp import remote
from firewalla_mcp.models import Config,Site
from firewalla_mcp.writes import WriteManager,digest
from test_managed import MAC,RULE,preview,apply
from test_managed_extensions import lifecycle,LIFE

@pytest.fixture
def upstream(monkeypatch):
    state={'policies':{},'calls':[],'race':False,'reactivated':False}
    monkeypatch.setattr(remote,'management_guard',lambda revision:None)
    monkeypatch.setattr(remote,'run',lambda argv:'1' if 'EXISTS' in argv else pytest.fail(str(argv)))
    def constructor(value):
        value=copy.deepcopy(value)
        if value['type'] in ('dns','domain'):value['target']=value['target'].lower()
        elif value['type']=='mac':value['target']=value['target'].upper()
        value.setdefault('direction','bidirection');value.setdefault('action','block')
        return value
    def rows():
        result=[]
        for pid,v in sorted(state['policies'].items()):
            result.append([pid]+[v['type'],v['target'],v['action'],v['direction'],json.dumps(v.get('scope',[])),v.get('disabled','0'),v.get('cronTime',False),v.get('expire',False),str(v.get('duration','')),v.get('resolver',False),str(v.get('domainExactMatch','')).lower(),str(v.get('ipOnly','')).lower(),digest(v)])
        return result
    monkeypatch.setattr(remote,'managed_rule_snapshot',rows)
    def request(command,item,target,value,want_pid=False,**kwargs):
        state['calls'].append((item,copy.deepcopy(value)))
        if item=='policy:create':
            candidate=constructor(value)
            if state['race']:
                state['policies']['7']={**candidate,'disabled':'1'}
            same=[(pid,p) for pid,p in state['policies'].items() if all(p.get(k)==candidate.get(k) for k in ('type','target','action','direction','scope','resolver','cronTime'))]
            if same:
                pid,p=same[0]
                # Models checkAndSave: disabled is NOT part of equality.
                if p.get('disabled')=='1' and candidate.get('disabled')!='1':
                    p['disabled']='0';state['reactivated']=True
                    raise remote.Unsupported('updated=true response after existing-rule mutation')
                raise remote.Unsupported('HTTP 409 duplicate')
            pid='123';state['policies'][pid]=candidate
            return pid
        if item=='policy:enable':
            state['policies'][value['policyID']]['disabled']='0';return
        if item=='policy:delete':
            del state['policies'][value['policyID']];return
        raise AssertionError(item)
    monkeypatch.setattr(remote,'management_request',request)
    return state


def existing_dns():
    return dict(type='dns',target='example.org',action='block',direction='outbound',scope=[MAC],disabled='1')


@pytest.mark.parametrize('stored_type,target',[('dns','example.org'),('dns','Example.ORG'),('domain','example.org')])
def test_existing_disabled_domain_never_reactivated(upstream,stored_type,target):
    upstream['policies']['7']={**existing_dns(),'type':stored_type,'target':target}
    spec={**RULE,'rule_type':'dns','target':'Example.org'}
    before=preview(spec)
    assert spec['target']=='example.org' and before['present']
    assert apply(spec,before)['outcome']=='stale'
    assert upstream['policies']['7']['disabled']=='1'
    assert not upstream['calls'] and not upstream['reactivated']


def test_duplicate_race_cannot_reactivate_existing_rule(upstream):
    spec={**RULE,'rule_type':'dns','target':'Example.org'}
    before=preview(spec)
    upstream['race']=True
    result=apply(spec,before)
    assert result['outcome']=='uncertain'
    assert upstream['calls']==[('policy:create',{'type':'dns','target':'example.org','action':'block','direction':'outbound','scope':[MAC],'disabled':'1'})]
    assert upstream['policies']['7']['disabled']=='1' and not upstream['reactivated']


def test_mixed_case_fresh_create_verify_and_rollback(upstream):
    spec={**RULE,'rule_type':'dns','target':'Example.ORG'}
    result=apply(spec,preview(spec))
    assert result['outcome']=='applied'
    assert upstream['policies']['123']['target']=='example.org'
    assert [item for item,_ in upstream['calls']]==['policy:create','policy:enable']
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'
    assert upstream['policies']=={}


def test_equivalent_ipv6_existing_target_conflict(upstream):
    upstream['policies']['7']={**existing_dns(),'type':'ip','target':'2001:0DB8:0000::1'}
    spec={**RULE,'rule_type':'ip','target':'2001:db8::1'}
    assert preview(spec)['present'] and not upstream['calls']


def test_existing_mac_normalization_conflict(upstream):
    upstream['policies']['7']={**existing_dns(),'type':'mac','target':MAC.lower()}
    assert preview({**RULE,'rule_type':'internet','target':'internet'})['present']


@pytest.mark.parametrize('value',['fe80::1%eth0','fe80::1%1','fe80::1%x\naddress=/example.org/127.0.0.1','fe80::1%x\r','fe80::1%x\x00','fe80::1%x\t','2001:db8::1\n',' 192.0.2.1','192.0.2.1#','[2001:db8::1]'])
@pytest.mark.parametrize('kind',['ip','dns_override'])
def test_scoped_or_config_ip_not_accepted(upstream,value,kind):
    spec={**RULE,'rule_type':kind,'target':value if kind=='ip' else 'example.org'}
    if kind=='dns_override':spec['address']=value
    with pytest.raises(ValueError):preview(spec)
    assert not upstream['calls']


def test_dns_override_domain_and_address_canonicalization(upstream):
    spec={**RULE,'rule_type':'dns_override','target':'Example.ORG','address':'2001:0DB8:0000::1'}
    result=apply(spec,preview(spec))
    assert spec['target']=='example.org' and spec['address']=='2001:db8::1'
    assert result['outcome']=='applied'
    assert upstream['policies']['123']['resolver']=='2001:db8::1'
    assert apply(spec,result['state'],'rollback',result['context'])['outcome']=='rolled_back'


async def test_canonical_spec_precedes_approval_digest_and_approved_rollback(upstream,tmp_path):
    class Transport:
        async def run(self,site,op,args):return remote.execute(op,args)
    site=Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',management_revision=remote.MANAGEMENT_REVISION,managed_devices=[MAC])
    manager=WriteManager(Config(sites={'router-a':site},writes_enabled=True,approval_directory=str(tmp_path),audit_file=str(tmp_path/'audit')),Transport())
    plan=await manager.preview('router-a',{**RULE,'rule_type':'dns','target':'ExAmPlE.ORG'})
    assert plan['spec']['target']=='example.org'
    internal=manager.plans[plan['plan_id']]
    assert plan['digest']==digest({k:v for k,v in internal.items() if k not in ('digest','status')})
    Path(plan['approval_file']).write_text(json.dumps(plan['approval_document']))
    assert (await manager.apply(plan['plan_id']))['data']['outcome']=='applied'
    rollback=await manager.rollback_preview(plan['plan_id'])
    Path(rollback['approval_file']).write_text(json.dumps(rollback['approval_document']))
    assert (await manager.apply(rollback['plan_id']))['data']['outcome']=='rolled_back'
    assert not upstream['policies']


@pytest.mark.parametrize('vpn_type',['openvpn','wireguard'])
def test_down_but_reconnecting_requires_approved_stop(lifecycle,monkeypatch,vpn_type):
    lifecycle['connected']=False;lifecycle['started']=True
    original=remote.management_request
    def request(*args,**kwargs):
        original(*args,**kwargs)
        if args[1]=='stopVpnClient':lifecycle['started']=False
    monkeypatch.setattr(remote,'management_request',request)
    spec={**LIFE,'vpn_type':vpn_type,'desired':'disconnect'}
    before=preview(spec)
    assert not before['present'] and before['field']['administrative_intent']=='unknown'
    assert lifecycle['started'] and not lifecycle['calls']
    result=apply(spec,before)
    assert result['outcome']=='applied' and not lifecycle['started']
    assert lifecycle['calls'][0][1]=='stopVpnClient'
    assert result['management_operation_acknowledged']=='disconnect'
    assert 'unverified' in result['administrative_intent']
