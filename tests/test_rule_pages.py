import json
from unittest.mock import AsyncMock
import pytest
from firewalla_mcp import remote
from firewalla_mcp.server import build_server
from test_server import config


def backend(monkeypatch, rows, version='a'*40):
    calls=[]
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[3]==remote.RULE_PAGE_LUA:
            offset,limit=int(argv[5]),int(argv[6])
            return json.dumps({'total':len(rows),'version':version,'rows':rows[offset:offset+limit]})
        return json.dumps({'host:mac:AA:BB:CC:DD:EE:FF':{'name':'Example device'},'tag:uid:3':{'name':'Example group'}})
    monkeypatch.setattr(remote,'run',run)
    return calls


def row(i,**fields):
    return {'id':str(i),'values':{'type':'dns','target':'example.test','action':'block',**fields}}


def test_page_names_fields_missing_state_and_constant_calls(monkeypatch):
    rows=[row(i,scope='["AA:BB:CC:DD:EE:FF"]',tag='["tag:3"]',remotePort='443',protocol='tcp',description='Example',cronTime='0 12 * * *') for i in range(50)]
    calls=backend(monkeypatch,rows)
    page=remote.rule_page({'limit':50})
    assert len(calls)==2
    assert page['total']==50 and not page['has_more']
    record=page['records'][0]
    assert record['configured_state']=='enabled' and record['disabled'] is False
    assert record['scopes'][0]['name']=='Example device'
    assert record['scopes'][1]['name']=='Example group'
    assert record['remotePort']=='443' and record['effective_state']=='unknown'


def test_filtered_empty_page_cursor_and_total(monkeypatch):
    backend(monkeypatch,[row(1,disabled='1'),row(2,disabled='0'),row(3,disabled='odd')])
    page=remote.rule_page({'limit':1,'enabled':True})
    assert page['records']==[] and page['has_more'] and page['total']==3
    next_page=remote.rule_page({'limit':1,'enabled':True,'cursor':page['next_cursor']})
    assert next_page['records'][0]['id']=='2'
    with pytest.raises(ValueError):remote.rule_page({'cursor':page['next_cursor'],'enabled':False})
    backend(monkeypatch,[row(1)],version='b'*40)
    assert remote.rule_page({'cursor':page['next_cursor'],'enabled':True})['restart_required']


@pytest.mark.parametrize('args',[{'limit':51},{'cursor':'1;id'},{'device':'bad'},{'enabled':1},{'category':'x;id'},{'action':'anything'}])
def test_invalid_filters_no_router_reads(monkeypatch,args):
    calls=backend(monkeypatch,[])
    with pytest.raises(ValueError):remote.rule_page(args)
    assert not calls


def test_unknown_state_scope_and_allowlist(monkeypatch):
    backend(monkeypatch,[row(1,disabled='odd',scope='invalid',password='not-returned')])
    data=remote.rule_page({})
    assert data['records'][0]['configured_state']=='unknown'
    assert data['records'][0]['scopes'][0]['kind']=='unknown'
    assert 'not-returned' not in json.dumps(data)


async def test_alias_and_bounded_traversal(config):
    config.aliases={'Example Box':'router-a'}
    transport=AsyncMock()
    transport.run.return_value={'status':'ok','data':{'records':[],'total':100,'scanned':5,'has_more':True,'next_cursor':'next'}}
    server=build_server(config,transport)
    await server.call_tool('managed_rule_summaries',{'box_name':'Example Box','all_pages':True})
    assert transport.run.await_count==10
    assert transport.run.call_args.args[0]==config.sites['router-a']
