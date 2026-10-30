import json
import pytest
import httpx
from starlette.testclient import TestClient
from firewalla_mcp.models import Config
from firewalla_mcp.server import build_server
from firewalla_mcp.http import PrivateHTTP,http_app

@pytest.fixture
def app(tmp_path):
    path=tmp_path/'token';path.write_text('x'*48)
    return http_app(build_server(Config(sites={}),readonly_catalog=True),str(path),['testserver'])

@pytest.mark.parametrize('headers,code', [({},401),({'Authorization':'Bearer wrong'},401),({'Authorization':'Bearer '+'x'*48,'Origin':'https://evil.example'},403),({'Authorization':'Bearer '+'x'*48,'Host':'evil.example'},421)])
def test_http_auth_origin_host(app,headers,code):
    with TestClient(app) as client:
        assert client.get('/mcp',headers=headers).status_code==code

def test_query_tokens_rejected(app):
    with TestClient(app) as client:
        assert client.get('/mcp?token=hidden',headers={'Authorization':'Bearer '+'x'*48}).status_code==400

def test_real_http_mcp_protocol(app):
    with TestClient(app) as client:
        headers={'Authorization':'Bearer '+'x'*48,'Accept':'application/json, text/event-stream'}
        result=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'test','version':'1'}}})
        assert result.status_code==200 and 'serverInfo' in result.json()['result']
        headers['MCP-Protocol-Version']=result.json()['result']['protocolVersion']
        result=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
        names={t['name'] for t in result.json()['result']['tools']}
        assert len(names)==36 and 'apply_change' not in names
        assert all(t.get('outputSchema',{}).get('type')=='object' for t in result.json()['result']['tools'])
        result=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_boxes','arguments':{}}})
        assert result.status_code==200 and not result.json()['result'].get('isError',False)
        assert result.json()['result']['structuredContent']=={'boxes':[],'aliases':{}}
        result=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'apply_change','arguments':{'plan_id':'a'*32}}})
        assert result.json()['result']['isError']

@pytest.mark.parametrize('token',['','short','x'*31,'x'*32+' secret'])
def test_weak_token_rejected(token):
    with pytest.raises(ValueError):PrivateHTTP(None,token,['testserver'])

def test_readonly_cannot_enable_writes():
    with pytest.raises(ValueError):build_server(Config(sites={},writes_enabled=True),readonly_catalog=True)

def test_no_wildcard_hosts():
    with pytest.raises(ValueError):PrivateHTTP(None,'x'*48,['*'])

def test_duplicate_auth_rejected(app):
    with TestClient(app) as client:
        response=client.get('/healthz',headers=[('Authorization','Bearer '+'x'*48),('Authorization','Bearer '+'x'*48)])
        assert response.status_code==401
