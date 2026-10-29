"""Authenticated HTTP MCP roundtrip in a temporary local Docker container; no routers."""
import json
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time
import httpx

DOCKER=['docker','--host=unix:///var/run/docker.sock']
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    config=root/'config.json';config.write_text('{"sites":{}}');config.chmod(0o644)
    token=secrets.token_urlsafe(36)
    secret=root/'http-token';secret.write_text(token);secret.chmod(0o644)
    container=subprocess.check_output(DOCKER+['run','-d','--rm','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
        '-p','127.0.0.1::8000','-v',str(config)+':/config/config.json:ro','-v',str(secret)+':/secrets/http-token:ro',
        '-e','FIREWALLA_MCP_HTTP_TOKEN_FILE=/secrets/http-token','-e','FIREWALLA_MCP_HTTP_ALLOWED_HOSTS=firewalla-test',
        sys.argv[1],'--transport','streamable-http','--host','0.0.0.0'],text=True).strip()
    try:
        address=subprocess.check_output(DOCKER+['port',container,'8000/tcp'],text=True).strip()
        with httpx.Client(base_url='http://'+address,headers={'Host':'firewalla-test'},timeout=5,trust_env=False) as client:
            ready=False
            for _ in range(40):
                try:
                    if client.get('/healthz').status_code==401:ready=True;break
                except httpx.TransportError:pass
                time.sleep(.25)
            assert ready,'HTTP listener did not start'
            headers={'Authorization':'Bearer '+token,'Accept':'application/json, text/event-stream'}
            r=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'smoke','version':'1'}}})
            assert r.status_code==200
            headers['MCP-Protocol-Version']=r.json()['result']['protocolVersion']
            r=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
            names={t['name'] for t in r.json()['result']['tools']}
            assert len(names)==34 and 'apply_change' not in names
            r=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_boxes','arguments':{}}})
            assert not r.json()['result'].get('isError',False)
            assert client.get('/healthz',headers=headers).json()['status']=='ok'
        print('Docker authenticated Streamable HTTP: initialize, 34 read-only tools, call, health, unauthenticated rejection: PASS')
    finally:
        subprocess.run(DOCKER+['rm','-f',container],check=True,stdout=subprocess.DEVNULL)
