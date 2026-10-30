"""Disposable Docker stdio + curl MCP checks; empty boxes, no router credentials.
Usage: python3 scripts/curl_smoke.py IMAGE --docker /usr/local/bin/docker --sudo
Only the built image persists. Temporary containers/files/bearer are removed.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import tempfile
import time
import uuid


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--docker',default='docker')
    parser.add_argument('--sudo',action='store_true')
    parser.add_argument('--temp-root',default=None)
    parser.add_argument('--no-cpu-quota',action='store_true',help='For NAS kernels without CPU CFS quota; memory limit remains enabled')
    args=parser.parse_args()
    docker=(['sudo','-n'] if args.sudo else [])+[args.docker]
    def command(*argv):
        return subprocess.check_output(list(argv),stderr=subprocess.PIPE,text=True,timeout=30)
    command(*(docker+['run','--rm','--network','none','--entrypoint','ssh',args.image,'-G','-F','/dev/null','example.invalid']))
    print('OpenSSH local service-account lookup: PASS',flush=True)
    def empty_boxes(result):
        data=result.get('structuredContent')
        if data is None:
            data=json.loads(next(v['text'] for v in result['content'] if v.get('type')=='text'))
        if 'result' in data:data=data['result']
        return data.get('boxes')==[]
    with tempfile.TemporaryDirectory(prefix='firewalla-mcp-smoke-',dir=args.temp_root) as directory:
        root=Path(directory)
        config=root/'config.json';config.write_text('{"sites":{},"writes_enabled":false}');config.chmod(0o644)
        common=['--rm','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory','256m',
                '-v',str(config)+':/config/config.json:ro']
        if not args.no_cpu_quota:common+=['--cpus','1']
        stdio_name='firewalla-mcp-stdio-'+uuid.uuid4().hex[:12]
        process=subprocess.Popen(docker+['run','--name',stdio_name,'-i','--network','none']+common+[args.image],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            def stdio(message):
                process.stdin.write(json.dumps(message)+'\n');process.stdin.flush()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout,selectors.EVENT_READ)
                    if not selector.select(20):raise RuntimeError('stdio response timeout')
                    line=process.stdout.readline()
                    if not line:
                        process.wait(timeout=5)
                        raise RuntimeError('stdio process exited: '+process.stderr.read(2048))
                    result=json.loads(line)
                assert result.get('id')==message['id'] and 'result' in result
                return result['result']
            init={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'curl-smoke','version':'1'}}}
            stdio(init)
            process.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');process.stdin.flush()
            names={t['name'] for t in stdio({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})['tools']}
            assert len(names)==36 and not {'apply_change','apply_vpn_change','apply_vpn_import','start_capture','apply_network_plan'} & names
            response=stdio({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_boxes','arguments':{}}})
            assert not response.get('isError',False)
            assert empty_boxes(response)
            print('Docker stdio initialize/list(36)/call(list_boxes): PASS',flush=True)
        finally:
            process.stdin.close()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            subprocess.run(docker+['rm','-f',stdio_name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        token=secrets.token_urlsafe(36)
        token_file=root/'http-token';token_file.write_text(token);token_file.chmod(0o644)
        # Parent directory remains mode 0700. Bind only this ephemeral file; no persistent credential.
        curl_config=root/'curl.conf'
        curl_config.write_text('header = "Authorization: Bearer '+token+'"\n')
        curl_config.chmod(0o600)
        name='firewalla-mcp-http-'+uuid.uuid4().hex[:12]
        command(*(docker+['run','-d','--name',name]+common+['-p','127.0.0.1::8000',
            '-v',str(token_file)+':/secrets/http-token:ro',
            '-e','FIREWALLA_MCP_HTTP_TOKEN_FILE=/secrets/http-token',
            '-e','FIREWALLA_MCP_HTTP_ALLOWED_HOSTS=firewalla-test',
            args.image,'--transport','streamable-http','--host','0.0.0.0']))
        try:
            address=command(*(docker+['port',name,'8000/tcp'])).strip()
            assert address.startswith('127.0.0.1:') and '\n' not in address
            base='http://'+address
            curl=['curl','--noproxy','*','--silent','--show-error','--max-time','5','-H','Host: firewalla-test']
            for attempt in range(40):
                try:
                    status=command(*(curl+['-o','/dev/null','-w','%{http_code}',base+'/healthz']))
                    if status=='401':break
                except subprocess.CalledProcessError:pass
                time.sleep(.25)
            else:raise RuntimeError('private HTTP listener did not start')
            def http(message,protocol=None):
                call=curl+['--config',str(curl_config),'-H','Accept: application/json, text/event-stream','-H','Content-Type: application/json']
                if protocol:call+=['-H','MCP-Protocol-Version: '+protocol]
                response=json.loads(command(*(call+['--data-binary',json.dumps(message),base+'/mcp'])))
                assert response.get('id')==message['id'] and 'result' in response
                return response['result']
            result=http(init);protocol=result['protocolVersion']
            # Stateless HTTP does not require a session ID; send the initialized notification.
            command(*(curl+['--config',str(curl_config),'-H','Accept: application/json, text/event-stream','-H','Content-Type: application/json','-H','MCP-Protocol-Version: '+protocol,'--data-binary',json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'}),base+'/mcp']))
            names={tool['name'] for tool in http({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},protocol)['tools']}
            assert len(names)==36 and not {'apply_change','apply_vpn_change','apply_vpn_import','start_capture','apply_network_plan'} & names
            result=http({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_boxes','arguments':{}}},protocol)
            assert not result.get('isError',False) and empty_boxes(result)
            health=json.loads(command(*(curl+['--config',str(curl_config),base+'/healthz'])))
            assert health['status']=='ok'
            print('curl Streamable HTTP initialize/list(36)/call(list_boxes), health, unauthenticated 401: PASS',flush=True)
            print('HTTP binding: '+address+' (temporary loopback only)',flush=True)
        finally:
            subprocess.run(docker+['rm','-f',name],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print('Temporary containers, files and bearer removed; appliance SSH authentication NOT tested.',flush=True)


if __name__=='__main__':main()
