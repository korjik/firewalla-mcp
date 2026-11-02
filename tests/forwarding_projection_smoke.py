"""Real Redis Lua projection test, disposable network-none container only."""
import json
import os
import subprocess
import tempfile
import time
from firewalla_mcp.forward_policy import read_projection

with tempfile.TemporaryDirectory() as d:
    socket=d+'/redis.sock'
    process=subprocess.Popen(['redis-server','--port','0','--unixsocket',socket,'--save','','--appendonly','no','--dir',d],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists(socket):break
            time.sleep(.02)
        def run(args):
            result=subprocess.run([args[0],'-s',socket]+args[1:],capture_output=True,check=True,timeout=5)
            assert len(result.stdout)<=131072
            return result.stdout.decode()
        def resp(values):
            encoded=[str(v).encode() for v in values]
            return b'*'+str(len(encoded)).encode()+b'\r\n'+b''.join(b'$'+str(len(v)).encode()+b'\r\n'+v+b'\r\n' for v in encoded)
        commands=[]
        for i in range(398):
            pid=str(i+1)
            commands.append(resp(['ZADD','policy_active',i,pid]))
            commands.append(resp(['HSET','policy:'+pid,'type','dns','target',f'host{i}.example.org','action','block','direction','outbound',
                                  'scope','["02:00:00:00:00:01"]','timestamp','1700000000','disabled','0','trust','false',
                                  'lastHitFlow','PRIVATE_SYNTHETIC_SENTINEL','hitCount','42']))
        subprocess.run(['redis-cli','-s',socket,'--pipe'],input=b''.join(commands),capture_output=True,check=True,timeout=10)
        rows=read_projection(run)
        assert len(rows)==398 and all(r['identity_complete'] for r in rows)
        assert 'PRIVATE_SYNTHETIC_SENTINEL' not in json.dumps(rows)
        prior=rows[0]['full_fingerprint']
        run(['redis-cli','HSET','policy:1','hitCount','99'])
        assert read_projection(run)[0]['full_fingerprint']==prior
        run(['redis-cli','HSET','policy:1','unknown_semantics','yes'])
        assert read_projection(run)[0]['identity_complete'] is False
        print('PASS: 398 complete projected policies, bounded output, no flow values; observational counters do not invalidate configured identity')
    finally:
        process.terminate();process.wait(timeout=5)
