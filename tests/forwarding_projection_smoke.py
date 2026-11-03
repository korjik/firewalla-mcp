"""Real Redis Lua projection test, disposable network-none container only."""
import json
import os
import subprocess
import tempfile
import time
from firewalla_mcp.forward_policy import read_projection, reject_duplicate, native_allow, projection_script

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
        def write(commands):
            result=subprocess.run(['redis-cli','-s',socket,'--pipe'],input=b''.join(resp(c) for c in commands),capture_output=True,check=True,timeout=10)
            assert b'errors: 0' in result.stdout, result.stdout
        def rejected(reason):
            script,fields=projection_script()
            raw=run(['redis-cli','--raw','EVAL',script,'0',fields])
            assert raw.startswith('ERR ') and reason in raw, raw
        def reset(values):
            run(['redis-cli','FLUSHDB'])
            commands=[]
            for i,value in enumerate(values,1):
                commands.extend([['ZADD','policy_active',i,str(i)],['HSET','policy:'+str(i),'unknown_semantics',value]])
            write(commands)
        commands=[]
        for i in range(398):
            pid=str(i+1)
            commands.append(resp(['ZADD','policy_active',i,pid]))
            commands.append(resp(['HSET','policy:'+pid,'type','dns','target',f'host{i}.example.org','action','block','direction','outbound',
                                  'scope','["02:00:00:00:00:01"]','timestamp','1700000000','disabled','0','trust','false',
                                  'dnsmasq_only','false','ipOnly','false','flowIsolation','false','useBf','false','upnp','false','seq','3',
                                  'lastHitFlow','PRIVATE_SYNTHETIC_SENTINEL','hitCount','42']))
        subprocess.run(['redis-cli','-s',socket,'--pipe'],input=b''.join(commands),capture_output=True,check=True,timeout=10)
        rows=read_projection(run)
        assert len(rows)==398 and all(r['identity_complete'] for r in rows)
        # A verbose projection exceeds the subprocess cap; the sparse atomic
        # wire representation fits without relaxing that cap or losing fields.
        expanded_bytes=len(json.dumps(rows,separators=(',',':')).encode())
        assert expanded_bytes>131072
        script,fields=projection_script()
        wire=run(['redis-cli','--raw','EVAL',script,'0',fields])
        assert len(wire.encode())<=131072 and json.loads(wire)['version']==1
        assert all(r['seq']=='3' and r['flowIsolation']=='false' for r in rows)
        objects={'policy:'+r['pid']:{'kind':'allow_policy','enabled':True,'value':{'policy_fingerprint':r['full_fingerprint']},
                 'instance':{'id':r['pid'],'birth':r['timestamp']}} for r in rows}
        assert len(json.dumps({'status':'ok','data':{'state':{'objects':objects},'policies':rows}}).encode())<524288
        assert 'PRIVATE_SYNTHETIC_SENTINEL' not in json.dumps(rows)
        prior=rows[0]['full_fingerprint']
        run(['redis-cli','HSET','policy:1','hitCount','99'])
        assert read_projection(run)[0]['full_fingerprint']==prior
        baseline=read_projection(run)
        # Reproduce a large inventory whose omitted flow metadata alone exceeds
        # the aggregate budget; no private/live policy data is used here.
        write([['HSET','policy:'+str(i),'lastHitFlow','PRIVATE_SYNTHETIC_SENTINEL'+'x'*512] for i in range(1,399)])
        assert read_projection(run)==baseline
        # Every exact observational field can exceed the per-value budget too.
        # Values are never fetched, returned, or included in identity hashes.
        write([['HSET','policy:1',field,'PRIVATE_SYNTHETIC_SENTINEL'+'x'*100000]
               for field in ('hitCount','lastHitTs','lastHitFlow','statsResetTs')])
        assert read_projection(run)==baseline
        run(['redis-cli','HSET','policy:1','target','changed.example.org'])
        assert read_projection(run)[0]['full_fingerprint']!=prior
        run(['redis-cli','HSET','policy:1','unknown_semantics','yes'])
        assert read_projection(run)[0]['identity_complete'] is False
        unknown=read_projection(run)[0]
        desired=native_allow('02:00:00:00:00:01','11111111-1111-4111-8111-111111111111','0.0.0.0/0','tcp',443,443,'a'*32)
        reject_duplicate([unknown],desired)
        run(['redis-cli','HSET','policy:1','i.type','net'])
        legacy=read_projection(run)[0]
        assert legacy['legacy_identity'] is True
        try:reject_duplicate([legacy],desired)
        except ValueError:pass
        else:raise AssertionError('legacy identity must block')
        # The exception is exact, not a prefix match or a relaxation for unknown
        # policy semantics. Unknown values remain bounded and fingerprint-bound.
        reset(['x'*8192])
        first=read_projection(run)[0]
        assert first['identity_complete'] is False
        run(['redis-cli','HSET','policy:1','unknown_semantics','y'*8192])
        assert read_projection(run)[0]['full_fingerprint']!=first['full_fingerprint']
        run(['redis-cli','HSET','policy:1','unknown_semantics','x'*8193])
        rejected('policy byte bound')
        reset(['small'])
        run(['redis-cli','HSET','policy:1','lastHitFlowExtra','x'*8193])
        rejected('policy byte bound')
        reset(['small'])
        run(['redis-cli','HSET','policy:1','target','x'*8193])
        rejected('policy byte bound')
        reset(['x'*8192]*10+['x'*8080])  # exactly 90,000 configured bytes
        assert len(read_projection(run))==11
        run(['redis-cli','HSET','policy:11','unknown_semantics','x'*8081])
        rejected('policy byte bound')
        # JSON escaping can exceed the wire cap even while source values fit.
        # Such inventories still fail closed with an explicit bounded response.
        reset(['\x01'*8192]*10+['\x01'*8080])
        write([['HSET','policy:'+str(i),'target','\x01'*8192] for i in range(1,11)])
        # Remove the unknown fields so the configured-value sum remains 90k.
        write([['HDEL','policy:'+str(i),'unknown_semantics'] for i in range(1,11)])
        rejected('policy projection output bound')
        reset(['x']*512)
        assert len(read_projection(run))==512
        write([['ZADD','policy_active',513,'513'],['HSET','policy:513','type','dns']])
        rejected('policy inventory bound')
        reset(['x'])
        write([['HSET','policy:1','field'+str(i),'x'] for i in range(95)])
        assert len(read_projection(run)[0]['unknown_fields'])==96
        run(['redis-cli','HSET','policy:1','lastHitFlow','omitted but still a field'])
        rejected('policy schema bound')
        run(['redis-cli','DEL','policy:1'])
        rejected('policy schema bound')
        print(f'PASS: 398-policy wire {len(wire.encode())} bytes; expanded {expanded_bytes} bytes; compact atomic projection and all bounds verified')
    finally:
        process.terminate();process.wait(timeout=5)
