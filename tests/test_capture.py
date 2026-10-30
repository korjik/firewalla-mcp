import asyncio,copy,importlib.util,ipaddress,json,shlex,struct,time
from pathlib import Path
import pytest
from firewalla_mcp.capture_helper import validate,command,Parser,statistics,packet_metadata
from firewalla_mcp.capture import CaptureManager,capture_command
from test_approval_bound_vpn import approved_config


def spec():return dict(interface='vpn_example',address='192.0.2.10',device=None,protocol='tcp',port=41000,duration=10,packets=50)

def packet(version=4):
    tcp=struct.pack('!HH',42000,41000)+b'\x00'*8+b'\x50\x12'+b'\x00'*6
    secret=b'PASSWORD_DO_NOT_RETURN'
    if version==4:
        ip=b'\x45\x00'+struct.pack('!H',40+len(secret))+b'\x00'*5+b'\x06'+b'\x00'*2+ipaddress.ip_address('192.0.2.1').packed+ipaddress.ip_address('192.0.2.10').packed
        return b'\x00'*12+b'\x08\x00'+ip+tcp+secret
    ip=b'\x60'+b'\x00'*3+struct.pack('!H',20+len(secret))+b'\x06\x40'+ipaddress.ip_address('2001:db8::1').packed+ipaddress.ip_address('2001:db8::2').packed
    return b'\x00'*12+b'\x86\xdd'+ip+tcp+secret

def pcap(payload):return b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,96,1)+struct.pack('<IIII',123,500000,len(payload),len(payload))+payload

@pytest.mark.parametrize('version',[4,6])
def test_incremental_parser_no_payload(version):
    p=Parser();raw=pcap(packet(version))
    for i in range(0,len(raw),3):p.feed(raw[i:i+3])
    assert len(p.rows)==1 and p.rows[0]['tcp_flags']==['SYN','ACK'] and p.rows[0]['destination_port']==41000
    assert p.rows[0]['ip_version']==version and 'PASSWORD' not in json.dumps(p.rows)
    assert p.rows[0]['timestamp_epoch']==123.5

@pytest.mark.parametrize('key,value',[('interface','any'),('interface','eth0;id'),('address','x;id'),('address','fe80::1%eth0'),('device','*'),('duration',16),('duration',True),('packets',101),('port',0),('protocol','tcp -A')])
def test_validation_and_injection(key,value):
    s=spec();s[key]=value
    with pytest.raises((ValueError,TypeError)):validate(s)

def test_structured_filter_only():
    c=command(spec());assert c[0]=='/usr/bin/tcpdump';assert c[-1]=='( host 192.0.2.10 ) and tcp and port 41000';assert '-A' not in c and '-X' not in c and c[c.index('-w')+1]=='-'

def test_drop_empty_truncated_unknown():
    assert statistics('')=={'captured':None,'received_by_filter':None,'dropped_by_kernel':None}
    assert statistics('0 packets captured\n8 packets received by filter\n3 packets dropped by kernel\n')['dropped_by_kernel']==3
    p=Parser(0);p.feed(pcap(packet()));assert p.truncated and not p.rows
    p=Parser();p.feed(pcap(packet())[:-5]);assert p.buffer and not p.rows
    assert packet_metadata(b'unknown',999,0,7) is None

class Fake:
    def __init__(self):self.calls=0;self.release=asyncio.Event()
    async def run(self,site,spec,ready,cancel):
        self.calls+=1;ready.set_result({'status':'ready'});await cancel.wait()
        return {'status':'cancelled','metadata':[],'statistics':{'dropped_by_kernel':None}}

@pytest.fixture
def manager(approved_config):
    c,_=approved_config;c=c.model_copy(update={'capture_enabled':True});f=Fake();return CaptureManager(c,f),f

async def test_ready_cancel_no_replay_and_concurrency(manager):
    m,f=manager;p=m.preview('Router A',spec());r=await m.start(p['plan_id']);assert r['status']=='ready'
    other=m.preview('router-a',spec())
    with pytest.raises(ValueError,match='concurrency'):await m.start(other['plan_id'])
    assert m.cancel(p['plan_id'])['status']=='cancellation_requested'
    await m.jobs[p['plan_id']]['task'];assert m.status(p['plan_id'])['result']['status']=='cancelled'
    await m.start(p['plan_id']);assert f.calls==1

async def test_altered_scope_and_expiry(manager,monkeypatch):
    m,f=manager;p=m.preview('router-a',spec());m.plans[p['plan_id']]['spec']['port']=1
    with pytest.raises(ValueError,match='changed'):await m.start(p['plan_id'])
    p=m.preview('router-a',spec());monkeypatch.setattr(time,'time',lambda:p['expires_at']+1)
    with pytest.raises(ValueError,match='expired'):await m.start(p['plan_id'])
    assert f.calls==0

def test_capture_gate_fixed_privilege_boundary():
    from test_vpn_only_gate import PIN
    import hashlib
    s=importlib.util.spec_from_file_location('capture_gate',Path(__file__).parents[1]/'scripts/capture_ssh_gate.py');g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
    cmd=capture_command();pin=hashlib.sha256(shlex.split(cmd)[-1].encode()).hexdigest()
    assert g.validated(cmd,PIN,PIN,capture_digest=pin)[0][:2]==['sudo','-n']
    for bad in (cmd.replace("'22'",'23') if "'22'" in cmd else cmd.replace(' 22 ',' 23 '),cmd+' extra',cmd.replace('python3 -I','python3')):
        with pytest.raises(ValueError):g.validated(bad,PIN,PIN,capture_digest=pin)

@pytest.mark.parametrize('mode',['empty','cancel','permission','packet'])
def test_real_helper_process_cleanup_with_fake_tcpdump(tmp_path,mode):
    import os,sys,subprocess,base64,socket
    binary=tmp_path/'tcpdump';pidfile=tmp_path/'pid'
    binary.write_text('#!'+sys.executable+'\n'+f'''import os,sys,signal,time,base64
open({str(pidfile)!r},'w').write(str(os.getpid()))
def stop(*a):
 sys.stderr.write('0 packets captured\\n0 packets received by filter\\n0 packets dropped by kernel\\n');sys.stderr.flush();sys.exit(0)
signal.signal(signal.SIGINT,stop)
if {mode!r}=='permission':
 sys.stderr.write('Permission denied SECRET_DO_NOT_RETURN\\n');sys.exit(1)
sys.stderr.write('listening on test, link-type EN10MB\\n');sys.stderr.flush()
raw=base64.b64decode({base64.b64encode(pcap(packet()) if mode=='packet' else pcap(packet())[:24]).decode()!r})
sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
while True:time.sleep(.02)
''');binary.chmod(0o755)
    env={**os.environ,'PATH':str(tmp_path)+':'+os.environ['PATH']}
    helper=Path(__file__).parents[1]/'src/firewalla_mcp/capture_helper.py'
    wrapper="import importlib.util; s=importlib.util.spec_from_file_location('capture_helper',"+repr(str(helper))+"); h=importlib.util.module_from_spec(s); s.loader.exec_module(h); original=h.command; h.command=lambda spec:["+repr(str(binary))+"]+original(spec)[1:]; h.main()"
    child=subprocess.Popen([sys.executable,'-c',wrapper],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    request=spec();request.update(interface=socket.if_nameindex()[0][1],duration=1)
    child.stdin.write(json.dumps(request).encode()+b'\n');child.stdin.flush()
    first=json.loads(child.stdout.readline())
    if mode=='permission':result=first
    else:
        assert first['event']=='ready'
        if mode=='cancel':child.stdin.write(b'cancel\n');child.stdin.flush()
        result=json.loads(child.stdout.readline())
    child.wait(timeout=5)
    assert 'SECRET' not in json.dumps(result) and 'PASSWORD' not in json.dumps(result)
    if mode=='permission':assert result['status']=='permission_denied' and not result['ready']
    elif mode=='cancel':assert result['status']=='cancelled'
    elif mode=='packet':assert len(result['metadata'])==1
    else:assert result['metadata']==[] and result['statistics']['dropped_by_kernel']==0
    pid=int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):os.kill(pid,0)


def test_invalid_existing_interface_before_start(monkeypatch):
    from firewalla_mcp.capture_helper import capture
    monkeypatch.setattr('socket.if_nameindex',lambda:[(1,'lo')])
    with pytest.raises(ValueError,match='absent'):capture(spec())

async def test_transport_timeout_cleanup_without_real_ssh(monkeypatch):
    from firewalla_mcp import capture as module
    class Writer:
        def write(self,x):pass
        async def drain(self):pass
        def is_closing(self):return False
        def close(self):pass
    class Process:
        returncode=None
        stdin=Writer()
        async def wait(self):self.returncode=0
    process=Process()
    async def create(*a,**kw):return process
    class Deadline:
        async def __aenter__(self):raise asyncio.TimeoutError()
        async def __aexit__(self,*a):pass
    monkeypatch.setattr(module.asyncio,'create_subprocess_exec',create)
    monkeypatch.setattr(module.asyncio,'timeout',lambda _:Deadline())
    from firewalla_mcp.models import Site
    site=Site(host='192.0.2.1',identity_file='/none',known_hosts_file='/none',vantage_group='test')
    future=asyncio.get_running_loop().create_future()
    result=await module.CaptureTransport().run(site,spec(),future,asyncio.Event())
    assert result['status']=='transport_timeout_or_cancelled' and process.returncode==0 and future.done()

async def test_global_capture_limit_and_catalog(manager):
    from firewalla_mcp.server import build_server
    m,f=manager;m.config.sites['router-b']=m.config.sites['router-a'].model_copy();m.config.sites['router-c']=m.config.sites['router-a'].model_copy()
    a=m.preview('router-a',spec());b=m.preview('router-b',spec());c=m.preview('router-c',spec())
    await m.start(a['plan_id']);await m.start(b['plan_id'])
    with pytest.raises(ValueError,match='concurrency'):await m.start(c['plan_id'])
    for p in (a,b):m.cancel(p['plan_id']);await m.jobs[p['plan_id']]['task']
    tools={t.name:t for t in await build_server(m.config,vpn_write_catalog=True).list_tools()}
    assert {'preview_capture','start_capture','capture_status','cancel_capture'}<=set(tools)
    assert tools['start_capture'].annotations.readOnlyHint is False


def test_oversized_pcap_rejected():
    raw=pcap(packet());bad=raw[:32]+struct.pack('<I',100000)+raw[36:]
    with pytest.raises(ValueError,match='bound'):Parser().feed(bad)


def test_vlan_and_short_vlan_header():
    raw=packet()
    tagged=raw[:12]+b'\x81\x00\x00\x01'+raw[12:]
    row=packet_metadata(tagged,1,1,len(tagged))
    assert row['destination_port']==41000 and row['tcp_flags']==['SYN','ACK']
    assert packet_metadata(tagged[:16],1,1,100) is None
