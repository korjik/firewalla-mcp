import asyncio
import json
import sys
from unittest.mock import AsyncMock
import pytest
from pydantic import ValidationError
from firewalla_mcp.models import Config, Site
from firewalla_mcp.server import build_server
from firewalla_mcp.transport import SSHTransport, bounded_read, ssh_argv, remote_command
from firewalla_mcp import remote

@pytest.fixture
def config():
    common = dict(host="192.0.2.1", identity_file="/secrets/key", known_hosts_file="/secrets/known_hosts", probe_networks=["192.0.2.0/24"])
    return Config(sites={"router-a": Site(**common, vantage_group="a"), "router-b": Site(**common, vantage_group="b")})

@pytest.mark.parametrize("value", ["-oProxyCommand=id", "example.org", "192.0.2.1;id", "$(id)", "192.0.2.1\n"])
def test_config_injection(value, config):
    data=config.model_dump(); data["sites"]["router-a"]["host"]=value
    with pytest.raises(ValidationError): Config.model_validate(data)

@pytest.mark.parametrize("bad", [0, 65536, True, "80;id", "$(id)"])
async def test_invalid_port(bad, config):
    transport=AsyncMock(); server=build_server(config, transport)
    with pytest.raises(Exception):
        await server.call_tool("tcp_probe", {"box_name":"router-a", "address":"192.0.2.2", "port":bad})
    transport.run.assert_not_called()

async def test_probe_scope(config):
    server=build_server(config, AsyncMock())
    with pytest.raises(Exception):
        await server.call_tool("tcp_probe", {"box_name":"router-a", "address":"198.51.100.1", "port":80})

async def test_unknown_box(config):
    t=AsyncMock(); server=build_server(config,t)
    with pytest.raises(Exception): await server.call_tool("system_health", {"box_name":"absent"})
    t.run.assert_not_called()

def test_ssh_host_verification(config):
    argv=ssh_argv(config.sites["router-a"], "true")
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentityAgent=none" in argv
    assert argv[1:3]==["-F","/dev/null"]
    assert "PasswordAuthentication=no" in argv

async def test_output_bound():
    stream=asyncio.StreamReader(); stream.feed_data(b"x"*140000); stream.feed_eof()
    with pytest.raises(ValueError): await bounded_read(stream)

def test_remote_timeout():
    with pytest.raises(remote.Unsupported): remote.run([sys.executable,"-c","import time;time.sleep(2)"],.02)

def test_remote_output_limit():
    with pytest.raises(remote.Unsupported): remote.run([sys.executable,"-c","print('x'*140000)"])

def test_error_secrets_suppressed(monkeypatch):
    def fail(*a,**k): raise remote.Unsupported("password=secret token=secret")
    monkeypatch.setattr(remote,"run",fail)
    result=remote.execute("mappings",{})
    assert result["status"]=="unsupported"
    assert "secret" not in json.dumps(result)

@pytest.mark.parametrize("raw", ['{}', '[]', '{"maps":"new-version"}', '{"maps":[{"protocol":"other"}]}'])
def test_unsupported_schema(raw,monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:raw)
    assert remote.execute("mappings",{})["status"]=="unsupported"

def test_mapping_projection(monkeypatch):
    row=dict(protocol="tcp",dport="50000-51000",toIP="192.0.2.8",toPort=50500, password="secret",description="private name",token="secret")
    monkeypatch.setattr(remote,"run",lambda *a,**k:json.dumps({"maps":[row],"credential":"secret"}))
    result=remote.execute("mappings",{})
    assert result["status"]=="ok"
    assert result["data"]["configured_mappings"][0]["external_ports"]==[50000,51000]
    assert "secret" not in json.dumps(result) and "private name" not in json.dumps(result)

def test_network_projection(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:json.dumps([dict(ifname="eth0",ifalias="password secret",linkinfo={"info_kind":"vlan","info_data":{"id":42}}, token="secret")]))
    result=remote.network("interfaces")
    assert result["rows"][0]["vlan_id"]==42
    assert "secret" not in json.dumps(result)

@pytest.mark.parametrize("name", ["-h", "x;id", "x\nwhoami", "$(id)", "a..b", "a"*254])
def test_dns_injection(name, monkeypatch):
    def fail(*a,**k): pytest.fail("must not execute")
    monkeypatch.setattr(remote,"run",fail)
    assert remote.execute("dns",{"name":name})["status"]=="unsupported"

def test_tcp_timeout_not_closed(monkeypatch):
    def fail(*a,**k): raise remote.Unsupported("timeout")
    monkeypatch.setattr(remote,"run",fail)
    assert remote.dispatch("tcp",{"address":"192.0.2.1","port":80})["outcome"]=="inconclusive"

async def test_diagnose_independent_success(config):
    class Fake:
        async def run(self,site,op,args):
            return {"status":"ok","data":{"outcome":"connected" if site.vantage_group=="b" else "inconclusive"}}
    server=build_server(config,Fake())
    result=await server.call_tool("diagnose_port_forward",dict(box_name="router-a",device_address="192.0.2.8",service_port=50500,vpn_interface="tun0",provider_port=50500,public_address="192.0.2.9",external_box="router-b"))
    assert "reachable_from_independent_vantage" in str(result)
    assert "unsupported" in str(result)

async def test_transport_timeout_kills(monkeypatch,config):
    process=AsyncMock(); process.returncode=None
    process.kill=lambda: setattr(process,"returncode",-9)
    process.stdout.read.side_effect=TimeoutError
    monkeypatch.setattr(asyncio,"create_subprocess_exec",AsyncMock(return_value=process))
    result=await SSHTransport().run(config.sites["router-a"],"health",{})
    assert result["status"]=="unavailable" and process.returncode==-9

async def test_catalog(config):
    tools=await build_server(config).list_tools()
    assert len(tools)==46
    assert all(t.annotations.readOnlyHint for t in tools if t.name != "apply_change")
    assert next(t for t in tools if t.name == "apply_change").annotations.destructiveHint
    assert not any("shell" in t.name for t in tools)

def test_quoting():
    import shlex
    command=remote_command("dns",{"name":"x';id"})
    argv=shlex.split(command)
    assert argv[:4]==["timeout","20","python3","-c"]
    assert json.loads(argv[-1])["arguments"]["name"]=="x';id"

def test_inventory_projection(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:"64\nhost:mac:02:00:00:00:00:01\n")
    assert remote.dispatch("inventory",{"cursor":"0"})["macs"]==["02:00:00:00:00:01"]

def test_device_policy_redaction(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:json.dumps({"state":True,"profileId":"vpn-test","password":"secret"}))
    result=remote.dispatch("device_policy",{"mac":"02:00:00:00:00:01"})
    assert "secret" not in json.dumps(result) and "unknown" in result["effective_path"]

def test_traffic_counters(monkeypatch):
    stats={direction:{k:10 for k in ("bytes","packets","errors","dropped")} for direction in ("rx","tx")}
    monkeypatch.setattr(remote,"run",lambda *a,**k:json.dumps([{"ifname":"eth0","stats64":stats,"credential":"secret"}]))
    assert remote.dispatch("traffic",{})["interfaces"][0]["rx"]["bytes"]==10

def test_alarm_count(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda argv,**k:"zset" if "TYPE" in argv else "7")
    assert remote.dispatch("alarm_count",{"seconds":3600})["active_alarm_count"]==7

def test_conntrack_projection(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:"tcp 6 5 ESTABLISHED src=192.0.2.2 dst=203.0.113.1 sport=1234 dport=443 src=203.0.113.1 dst=192.0.2.2 sport=443 dport=1234 secret=hidden\n")
    result=remote.dispatch("conntrack",{"address":"192.0.2.2"})
    assert len(result["connections"][0]["tuples_in_kernel_order"])==8
    assert "hidden" not in json.dumps(result)

@pytest.mark.parametrize("operation,args",[("inventory",{"cursor":"0;id"}),("alarm_count",{"seconds":0}),("device_policy",{"mac":";id"}),("conntrack",{"address":";id"})])
def test_added_adapter_validation(operation,args,monkeypatch):
    def fail(*a,**k): pytest.fail("no command should run")
    monkeypatch.setattr(remote,"run",fail)
    assert remote.execute(operation,args)["status"]=="unsupported"

def test_inventory_empty_nonterminal(monkeypatch):
    monkeypatch.setattr(remote,"run",lambda *a,**k:"64\n\n")
    assert remote.dispatch("inventory",{"cursor":"0"})["macs"]==[]

def test_alarm_fields_only(monkeypatch):
    commands=[]
    def read(argv):
        commands.append(argv)
        if 'TYPE' in argv:return 'zset'
        if 'ZREVRANGE' in argv:return '12\n'
        return 'ALARM_NEW_DEVICE\n1700000000\n\n'
    monkeypatch.setattr(remote,'run',read)
    result=remote.dispatch('alarm_summaries',{'limit':3})
    assert result['records'][0]['type']=='ALARM_NEW_DEVICE'
    assert commands[-1][-3:]==['type','timestamp','alarmTimestamp']
    assert not any('HGETALL' in x for x in commands)

def test_policy_selected_fields(monkeypatch):
    def read(argv):
        if 'TYPE' in argv:return 'zset'
        if 'ZREVRANGE' in argv:return '42\n'
        return 'ip\nblock\n1\ninbound\n'
    monkeypatch.setattr(remote,'run',read)
    result=remote.dispatch('policy_summaries',{'limit':3})
    assert result['records'][0]['disabled'] is True

def test_flow_aggregation_redacts(monkeypatch):
    flows=[dict(ob=10,rb=20,lh='192.0.2.2',sh='192.0.2.2',pr='tcp',token='secret',af={'private.example':{}}),dict(ob=5,rb=7,lh='192.0.2.2',sh='203.0.113.2',pr='udp')]
    monkeypatch.setattr(remote,'run',lambda a:'zset' if 'TYPE' in a else '\n'.join(json.dumps(f) for f in flows))
    result=remote.dispatch('flow_sample',{'limit':20})
    assert result['sample_upload_bytes']==17 and result['sample_download_bytes']==25
    assert 'secret' not in json.dumps(result) and '192.0.2' not in json.dumps(result) and 'private.example' not in json.dumps(result)

@pytest.mark.parametrize('op',['flow_sample','alarm_summaries','policy_summaries'])
def test_sample_limits(op,monkeypatch):
    monkeypatch.setattr(remote,'run',lambda a:pytest.fail('must not read'))
    assert remote.execute(op,{'limit':0})['status']=='unsupported'

def test_unknown_flow_schema(monkeypatch):
    monkeypatch.setattr(remote,'run',lambda a:'zset' if 'TYPE' in a else '{"password":"secret"}')
    result=remote.execute('flow_sample',{'limit':1})
    assert result['status']=='unsupported' and 'secret' not in json.dumps(result)
