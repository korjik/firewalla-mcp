"""Run only inside a disposable Docker --network none namespace with NET_ADMIN."""
from firewalla_mcp.remote import write_operation, run
from pathlib import Path
import json


def roundtrip(spec):
    before=write_operation({'mode':'preview','spec':spec})
    assert not before['present']
    result=write_operation({'mode':'apply','spec':spec,'expected':before['fingerprint']})
    assert result['outcome']=='applied',result
    verified=write_operation({'mode':'preview','spec':spec})
    assert verified['present'] and verified==result['state']
    conflict=write_operation({'mode':'apply','spec':spec,'expected':verified['fingerprint']})
    assert conflict['outcome']=='already_present' and conflict['changed'] is False
    stale=write_operation({'mode':'rollback','spec':spec,'expected':before['fingerprint']})
    assert stale['outcome']=='stale'
    result=write_operation({'mode':'rollback','spec':spec,'expected':result['state']['fingerprint']})
    assert result['outcome']=='rolled_back',result
    after=write_operation({'mode':'preview','spec':spec})
    assert before==after

run(['iptables','-N','MCP_TEST'])
run(['iptables','-t','nat','-N','MCP_NAT_TEST'])
roundtrip(dict(kind='route',destination='192.0.2.0/24',table=42420,route_type='blackhole',gateway=None,interface=None))
# Custom names must not hide routes from numeric-table conflict checks.
# This file exists only in the disposable network-none container.
table_file=Path('/etc/iproute2/rt_tables')
original=table_file.read_text()
try:
    table_file.write_text(original+'\n42420 mcp_test_table\n')
    host_spec=dict(kind='route',destination='192.0.2.254/32',table=42420,route_type='blackhole',gateway=None,interface=None)
    run(['ip','-4','route','add','blackhole','192.0.2.254/32','table','42420','proto','static'])
    named=json.loads(run(['ip','-4','-j','route','show','table','all']))
    numeric=json.loads(run(['ip','-4','-N','-j','route','show','table','all']))
    assert any(r.get('table')=='mcp_test_table' and r.get('dst')=='192.0.2.254' for r in named),named
    assert any(str(r.get('table'))=='42420' and r.get('dst')=='192.0.2.254' for r in numeric),numeric
    existing=write_operation({'mode':'preview','spec':host_spec})
    assert existing['present']
    assert write_operation({'mode':'apply','spec':host_spec,'expected':existing['fingerprint']})['outcome']=='already_present'
    run(['ip','-4','route','del','blackhole','192.0.2.254/32','table','42420','proto','static'])
    roundtrip(host_spec)
    roundtrip({**host_spec,'destination':'0.0.0.0/0'})
finally:
    table_file.write_text(original)
roundtrip(dict(kind='filter_rule',chain='MCP_TEST',source='192.0.2.0/24',destination='198.51.100.0/24',protocol='tcp',destination_port=443,action='DROP'))
roundtrip(dict(kind='dnat',chain='MCP_NAT_TEST',public_address='203.0.113.1',interface='lo',protocol='tcp',external_port=443,destination_address='192.0.2.2',destination_port=443))
run(['iptables','-X','MCP_TEST'])
run(['iptables','-t','nat','-X','MCP_NAT_TEST'])
print('Isolated kernel /24, /32, default and named-table conflicts, route/filter/DNAT apply and rollback: PASS')
