"""Run only inside a disposable Docker --network none namespace with NET_ADMIN."""
from firewalla_mcp.remote import write_operation, run


def roundtrip(spec):
    before=write_operation({'mode':'preview','spec':spec})
    assert not before['present']
    result=write_operation({'mode':'apply','spec':spec,'expected':before['fingerprint']})
    assert result['outcome']=='applied',result
    stale=write_operation({'mode':'rollback','spec':spec,'expected':before['fingerprint']})
    assert stale['outcome']=='stale'
    result=write_operation({'mode':'rollback','spec':spec,'expected':result['state']['fingerprint']})
    assert result['outcome']=='rolled_back',result
    after=write_operation({'mode':'preview','spec':spec})
    assert before==after

run(['iptables','-N','MCP_TEST'])
run(['iptables','-t','nat','-N','MCP_NAT_TEST'])
roundtrip(dict(kind='route',destination='192.0.2.0/24',table=42420,route_type='blackhole',gateway=None,interface=None))
roundtrip(dict(kind='filter_rule',chain='MCP_TEST',source='192.0.2.0/24',destination='198.51.100.0/24',protocol='tcp',destination_port=443,action='DROP'))
roundtrip(dict(kind='dnat',chain='MCP_NAT_TEST',public_address='203.0.113.1',interface='lo',protocol='tcp',external_port=443,destination_address='192.0.2.2',destination_port=443))
run(['iptables','-X','MCP_TEST'])
run(['iptables','-t','nat','-X','MCP_NAT_TEST'])
print('Isolated kernel route/filter/DNAT apply, stale rejection and rollback: PASS')
