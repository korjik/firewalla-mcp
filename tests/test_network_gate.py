import importlib.util
from pathlib import Path
import pytest
from test_vpn_only_gate import command,PIN
from firewalla_mcp.transport import remote_command
from test_network_workflow import spec
specification=importlib.util.spec_from_file_location('network_gate',Path(__file__).parents[1]/'scripts/network_ssh_gate.py')
gate=importlib.util.module_from_spec(specification);specification.loader.exec_module(gate)

def test_narrow_network_gate():
    assert gate.validated(command('managed_workflow_state',{}),PIN,PIN)[1] is None
    for kind in ('managed_forward','managed_forward_batch'):
        assert gate.validated(command('managed_write',{'spec':{'kind':kind},'mode':'apply'}),PIN,PIN)[1] is None
    for kind in ('managed_feature','managed_rule','managed_scoped','route','dnat','vpn_workflow'):
        with pytest.raises(ValueError):gate.validated(command('managed_write',{'spec':{'kind':kind},'mode':'apply'}),PIN,PIN)
    with pytest.raises(ValueError):gate.validated(command('write',{}),PIN,PIN)

def test_real_helper_command_stays_within_ssh_argument_bound():
    assert len(remote_command('managed_workflow_state',{'revision':'a'*40,'spec':spec()}).encode())<131072
