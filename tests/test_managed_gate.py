import importlib.util
from pathlib import Path
import pytest
from test_vpn_only_gate import command,PIN
s=importlib.util.spec_from_file_location('managed_gate',Path(__file__).parents[1]/'scripts/managed_ssh_gate.py')
g=importlib.util.module_from_spec(s);s.loader.exec_module(g)

@pytest.mark.parametrize('kind,feature',[('managed_feature','adblock'),('managed_feature','safeSearch'),('managed_scoped','unbound'),('managed_rule',None)])
def test_reviewed_kind_only(kind,feature):
    assert g.validated(command('managed_write',{'spec':{'kind':kind,'feature':feature},'mode':'preview'}),PIN,PIN)[1] is None

@pytest.mark.parametrize('kind,feature',[('managed_feature','doh'),('managed_scoped','ntp_redirect'),('route',None),('managed_other',None)])
def test_no_unreviewed_permission(kind,feature):
    with pytest.raises(ValueError):g.validated(command('managed_write',{'spec':{'kind':kind,'feature':feature},'mode':'apply'}),PIN,PIN)
