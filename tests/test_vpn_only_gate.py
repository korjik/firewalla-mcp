import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import zipfile
import pytest

spec=importlib.util.spec_from_file_location('vpn_only_gate',Path(__file__).parents[1]/'scripts/vpn_only_ssh_gate.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
CODE='print("synthetic")';PIN=hashlib.sha256(CODE.encode()).hexdigest()


def command(operation,args,timeout='20'):
    return shlex.join(['timeout',timeout,'python3','-c',CODE,json.dumps(dict(operation=operation,arguments=args))])


def test_read_and_only_two_write_kinds():
    assert gate.validated(command('health',{}),PIN,PIN)[1] is None
    for kind,timeout in [('managed_vpn','20'),('managed_lifecycle','110')]:
        for mode in ('preview','apply','rollback'):
            assert gate.validated(command('managed_write',dict(spec={'kind':kind},mode=mode),timeout),PIN,PIN)[1] is None
    for kind in ('managed_rule','managed_feature','managed_scoped','dnat','route'):
        with pytest.raises(ValueError):gate.validated(command('managed_write',dict(spec={'kind':kind},mode='apply')),PIN,PIN)
    for operation in ('write','shell','reboot'):
        with pytest.raises(ValueError):gate.validated(command(operation,{}),PIN,PIN)


@pytest.mark.parametrize('text',['firewalla-vpn-import-v1 extra','firewalla-vpn-import-v1; id','python3 -c pass','', 'x'*131073])
def test_no_extra_commands(text):
    with pytest.raises(ValueError):gate.validated(text,PIN,PIN)


def test_wrong_helper_and_deadline_rejected():
    with pytest.raises(ValueError):gate.validated(command('health',{}),'0'*64,PIN)
    with pytest.raises(ValueError):gate.validated(command('health',{},'110'),PIN,PIN)
    with pytest.raises(ValueError):gate.validated(command('managed_write',dict(spec={'kind':'managed_lifecycle'},mode='apply')),PIN,PIN)


def test_import_executes_verified_inode_even_if_path_replaced(tmp_path):
    tmp_path.chmod(0o700);path=tmp_path/'helper.pyz'
    with zipfile.ZipFile(path,'w') as z:z.writestr('__main__.py','print("verified synthetic helper")')
    path.chmod(0o600);pin=hashlib.sha256(path.read_bytes()).hexdigest()
    argv,fd=gate.validated('firewalla-vpn-import-v1',PIN,pin,str(path))
    try:
        path.unlink();path.write_text('unverified replacement')
        result=subprocess.run(argv,pass_fds=(fd,),capture_output=True,text=True,timeout=10)
        assert result.returncode==0 and result.stdout.strip()=='verified synthetic helper'
    finally:os.close(fd)


def test_import_permissions_and_hash_fail(tmp_path):
    tmp_path.chmod(0o700);path=tmp_path/'helper.pyz';path.write_bytes(b'not zip');path.chmod(0o600)
    with pytest.raises(ValueError):gate.validated('firewalla-vpn-import-v1',PIN,PIN,str(path))
    pin=hashlib.sha256(path.read_bytes()).hexdigest();path.chmod(0o644)
    with pytest.raises(ValueError):gate.validated('firewalla-vpn-import-v1',PIN,pin,str(path))
