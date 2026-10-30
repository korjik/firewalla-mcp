import hashlib,importlib.util
import pytest
spec=importlib.util.spec_from_file_location('once','scripts/one_shot_import_gate.py');once=importlib.util.module_from_spec(spec);spec.loader.exec_module(once)


def options(tmp_path):
    tmp_path.chmod(0o700);p=tmp_path/'helper.py';p.write_text('print("synthetic")\n');p.chmod(0o600)
    return dict(nonce='a'*32,helper_path=str(p),helper_digest=hashlib.sha256(p.read_bytes()).hexdigest(),deadline=1300,used_path=str(tmp_path/'used'),now=1000)


def test_exact_once_pinned_source(tmp_path):
    args=options(tmp_path);cmd='firewalla-import-once '+'a'*32
    result=once.one_shot_command(cmd,**args)
    assert result[:3]==['timeout','110','python3'] and result[-1]=='1300'
    with pytest.raises(FileExistsError):once.one_shot_command(cmd,**args)


@pytest.mark.parametrize('command',['sh','firewalla-import-once wrong','firewalla-import-once '+'a'*32+' extra','firewalla-import-once '+'a'*32+'; id'])
def test_other_commands_rejected(tmp_path,command):
    args=options(tmp_path)
    with pytest.raises(ValueError):once.one_shot_command(command,**args)
    assert not (tmp_path/'used').exists()


@pytest.mark.parametrize('change',['digest','expired','long_window','permissions','symlink'])
def test_hash_window_file_guards(tmp_path,change):
    args=options(tmp_path)
    if change=='digest':args['helper_digest']='0'*64
    if change=='expired':args['now']=1300
    if change=='long_window':args['deadline']=1700
    if change=='permissions':(tmp_path/'helper.py').chmod(0o644)
    if change=='symlink':
        (tmp_path/'helper.py').rename(tmp_path/'real');(tmp_path/'helper.py').symlink_to(tmp_path/'real')
    with pytest.raises((ValueError,OSError)):once.one_shot_command('firewalla-import-once '+'a'*32,**args)
    assert not (tmp_path/'used').exists()
