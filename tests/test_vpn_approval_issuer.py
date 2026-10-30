import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest

spec = importlib.util.spec_from_file_location('issuer', Path(__file__).parents[1]/'scripts/issue_vpn_approval.py')
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)
PLAN='a'*32
DIGEST='b'*64

@pytest.fixture
def inbox(tmp_path, monkeypatch):
    path=tmp_path/'inbox'; path.mkdir(mode=0o750); path.chmod(0o750)
    original=os.fstat
    def fstat(fd):
        value=original(fd)
        return SimpleNamespace(st_uid=0,st_gid=10001,st_mode=value.st_mode)
    proxy=SimpleNamespace(**{k:getattr(os,k) for k in dir(os) if not k.startswith('__')})
    proxy.geteuid=lambda:0
    proxy.fstat=fstat
    proxy.fchown=lambda *args:None
    monkeypatch.setattr(issuer,'os',proxy)
    monkeypatch.setattr(issuer.time,'time',lambda:1000)
    return path

def test_issue_exact_atomic_document(inbox):
    result=issuer.issue(inbox,PLAN,DIGEST,1100)
    assert result['status']=='issued'
    doc=json.loads((inbox/(PLAN+'.json')).read_text())
    assert doc==dict(plan_id=PLAN,digest=DIGEST,expires_at=1100,approved=True)
    assert (inbox/(PLAN+'.json')).stat().st_mode&0o777==0o640
    assert (inbox/(PLAN+'.json')).stat().st_nlink==1
    assert len(list(inbox.iterdir()))==1

def test_no_overwrite_or_reissue(inbox):
    issuer.issue(inbox,PLAN,DIGEST,1100)
    with pytest.raises(FileExistsError):issuer.issue(inbox,PLAN,'c'*64,1100)
    assert json.loads((inbox/(PLAN+'.json')).read_text())['digest']==DIGEST
    assert len(list(inbox.iterdir()))==1

@pytest.mark.parametrize('plan,digest,expiry',[(PLAN,DIGEST,1000),(PLAN,DIGEST,1601),(PLAN,DIGEST,True),('../x',DIGEST,1100),(PLAN,'x;id',1100)])
def test_invalid_input(inbox,plan,digest,expiry):
    with pytest.raises(ValueError):issuer.issue(inbox,plan,digest,expiry)
    assert not list(inbox.iterdir())

def test_unprivileged_cannot_issue(inbox,monkeypatch):
    monkeypatch.setattr(issuer.os,'geteuid',lambda:10001)
    with pytest.raises(ValueError):issuer.issue(inbox,PLAN,DIGEST,1100)

def test_unsafe_directory_and_symlink(inbox):
    inbox.chmod(0o770)
    with pytest.raises(ValueError):issuer.issue(inbox,PLAN,DIGEST,1100)
    inbox.chmod(0o750)
    link=inbox.parent/'link'; link.symlink_to(inbox)
    with pytest.raises(ValueError):issuer.issue(link,PLAN,DIGEST,1100)

def test_failed_write_leaves_no_approval(inbox,monkeypatch):
    monkeypatch.setattr(issuer.os,'write',lambda *args:0)
    with pytest.raises(OSError):issuer.issue(inbox,PLAN,DIGEST,1100)
    assert not list(inbox.iterdir())
