import json
import os

import pytest

from firewalla_mcp.vpn_import import ImportBlocked
from test_vpn_import import profile, sandbox, approve  # noqa: F401


def test_journal_failure_occurs_before_secret_write(sandbox, monkeypatch):
    root, tool, target, _ = sandbox
    plan = tool.plan('source', [target])
    approve(root, plan)
    save = tool.save
    observed = []
    def fail_entry_save(tx, journal):
        if journal['entries']:
            staged = root / '.mcp-import' / journal['entries'][-1]['staged']
            observed.append(staged.read_bytes())
            raise OSError('synthetic sensitive failure')
        return save(tx, journal)
    monkeypatch.setattr(tool, 'save', fail_entry_save)
    with pytest.raises(ImportBlocked, match='interrupted'):
        tool.apply(plan['transaction'])
    assert observed == [b'']
    assert not list((root / '.mcp-import').glob(plan['transaction'] + '-*'))
    monkeypatch.setattr(tool, 'save', save)
    rollback = tool.rollback_plan(plan['transaction'])
    approve(root, rollback, 'rollback')
    tool.rollback(plan['transaction'])


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='POSIX crash-recovery test')
def test_process_death_during_credential_write_recovers_exact_inode(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan('source', [target])
    approve(root, plan)
    pid = os.fork()
    if pid == 0:
        original = os.fdopen
        class CrashWriter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, data):
                self.stream.write(data[:3])
                self.stream.flush()
                os.fsync(self.stream.fileno())
                os._exit(73)
        def fdopen(fd, *args, **kwargs):
            stream = original(fd, *args, **kwargs)
            name = os.readlink('/proc/self/fd/' + str(fd))
            return CrashWriter(stream) if name.endswith('-target_a.userpass') else stream
        os.fdopen = fdopen
        try:
            tool.apply(plan['transaction'])
        except BaseException:
            os._exit(74)
        os._exit(75)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 73
    stage = root / '.mcp-import'
    journal = json.loads((stage / (plan['transaction'] + '.json')).read_text())
    assert len(journal['entries']) == 1
    entry = journal['entries'][0]
    partial = stage / entry['staged']
    assert partial.stat().st_ino == entry['fingerprint']['ino']
    assert partial.stat().st_size == 3
    unrelated = stage / 'another_transaction.userpass'
    unrelated.write_bytes(b'synthetic unrelated')
    unrelated.chmod(0o600)
    rollback = tool.rollback_plan(plan['transaction'])
    approve(root, rollback, 'rollback')
    tool.rollback(plan['transaction'])
    assert not partial.exists()
    assert unrelated.read_bytes() == b'synthetic unrelated'
    assert not list(root.glob('target_*'))


def test_staging_cleanup_refuses_replacement(sandbox):
    root, tool, _, _ = sandbox
    stage = root / '.mcp-import'
    original = stage / 'owned'
    original.write_bytes(b'original')
    original.chmod(0o600)
    info = original.stat()
    moved = stage / 'retained_inode'
    original.rename(moved)
    original.write_bytes(b'foreign')
    original.chmod(0o600)
    with pytest.raises(ImportBlocked, match='ownership changed'):
        tool.remove_owned_stage('owned', info.st_dev, info.st_ino, 8)
    assert original.read_bytes() == b'foreign'


def test_journal_rename_failure_removes_only_its_temporary_file(sandbox, monkeypatch):
    root, tool, target, _ = sandbox
    plan = tool.plan('source', [target])
    journal = tool.load(plan['transaction'])
    def fail(*args, **kwargs):
        raise OSError('synthetic rename failure')
    monkeypatch.setattr(os, 'rename', fail)
    with pytest.raises(OSError):
        tool.save(plan['transaction'], journal)
    assert not list((root / '.mcp-import').glob(plan['transaction'] + '.new-*'))
    assert (root / '.mcp-import' / (plan['transaction'] + '.json')).exists()
