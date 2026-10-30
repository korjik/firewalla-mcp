import os
import time

import pytest

from firewalla_mcp.vpn_import import InactiveImport, ImportBlocked, fresh_profile_id, profile_id
from test_vpn_import import profile, sandbox, approve  # noqa: F401


def absent_instances(ids):
    return {i: {"inactive": True, "unreferenced": True, "administrative_intent": "not_instantiated"} for i in ids}


@pytest.mark.parametrize('bad', ['target-a', 'abcdefghijk', '../abc', 'a b'])
def test_upstream_profile_ids(bad):
    with pytest.raises(ImportBlocked):
        profile_id(bad)


def test_upstream_profile_id_boundary():
    assert profile_id('A_b0123456') == 'A_b0123456'
    assert profile_id('_') == '_'
    candidate = fresh_profile_id()
    assert len(candidate) == 10 and profile_id(candidate) == candidate


@pytest.mark.parametrize('symlink', [False, True])
def test_optional_source_password_appearance_blocks_before_approval(sandbox, symlink):
    root, tool, target, _ = sandbox
    (root / 'source.password').unlink()
    plan = tool.plan('source', [target])
    approve(root, plan)
    if symlink:
        (root / 'source.password').symlink_to('missing')
    else:
        (root / 'source.password').write_bytes(b'synthetic-new-secret')
        (root / 'source.password').chmod(0o600)
    with pytest.raises(ImportBlocked, match='absent source file appeared'):
        tool.apply(plan['transaction'])
    assert not (root / 'target_a.ovpn').exists()
    assert (root / '.mcp-import' / (plan['transaction'] + '.approval')).exists()


def test_strict_mode_still_rejects_absent_instance(sandbox):
    _, tool, target, _ = sandbox
    tool.probe = absent_instances
    with pytest.raises(ImportBlocked):
        tool.plan('source', [target])


def test_maintenance_new_id_apply_and_rollback(sandbox):
    root, _, target, _ = sandbox
    window = {'nonce': '1' * 32, 'expires': int(time.time()) + 300}
    tool = InactiveImport(root, absent_instances, maintenance_window=window)
    try:
        target = {**target, 'id': fresh_profile_id()}
        plan = tool.plan('source', [target])
        assert plan['maintenance']['atomic_guarantee'] is False
        assert 'no concurrent' in plan['maintenance']['owner_condition']
        approve(root, plan)
        assert tool.apply(plan['transaction'])['state'] == 'imported_inactive'
        rollback = tool.rollback_plan(plan['transaction'])
        approve(root, rollback, 'rollback')
        assert tool.rollback(plan['transaction'])['state'] == 'rolled_back'
    finally:
        tool.close()


def test_maintenance_window_drift_and_expiry(sandbox):
    root, _, target, _ = sandbox
    clock = [1000]
    tool = InactiveImport(root, absent_instances, clock=lambda: clock[0],
                          maintenance_window={'nonce': '1' * 32, 'expires': 1300})
    try:
        target = {**target, 'id': fresh_profile_id()}
        plan = tool.plan('source', [target])
        approve(root, plan)
        tool.maintenance_window['nonce'] = '2' * 32
        with pytest.raises(ImportBlocked, match='policy changed'):
            tool.apply(plan['transaction'])
        tool.maintenance_window['nonce'] = '1' * 32
        clock[0] = 1301
        with pytest.raises(ImportBlocked, match='expired'):
            tool.apply(plan['transaction'])
        assert not (root / (target['id'] + '.ovpn')).exists()
    finally:
        tool.close()


def test_post_publication_state_change_keeps_files_for_review(sandbox, monkeypatch):
    root, _, target, _ = sandbox
    changed = [False]
    def probe(ids):
        result = absent_instances(ids)
        if changed[0]:
            for row in result.values():
                row['unreferenced'] = False
        return result
    tool = InactiveImport(root, probe, maintenance_window={'nonce': '1' * 32, 'expires': int(time.time()) + 300})
    try:
        target = {**target, 'id': fresh_profile_id()}
        plan = tool.plan('source', [target])
        approve(root, plan)
        real_link = os.link
        def racing_link(src, dst, **kwargs):
            real_link(src, dst, **kwargs)
            if dst.endswith('.ovpn'):
                changed[0] = True
        monkeypatch.setattr(os, 'link', racing_link)
        with pytest.raises(ImportBlocked, match='interrupted'):
            tool.apply(plan['transaction'])
        assert (root / (target['id'] + '.ovpn')).exists()
        with pytest.raises(ImportBlocked):
            tool.rollback_plan(plan['transaction'])
        assert (root / (target['id'] + '.userpass')).exists()
    finally:
        tool.close()
