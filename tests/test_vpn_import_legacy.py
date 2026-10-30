import json
import os
from pathlib import Path

import pytest

from firewalla_mcp.vpn_import import InactiveImport, ImportBlocked, legacy_userpass_allowed
from test_vpn_import import approve, inactive, profile, sandbox  # shared synthetic fixtures only
from test_vpn_import_state import environment
from firewalla_mcp.vpn_import_state import preflight


@pytest.fixture(autouse=True)
def native_root_metadata(monkeypatch):
    # Managed cloud remaps host-root ownership to nobody. Model native Linux root
    # for the two ancestor directories; do not relax the production trust check.
    original = os.lstat
    def checked(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if str(path) in ("/", "/tmp") and result.st_uid == 65534:
            fields = list(result);fields[4] = 0;return os.stat_result(fields)
        return result
    monkeypatch.setattr(os, "lstat", checked)


def legacy_tool(root, source="source"):
    return InactiveImport(root, inactive, legacy_readable_userpass_source=source)


def test_explicit_source_exception_preserves_existing_file(sandbox):
    root, default, target, values = sandbox
    source = root / "source.userpass";source.chmod(0o644)
    before = source.stat()
    with pytest.raises(ImportBlocked, match="permissions"):
        default.plan("source", [target])
    tool = legacy_tool(root)
    try:
        plan = tool.plan("source", [target])
        policy = plan["source_permission_exception"]
        assert policy == {"profile": "source", "suffix": "userpass", "mode": "0644",
                          "owner_uid": os.getuid(), "source_unchanged": True, "destination_mode": "0600"}
        assert "synthetic-password" not in json.dumps(plan)
        approve(root, plan);tool.apply(plan["transaction"])
        assert (root / "target_a.userpass").stat().st_mode & 0o777 == 0o600
        assert (root / "target_a.userpass").read_bytes() == values["userpass"]
        after = source.stat()
        assert (before.st_mode, before.st_uid, before.st_gid, before.st_ino) == (after.st_mode, after.st_uid, after.st_gid, after.st_ino)
        assert source.read_bytes() == values["userpass"]
        rollback = tool.rollback_plan(plan["transaction"]);approve(root, rollback, "rollback");tool.rollback(plan["transaction"])
        assert source.stat().st_mode & 0o777 == 0o644 and source.read_bytes() == values["userpass"]
    finally:
        tool.close()


@pytest.mark.parametrize("mode", [0o640, 0o664, 0o666, 0o646, 0o744, 0o1644])
def test_exception_rejects_other_readable_or_writable_modes(sandbox, mode):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(mode)
    tool = legacy_tool(root)
    try:
        with pytest.raises(ImportBlocked, match="permissions"):
            tool.plan("source", [target])
    finally:
        tool.close()


def test_exception_does_not_cover_other_sources_or_password_file(sandbox):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    tool = legacy_tool(root, "different")
    try:
        with pytest.raises(ImportBlocked):tool.plan("source", [target])
    finally:
        tool.close()
    (root / "source.password").chmod(0o644)
    tool = legacy_tool(root)
    try:
        with pytest.raises(ImportBlocked):tool.plan("source", [target])
    finally:
        tool.close()


def test_exception_rejects_untrusted_parent_at_read_time(sandbox):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    tool = legacy_tool(root)
    parent_mode = root.parent.stat().st_mode & 0o7777
    try:
        root.parent.chmod(0o777)
        with pytest.raises(ImportBlocked):tool.plan("source", [target])
    finally:
        root.parent.chmod(parent_mode);tool.close()


def test_exception_rejects_symlink_hardlink_and_wrong_owner(sandbox, monkeypatch):
    root, _, _, _ = sandbox
    source = root / "source.userpass";source.chmod(0o644)
    assert legacy_userpass_allowed(root, "source")
    uid = os.getuid()
    with monkeypatch.context() as context:
        context.setattr(os, "getuid", lambda: uid + 1)
        assert not legacy_userpass_allowed(root, "source")
    os.link(source, root / "extra")
    assert not legacy_userpass_allowed(root, "source")
    (root / "extra").unlink()
    source.rename(root / "original");source.symlink_to(root / "original")
    assert not legacy_userpass_allowed(root, "source")


def test_exception_does_not_cover_destination_or_approval_files(sandbox):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    tool = legacy_tool(root)
    try:
        plan = tool.plan("source", [target]);approve(root, plan)
        approval_path = root / ".mcp-import" / (plan["transaction"] + ".approval")
        approval_path.chmod(0o644)
        with pytest.raises(ImportBlocked):tool.apply(plan["transaction"])
        approval_path.chmod(0o600);tool.apply(plan["transaction"])
        (root / "target_a.userpass").chmod(0o644)
        with pytest.raises(ImportBlocked):tool.rollback_plan(plan["transaction"])
    finally:
        tool.close()


def test_exception_is_bound_to_preview_policy(sandbox):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    tool = legacy_tool(root)
    try:
        plan = tool.plan("source", [target]);approve(root, plan)
    finally:
        tool.close()
    default = InactiveImport(root, inactive)
    try:
        with pytest.raises(ImportBlocked, match="policy changed"):
            default.apply(plan["transaction"])
    finally:
        default.close()


def test_permission_drift_after_preview_fails(sandbox):
    root, _, target, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    tool = legacy_tool(root)
    try:
        plan = tool.plan("source", [target]);approve(root, plan)
        (root / "source.userpass").chmod(0o664)
        with pytest.raises(ImportBlocked):tool.apply(plan["transaction"])
        assert not list(root.glob("target_*"))
    finally:
        tool.close()


def test_compatibility_preflight_is_stat_only_and_explicit(environment, monkeypatch):
    sources, profiles = environment
    (profiles / "source.userpass").chmod(0o644)
    original = os.open
    def checked(path, *args, **kwargs):
        assert not str(path).endswith((".userpass", ".password", ".ovpn"))
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "open", checked)
    default = preflight(sources, profiles, "Provider Region A", ["target_a"])
    assert not default["legacy_userpass_exception_eligible"]
    explicit = preflight(sources, profiles, "Provider Region A", ["target_a"], legacy_readable_userpass_source="source")
    assert explicit["legacy_userpass_exception_eligible"]
    assert not explicit["credential_contents_read"] and not explicit["live_import_ready"]
    assert not any("permissions" in b for b in explicit["blockers"])


def test_opened_file_must_match_trusted_path(sandbox):
    root, _, _, _ = sandbox
    (root / "source.userpass").chmod(0o644)
    wrong = (root / "source.settings").stat()
    assert not legacy_userpass_allowed(root, "source", opened_stat=wrong)


def test_destination_0644_is_plan_bound_and_rollback_supported(sandbox):
    from test_vpn_import import approve
    root,tool,target,_=sandbox
    tool.destination_mode='0644'
    plan=tool.plan('source',[target])
    assert plan['destination_mode']=='0644'
    approve(root,plan);tool.apply(plan['transaction'])
    for suffix in ['ovpn','settings','userpass','password']:
        assert (root/('target_a.'+suffix)).stat().st_mode&0o777==0o644
    rollback=tool.rollback_plan(plan['transaction']);approve(root,rollback,'rollback')
    assert tool.rollback(plan['transaction'])['state']=='rolled_back'


def test_destination_mode_change_invalidates_preview(sandbox):
    from test_vpn_import import approve
    root,tool,target,_=sandbox
    plan=tool.plan('source',[target]);approve(root,plan);tool.destination_mode='0644'
    with pytest.raises(ImportBlocked,match='permission policy changed'):tool.apply(plan['transaction'])
    assert not (root/'target_a.ovpn').exists()
