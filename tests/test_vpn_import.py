import json
import os
import ssl
from pathlib import Path

import pytest

from firewalla_mcp.vpn_import import InactiveImport, ImportBlocked, digest, profile_id, settings_copy, validate_profile


def inactive(ids):
    return {i: {"inactive": True, "unreferenced": True, "administrative_intent": "stopped"} for i in ids}


@pytest.fixture
def profile():
    # Public trust anchor already installed on the test machine; no private keys or network.
    der = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca = ssl.DER_cert_to_PEM_cert(der)
    return ("client\ndev tun\nproto udp\nremote vpn.example.test 1194\nremote-cert-tls server\n"
            "auth-user-pass\nnobind\npersist-key\npersist-tun\nauth-nocache\n"
            "cipher AES-128-GCM\ntls-version-min 1.2\nverb 3\n<ca>\n" + ca + "</ca>\n").encode()


@pytest.fixture
def sandbox(tmp_path, profile):
    root = tmp_path / "profiles"
    root.mkdir(mode=0o700)
    values = {"ovpn": profile, "userpass": b"synthetic-user\nsynthetic-password", "password": b"synthetic-extra",
              "settings": json.dumps({"strictVPN": True, "routeDNS": True, "overrideDefaultRoute": True,
                                     "autoReconnect": False, "serverSubnets": [], "displayName": "Source"}).encode()}
    for ext, value in values.items():
        p = root / ("source." + ext)
        p.write_bytes(value)
        p.chmod(0o600)
    importer = InactiveImport(root, inactive)
    target = {"id": "target_a", "display_name": "Target A", "content": profile,
              "sha256": digest(profile), "endpoint": "vpn.example.test"}
    yield root, importer, target, values
    importer.close()


def approve(root, plan, operation="apply"):
    p = root / ".mcp-import" / (plan["transaction"] + ".approval")
    p.write_text(json.dumps({"transaction": plan["transaction"], "operation": operation, "digest": plan["approval_digest"]}))
    p.chmod(0o600)


def test_three_profiles_inactive_idempotence_and_rollback(sandbox):
    root, tool, target, source = sandbox
    targets = [{**target, "id": "target_" + letter, "display_name": "Target " + letter} for letter in "abc"]
    plan = tool.plan("source", targets)
    assert "synthetic-password" not in json.dumps(plan)
    assert digest(source["userpass"]) not in json.dumps(plan)
    assert not list(root.glob("target_*"))
    approve(root, plan)
    assert tool.apply(plan["transaction"])["state"] == "imported_inactive"
    assert tool.apply(plan["transaction"])["state"] == "already_imported"
    for t in targets:
        for ext in ("ovpn", "userpass", "password"):
            assert (root / (t["id"] + "." + ext)).read_bytes() == source[ext]
        settings = json.loads((root / (t["id"] + ".settings")).read_text())
        assert settings["strictVPN"] and settings["routeDNS"] and not settings["autoReconnect"]
        assert settings["displayName"] == t["display_name"]
        assert (root / (t["id"] + ".userpass")).stat().st_mode & 0o777 == 0o600
    rollback = tool.rollback_plan(plan["transaction"])
    assert rollback["approval_digest"] != plan["approval_digest"]
    approve(root, rollback, "rollback")
    assert tool.rollback(plan["transaction"])["state"] == "rolled_back"
    assert tool.rollback(plan["transaction"])["state"] == "already_rolled_back"
    assert not list(root.glob("target_*"))
    for ext, value in source.items():
        assert (root / ("source." + ext)).read_bytes() == value


@pytest.mark.parametrize("identifier", ["../source", "a/b", "a;id", "a$(id)", "a\n", "", "a" * 12, ".hidden"])
def test_id_injection(identifier):
    with pytest.raises(ImportBlocked):
        profile_id(identifier)


@pytest.mark.parametrize("line", ["up /bin/id", "plugin /tmp/p.so", "script-security 2", "config /tmp/x", "ca /tmp/ca",
                                  "auth-user-pass /tmp/secret", "remote other.example.test 1194", "proto tcp", "dev tap",
                                  "<key>\nprivate\n</key>", "setenv opt x", "log /tmp/file", "management 127.0.0.1 1234"])
def test_unsafe_or_duplicate_directive(profile, line):
    data = profile + (line + "\n").encode()
    with pytest.raises(ImportBlocked):
        validate_profile(data, digest(data), "vpn.example.test")


def test_html_and_digest_rejection(profile):
    html = b"<!DOCTYPE html><html>download blocked</html>"
    with pytest.raises(ImportBlocked, match="HTML"):
        validate_profile(html, digest(html), "vpn.example.test")
    with pytest.raises(ImportBlocked, match="digest"):
        validate_profile(profile, "0" * 64, "vpn.example.test")


@pytest.mark.parametrize("extra", [{"started": True}, {"password": "synthetic"}, {"routeDNS": None}, {"serverSubnets": ["fe80::1%eth0/128"]}])
def test_unsafe_settings(extra):
    value = {"strictVPN": True, "routeDNS": True, "overrideDefaultRoute": True, **extra}
    with pytest.raises(ImportBlocked):
        settings_copy(json.dumps(value).encode(), "New profile")


@pytest.mark.parametrize("suffix", ["", ".ovpn", ".settings", ".conf", ".gateway", ".userpass"])
def test_any_target_filename_collision(sandbox, suffix):
    root, tool, target, _ = sandbox
    (root / (target["id"] + suffix)).write_text("existing")
    with pytest.raises(ImportBlocked, match="collision"):
        tool.plan("source", [target])


def test_target_symlink_and_source_hardlink(sandbox):
    root, tool, target, _ = sandbox
    path = root / "target_a.userpass"
    path.symlink_to(root / "source.userpass")
    with pytest.raises(ImportBlocked):
        tool.plan("source", [target])
    path.unlink()
    os.link(root / "source.userpass", root / "unrelated")
    with pytest.raises(ImportBlocked, match="Hardlinked"):
        tool.plan("source", [target])


def test_source_symlink_and_permissive_secret(sandbox):
    root, tool, target, _ = sandbox
    p = root / "source.userpass"
    p.chmod(0o644)
    with pytest.raises(ImportBlocked, match="permissions"):
        tool.plan("source", [target])
    p.rename(root / "secret-original")
    p.symlink_to(root / "secret-original")
    with pytest.raises(ImportBlocked):
        tool.plan("source", [target])


def test_state_must_prove_intent_and_no_references(sandbox):
    _, tool, target, _ = sandbox
    for observation in ({}, {"target_a": {"inactive": True}}, {"target_a": {"inactive": True, "unreferenced": False, "administrative_intent": "stopped"}}):
        tool.probe = lambda ids, value=observation: value
        with pytest.raises(ImportBlocked):
            tool.plan("source", [target])


def test_approval_required_expired_and_mismatched(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target])
    with pytest.raises(FileNotFoundError):
        tool.apply(plan["transaction"])
    approve(root, {**plan, "approval_digest": "wrong"})
    with pytest.raises(ImportBlocked, match="Approval"):
        tool.apply(plan["transaction"])
    approve(root, plan)
    tool.clock = lambda: plan["expires"] + 1
    with pytest.raises(ImportBlocked, match="expired"):
        tool.apply(plan["transaction"])
    assert not list(root.glob("target_*"))


def test_source_change_and_collision_after_preview(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target])
    approve(root, plan)
    (root / "source.userpass").write_bytes(b"changed\ncredential")
    with pytest.raises(ImportBlocked, match="Source changed"):
        tool.apply(plan["transaction"])
    (root / "target_a.conf").write_text("external")
    with pytest.raises(ImportBlocked, match="collision"):
        tool.apply(plan["transaction"])


def test_crash_recovery_and_no_approval_replay(sandbox, monkeypatch):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target])
    approve(root, plan)
    original = os.link
    calls = []
    def interrupted(*args, **kwargs):
        calls.append(args)
        if len(calls) == 2:
            raise OSError("synthetic private failure details")
        return original(*args, **kwargs)
    monkeypatch.setattr(os, "link", interrupted)
    with pytest.raises(ImportBlocked, match="journal") as error:
        tool.apply(plan["transaction"])
    assert "private failure" not in str(error.value)
    assert not (root / "target_a.ovpn").exists()
    assert not (root / ".mcp-import" / (plan["transaction"] + ".approval")).exists()
    with pytest.raises(ImportBlocked, match="Partial"):
        tool.apply(plan["transaction"])
    rollback = tool.rollback_plan(plan["transaction"])
    approve(root, rollback, "rollback")
    tool.rollback(plan["transaction"])
    assert not list(root.glob("target_*"))


def test_rollback_refuses_modified_or_active_target(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target]);approve(root, plan);tool.apply(plan["transaction"])
    (root / "target_a.userpass").write_bytes(b"external-change")
    with pytest.raises(ImportBlocked, match="changed"):
        tool.rollback_plan(plan["transaction"])
    tool.probe = lambda ids: {}
    with pytest.raises(ImportBlocked, match="administrative"):
        tool.rollback_plan(plan["transaction"])
    assert (root / "target_a.ovpn").exists()


def test_concurrent_import_lock(sandbox):
    root, tool, target, _ = sandbox
    other = InactiveImport(root, inactive)
    try:
        with tool.locked(), pytest.raises(ImportBlocked, match="active"):
            other.plan("source", [target])
    finally:
        other.close()


def test_publication_race_never_overwrites_foreign_file(sandbox, monkeypatch):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target]);approve(root, plan)
    original = os.link
    def collision(src, dst, **kwargs):
        if dst == "target_a.userpass":
            p = root / dst;p.write_bytes(b"foreign-file");p.chmod(0o600)
        return original(src, dst, **kwargs)
    monkeypatch.setattr(os, "link", collision)
    with pytest.raises(ImportBlocked, match="journal"):
        tool.apply(plan["transaction"])
    assert (root / "target_a.userpass").read_bytes() == b"foreign-file"
    with pytest.raises(ImportBlocked, match="changed"):
        tool.rollback_plan(plan["transaction"])
    assert (root / "target_a.userpass").read_bytes() == b"foreign-file"


def test_rollback_refuses_runtime_file_created_after_import(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target]);approve(root, plan);tool.apply(plan["transaction"])
    (root / "target_a.conf").write_text("new runtime state")
    with pytest.raises(ImportBlocked, match="New target"):
        tool.rollback_plan(plan["transaction"])


def test_rollback_requires_its_own_preview(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target]);approve(root, plan);tool.apply(plan["transaction"])
    approve(root, plan, "rollback")
    with pytest.raises(ImportBlocked, match="separate rollback"):
        tool.rollback(plan["transaction"])


def test_matching_content_replaced_inode_is_not_owned(sandbox):
    root, tool, target, _ = sandbox
    plan = tool.plan("source", [target]);approve(root, plan);tool.apply(plan["transaction"])
    p = root / "target_a.ovpn";content = p.read_bytes();p.unlink();p.write_bytes(content);p.chmod(0o600)
    with pytest.raises(ImportBlocked, match="changed"):
        tool.rollback_plan(plan["transaction"])
