import hashlib
import json
import os

import pytest

from firewalla_mcp.vpn_import import ImportBlocked, settings_copy
from firewalla_mcp import vpn_import_state as state


@pytest.fixture
def environment(tmp_path, monkeypatch):
    sources = tmp_path / "source"
    sources.mkdir()
    reviewed = {}
    for i, name in enumerate(state.SOURCE_HASHES):
        p = sources / name;p.parent.mkdir(parents=True, exist_ok=True)
        data = ("// synthetic source contract " + str(i)).encode()
        p.write_bytes(data);reviewed[name] = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(state, "SOURCE_HASHES", reviewed)
    profiles = tmp_path / "profiles";profiles.mkdir(mode=0o700)
    (profiles / "source.settings").write_text(json.dumps({"displayName": "Provider Region A", "password": "never-return-this"}))
    (profiles / "source.ovpn").write_text("must-not-read-configuration")
    (profiles / "source.userpass").write_text("must-not-read-credentials")
    (profiles / "source.userpass").chmod(0o600)
    return sources, profiles


def test_metadata_projection_never_opens_credentials(environment, monkeypatch):
    sources, profiles = environment
    opened = []
    original = os.open
    def checked(path, *args, **kwargs):
        opened.append(str(path))
        assert not str(path).endswith((".ovpn", ".userpass", ".password"))
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "open", checked)
    report = state.preflight(sources, profiles, " provider   REGION a ", ["target_a", "target_b"])
    assert report["source"]["id"] == "source"
    assert report["firmware"]["compatible_sources"]
    assert report["status"] == "blocked" and report["live_import_ready"] is False
    assert report["credential_contents_read"] is False
    assert "never-return" not in json.dumps(report)
    assert "must-not-read" not in json.dumps(report)
    assert not (profiles / ".mcp-import").exists()


def test_ambiguous_source_is_not_guessed(environment):
    _, profiles = environment
    (profiles / "second.settings").write_text('{"displayName":"provider region a"}')
    with pytest.raises(ImportBlocked, match="ambiguous"):
        state.discover_source(profiles, "Provider Region A")


def test_unknown_source_and_symlink_fail_closed(environment):
    sources, _ = environment
    name = next(iter(state.SOURCE_HASHES))
    p = sources / name;p.write_text("changed")
    assert not state.compatibility(sources)["compatible_sources"]
    p.unlink();p.symlink_to(sources / "absent")
    assert not state.compatibility(sources)["compatible_sources"]


def test_bounded_catalog_and_malformed_metadata(environment):
    _, profiles = environment
    (profiles / "source.settings").write_text("not json")
    with pytest.raises(ImportBlocked):state.discover_source(profiles, "Provider Region A")
    for i in range(65):
        (profiles / ("id" + str(i) + ".settings")).write_text('{}')
    with pytest.raises(ImportBlocked, match="incomplete"):
        state.discover_source(profiles, "Provider Region A")


def test_permissions_and_collision_reported_without_read(environment):
    sources, profiles = environment
    (profiles / "source.userpass").chmod(0o644)
    (profiles / "target_a.conf").write_text("runtime")
    report = state.preflight(sources, profiles, "Provider Region A", ["target_a"])
    assert report["target_collisions"]["target_a"]
    assert not report["source_file_metadata"]["userpass"]["owner_only"]
    assert any("permissions" in b for b in report["blockers"])


@pytest.mark.parametrize("cached", [None, False, True])
def test_cached_link_never_proves_stopped_intent(cached):
    result = state.observed_state(interface_present=False, unit_active=False, cached_connected=cached)
    assert result["administrative_intent"] == "unknown"
    assert result["safe_to_import"] is False
    with pytest.raises(ImportBlocked, match="Administrative intent"):
        state.import_state_probe(["target_a"])


def test_source_settings_endpoint_metadata_is_explicit():
    original = {"displayName": "Original", "serverDDNS": "original.example.test", "serverVPNPort": 443,
                "createdDate": 1700000000.5, "subtype": "provider", "strictVPN": True,
                "routeDNS": False, "overrideDefaultRoute": True, "serverSubnets": []}
    copy = json.loads(settings_copy(json.dumps(original).encode(), "New label", "new.example.test"))
    assert copy["serverDDNS"] == "new.example.test" and copy["serverVPNPort"] == 1194
    assert copy["strictVPN"] is True and copy["routeDNS"] is False and copy["overrideDefaultRoute"] is True
    assert copy["subtype"] == original["subtype"] and "createdDate" not in copy
    assert original["serverDDNS"] == "original.example.test"
    with pytest.raises(ImportBlocked, match="endpoint required"):
        settings_copy(json.dumps(original).encode(), "New label")


@pytest.mark.parametrize("metadata", [{"createdDate": float("nan")}, {"serverVPNPort": True}, {"subtype": "bad\nvalue"}, {"serverDDNS": "https://user:password@example.test"}])
def test_unsafe_metadata_rejected(metadata):
    base = {"strictVPN": True, "routeDNS": True, "overrideDefaultRoute": True, **metadata}
    with pytest.raises(ImportBlocked):settings_copy(json.dumps(base).encode(), "New label", "new.example.test")
