"""Read-only, credential-free import preflight for one reviewed source revision.

Discovery/compatibility is implemented. Live administrative intent is NOT exposed
by the reviewed safe interfaces: this module deliberately cannot authorize import.
No constructor writes, Redis/API calls, service actions, or credential file opens.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

from .vpn_import import ImportBlocked, legacy_userpass_allowed, need, profile_id


REVISION = "173ac36dccb5239a5195a5b4e64d20cb1b618a91"
SOURCE_HASHES = {
    "extension/vpnclient/OpenVPNClient.js": "bf3bca904c057949f453992c3c8f004ead43bb6dd968dab63e0f94b62e84efb6",
    "extension/vpnclient/VPNClient.js": "a08e6c378758504ea57a96136ea1d3d35fc2634aef299b8b5d40de1e0fff52c1",
    "net2/HostManager.js": "8e01724086e36e10c0e182449d4edefba7577b6d18666a7049752997af0c2771",
    "controllers/netbot.js": "d7ae7676389d54fff71c0dadf83540a8cd454a8d1dca9336fa8d8b83cc7c9871",
    "net2/VirtWanGroup.js": "3bf389ab04c730aa6cf341d3bf172cd27f8d5fe1c7e0db4c830184f9e052698d",
}


def read_regular(path, limit):
    """Only called for application source and .settings metadata, never secrets."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlink metadata/source path")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "Unexpected metadata/source file")
            data = os.read(fd, limit + 1)
            need(len(data) <= limit, "Metadata/source output limit")
            return data
        finally:
            os.close(fd)
    except OSError:
        raise ImportBlocked("Metadata/source unavailable") from None


def compatibility(source_root):
    result = {}
    for relative, expected in SOURCE_HASHES.items():
        try:
            actual = hashlib.sha256(read_regular(Path(source_root) / relative, 1048576)).hexdigest()
            result[relative] = actual == expected
        except ImportBlocked:
            result[relative] = False
    return {"reviewed_revision": REVISION, "source_matches": result, "compatible_sources": all(result.values()),
            "discovery": "OpenVPN .ovpn filenames; enumeration is not a start/stop operation",
            "administrative_intent_observable": False,
            "review_scope": "five source files; not a claim of exhaustive extension/watcher coverage"}


def entries(directory):
    root = Path(directory).absolute()
    for item in (root, *root.parents):
        need(not item.is_symlink(), "Symlink profile directory")
    need(root.is_dir(), "Profile directory missing")
    rows = []
    with os.scandir(root) as iterator:
        for item in iterator:
            rows.append(item.name)
            need(len(rows) <= 1024, "Profile directory enumeration incomplete")
    return root, rows


def discover_source(directory, exact_display_name):
    """Exact whitespace/case-normalized name; ambiguity is never resolved by guessing."""
    need(isinstance(exact_display_name, str) and 1 <= len(exact_display_name) <= 128, "Invalid source label")
    wanted = " ".join(exact_display_name.casefold().split())
    root, names = entries(directory)
    candidates = [name for name in names if name.endswith(".settings")]
    need(len(candidates) <= 64, "Profile catalog incomplete")
    matches = []
    for name in candidates:
        identifier = profile_id(name[:-len(".settings")])
        try:
            value = json.loads(read_regular(root / name, 65536))
        except (UnicodeError, ValueError):
            raise ImportBlocked("Profile metadata schema unknown") from None
        need(isinstance(value, dict), "Profile metadata schema unknown")
        label = value.get("displayName")
        need(label is None or isinstance(label, str) and len(label) <= 128, "Profile label schema unknown")
        if isinstance(label, str) and " ".join(label.casefold().split()) == wanted:
            matches.append({"id": identifier, "display_name": label})
    need(len(matches) == 1, "Source name absent or ambiguous")
    need(matches[0]["id"] + ".ovpn" in names, "Selected source has no OpenVPN discovery marker")
    return matches[0]


def file_metadata(directory, identifier):
    """lstat only: no .ovpn/.userpass/.password content is read."""
    root, _ = entries(directory)
    identifier = profile_id(identifier)
    result = {}
    for suffix in ("ovpn", "settings", "userpass", "password"):
        try:
            info = (root / (identifier + "." + suffix)).lstat()
        except FileNotFoundError:
            result[suffix] = {"exists": False}
            continue
        result[suffix] = {"exists": True, "regular": stat.S_ISREG(info.st_mode),
                          "symlink": stat.S_ISLNK(info.st_mode), "owner_matches": info.st_uid == os.getuid(),
                          "owner_only": not bool(info.st_mode & 0o077), "single_link": info.st_nlink == 1}
    return result


def preflight(source_root, profile_directory, source_label, targets, *, legacy_readable_userpass_source=None):
    need(isinstance(targets, (list, tuple)) and 1 <= len(targets) <= 3, "One to three target IDs required")
    targets = [profile_id(target) for target in targets]
    need(len(set(targets)) == len(targets), "Duplicate targets")
    firmware = compatibility(source_root)
    source = discover_source(profile_directory, source_label)
    need(source["id"] not in targets, "Target collides with source")
    _, names = entries(profile_directory)
    metadata = file_metadata(profile_directory, source["id"])
    compatibility_exception = (legacy_readable_userpass_source == source["id"] and
                               legacy_userpass_allowed(profile_directory, source["id"]))
    blockers = ["No credential-free authoritative FireMain administrative-intent channel has been validated",
                "Target references and concurrent API/extension start events have not been comprehensively excluded"]
    if not firmware["compatible_sources"]:
        blockers.append("Installed source differs from reviewed files")
    for suffix in ("userpass", "password"):
        row = metadata[suffix]
        if suffix == "password" and not row["exists"]:
            continue
        if suffix == "userpass" and compatibility_exception:
            continue
        if not row["exists"] or not all(row.get(k, False) for k in ("regular", "owner_matches", "owner_only", "single_link")):
            blockers.append("Source credential file ownership/permissions/type do not meet import requirements")
    collisions = {target: any(name == target or name.startswith(target + ".") for name in names) for target in targets}
    if any(collisions.values()):
        blockers.append("Target filename collision")
    return {"status": "blocked", "source": source, "firmware": firmware, "source_file_metadata": metadata,
            "target_collisions": collisions, "credential_contents_read": False, "live_import_ready": False,
            "legacy_userpass_exception_eligible": compatibility_exception,
            "blockers": list(dict.fromkeys(blockers))}


def observed_state(*, interface_present, unit_active, cached_connected):
    """Classify observations without turning a down link into stopped intent."""
    need(type(interface_present) is bool and type(unit_active) is bool and
         (cached_connected is None or type(cached_connected) is bool), "Invalid state observation")
    return {"link_observed_down": not interface_present and not unit_active and cached_connected is not True,
            "administrative_intent": "unknown", "unreferenced": None, "safe_to_import": False}


def import_state_probe(_targets):
    """Fail closed until a separately reviewed in-process observation path exists."""
    raise ImportBlocked("Administrative intent cannot be established from the reviewed credential-free interfaces")
