"""Inactive OpenVPN import transaction core. No network, shell, logging, or MCP exposure.

Requires an independently reviewed local state probe. No live firmware adapter is
provided: callers must not substitute interface absence for administrative state.
Secrets remain in owner-only files; public results contain no credential hashes.
"""
import base64
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import ssl
import stat
import time
from contextlib import contextmanager


class ImportBlocked(ValueError):
    """Only fixed safe messages; never include file contents or upstream errors."""


def need(condition, message):
    if not condition:
        raise ImportBlocked(message)


def profile_id(value):
    need(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,10}", value), "Invalid profile ID")
    return value


def fresh_profile_id():
    """Candidate only: collision and complete exact-ID reference checks still apply."""
    return secrets.token_hex(5)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def legacy_userpass_allowed(directory, source, *, opened_stat=None, root_stat=None):
    """Narrow stat-only exception for one existing owner-owned 0644 .userpass.

    Ancestors must be owned by root/current uid and not writable by others.
    Root-owned sticky temporary directories are allowed: their child must also
    pass ownership checks. Same-uid/root processes remain outside this boundary.
    """
    profile_id(source)
    try:
        directory = os.path.abspath(directory)
        current = "/"
        paths = ["/"]
        for part in directory.split("/")[1:]:
            current = os.path.join(current, part)
            paths.append(current)
        for path in paths:
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
                return False
            if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                return False
        directory_info = os.lstat(directory)
        if directory_info.st_uid != os.getuid() or directory_info.st_mode & 0o022:
            return False
        if root_stat is not None and (directory_info.st_dev, directory_info.st_ino) != (root_stat.st_dev, root_stat.st_ino):
            return False
        info = os.lstat(os.path.join(directory, source + ".userpass"))
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644):
            return False
        if opened_stat is not None and (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink) != (
                opened_stat.st_dev, opened_stat.st_ino, opened_stat.st_mode, opened_stat.st_uid, opened_stat.st_nlink):
            return False
        return True
    except OSError:
        return False


def hostname(value):
    need(isinstance(value, str) and len(value) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
        for part in value.split(".")), "Invalid endpoint hostname")
    return value.lower()


def validate_profile(data, expected_sha256, expected_endpoint, *, provider_features=False):
    """Conservative UDP/1194 subset; explicit opt-in for inline TLS auth/compression."""
    need(isinstance(data, bytes) and 1 <= len(data) <= 131072, "Invalid profile size")
    need(re.fullmatch(r"[a-f0-9]{64}", expected_sha256 or ""), "Invalid public profile digest")
    need(digest(data) == expected_sha256, "Public profile digest mismatch")
    expected_endpoint = hostname(expected_endpoint)
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise ImportBlocked("Profile must be ASCII") from None
    need(not any(ord(c) < 32 and c not in "\r\n\t" for c in text), "Profile contains control characters")
    need("<html" not in text.lower() and "<!doctype" not in text.lower(), "HTML is not a VPN profile")
    need(type(provider_features) is bool, "Invalid provider compatibility option")
    # Parse inline static authentication without returning or logging its contents.
    # Original bytes remain untouched and are hash-bound in the private journal.
    tls_auth = False
    if provider_features:
        lines = text.splitlines()
        cleaned = []
        inside = False
        inside_ca = False
        key_lines = []
        for raw in lines:
            line = raw.strip()
            if line == "<tls-auth>":
                need(not inside and not tls_auth and not inside_ca, "Duplicate or nested TLS authentication block")
                inside = tls_auth = True
            elif line == "</tls-auth>":
                need(inside, "Unexpected TLS authentication terminator")
                inside = False
                useful = [v for v in key_lines if v and not v.startswith("#")]
                need(len(useful) == 18 and useful[0] == "-----BEGIN OpenVPN Static key V1-----"
                     and useful[-1] == "-----END OpenVPN Static key V1-----"
                     and all(re.fullmatch(r"[0-9a-fA-F]{32}", v) for v in useful[1:-1]),
                     "Invalid inline TLS authentication key")
            elif inside:
                key_lines.append(line)
            else:
                if line == "<ca>":
                    inside_ca = True
                elif line == "</ca>":
                    inside_ca = False
                cleaned.append(raw)
        need(not inside, "Incomplete TLS authentication block")
        text = "\n".join(cleaned)
    directives = {}
    ca = []
    in_ca = False
    seen_ca = False
    for raw in text.splitlines():
        line = raw.strip()
        if line == "<ca>":
            need(not in_ca and not seen_ca, "Duplicate CA block")
            in_ca = seen_ca = True
            continue
        if line == "</ca>":
            need(in_ca, "Unexpected CA terminator")
            in_ca = False
            continue
        if in_ca:
            need(bool(re.fullmatch(r"[A-Za-z0-9+/= -]*", line)), "Invalid CA data")
            ca.append(line)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        need("<" not in line and ">" not in line and "\\" not in line, "Unsupported inline block or escape")
        try:
            fields = shlex.split(line, comments=True)
        except ValueError:
            raise ImportBlocked("Invalid profile syntax") from None
        need(bool(fields) and fields[0] not in directives, "Duplicate directive")
        directives[fields[0]] = fields[1:]
    need(seen_ca and not in_ca and len(ca) > 2, "Missing or incomplete CA")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata="\n".join(ca)+"\n")
    except (ssl.SSLError, ValueError):
        raise ImportBlocked("Invalid CA certificate") from None
    if provider_features and directives.get("remote") == [expected_endpoint, "1194", "udp"]:
        need(directives.get("proto") in (None, ["udp"]), "Conflicting transport directives")
        # Validate equivalent per-remote transport without altering original bytes.
        directives = dict(directives)
        directives["remote"] = [expected_endpoint, "1194"]
        directives["proto"] = ["udp"]
    fixed = {"client": [], "dev": ["tun"], "proto": ["udp"],
             "remote": [expected_endpoint, "1194"], "remote-cert-tls": ["server"], "auth-user-pass": []}
    for key, value in fixed.items():
        need(directives.get(key) == value, "Missing or unexpected required directive")
    need("cipher" in directives or "data-ciphers" in directives, "Explicit approved data cipher required")
    zero = {"nobind", "persist-key", "persist-tun", "auth-nocache"}
    enums = {"cipher": {"AES-128-GCM", "AES-256-GCM"}, "auth": {"SHA256", "SHA512"},
             "tls-version-min": {"1.2", "1.3"}, "resolv-retry": {"infinite"}}
    for key, args in directives.items():
        if key in fixed:
            continue
        if key in zero:
            need(not args, "Unexpected directive arguments")
        elif key in enums:
            need(len(args) == 1 and args[0] in enums[key], "Unsupported cryptographic or retry setting")
        elif provider_features and key == "key-direction":
            need(tls_auth and args == ["1"], "Invalid TLS authentication direction")
        elif provider_features and key == "comp-lzo":
            need(args in ([], ["no"], ["yes"], ["adaptive"]), "Invalid compression setting")
        elif key == "data-ciphers":
            need(len(args) == 1 and set(args[0].split(":")) <= {"AES-128-GCM", "AES-256-GCM"}, "Unsupported data cipher")
        elif key in ("verb", "mute", "reneg-sec"):
            need(len(args) == 1 and args[0].isdigit() and 0 <= int(args[0]) <= (3 if key == "verb" else 86400), "Invalid numeric directive")
        elif key == "verify-x509-name":
            need(len(args) == 2 and args[1] == "name" and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", args[0])), "Invalid certificate name constraint")
        else:
            raise ImportBlocked("Unsupported directive; manual review required")
    if tls_auth:
        need(directives.get("key-direction") == ["1"], "Explicit client TLS authentication direction required")
    result = {"sha256": expected_sha256, "endpoint": expected_endpoint, "protocol": "udp", "port": 1194}
    if provider_features:
        result.update({"inline_tls_auth": tls_auth, "profile_contains_shared_key": tls_auth,
                       "compression": (directives["comp-lzo"] or ["adaptive"])[0] if "comp-lzo" in directives else "absent",
                       "compression_server_push_possible": "comp-lzo" in directives,
                       "profile_bytes_preserved": True})
    return result


def settings_copy(data, display_name, endpoint=None):
    need(isinstance(display_name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", display_name), "Invalid display name")
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError):
        raise ImportBlocked("Unsupported settings format") from None
    bools = {"overrideDefaultRoute", "routeDNS", "c2sSNATDisabled", "strictVPN", "enablePortforward", "autoReconnect", "noDNSBooster"}
    allowed = bools | {"serverSubnets", "displayName", "createdDate", "serverDDNS", "serverVPNPort", "subtype"}
    need(isinstance(value, dict) and set(value) <= allowed, "Unreviewed settings fields")
    need({"overrideDefaultRoute", "routeDNS", "strictVPN"} <= set(value), "Explicit routing and DNS settings required")
    for key in bools & set(value):
        need(type(value[key]) is bool, "Invalid boolean setting")
    subnets = value.get("serverSubnets", [])
    need(isinstance(subnets, list) and len(subnets) <= 64, "Invalid route settings")
    try:
        for subnet in subnets:
            need(isinstance(subnet, str) and "%" not in subnet, "Invalid route setting")
            ipaddress.ip_network(subnet, strict=True)
    except ValueError:
        raise ImportBlocked("Invalid route setting") from None
    value["displayName"] = display_name
    # App metadata must not keep the old endpoint when cloning to a new server.
    if "serverDDNS" in value or "serverVPNPort" in value:
        need(endpoint is not None, "Reviewed target endpoint required for metadata")
        if "serverDDNS" in value:
            hostname(value["serverDDNS"])
            value["serverDDNS"] = hostname(endpoint)
        if "serverVPNPort" in value:
            need(type(value["serverVPNPort"]) is int and 1 <= value["serverVPNPort"] <= 65535, "Invalid source endpoint port")
            value["serverVPNPort"] = 1194
    if "subtype" in value:
        need(isinstance(value["subtype"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}", value["subtype"]), "Invalid subtype metadata")
    if "createdDate" in value:
        need(type(value["createdDate"]) in (int, float) and math.isfinite(value["createdDate"]) and 0 <= value["createdDate"] <= 4102444800000, "Invalid creation metadata")
        # Do not claim the clone was created at the source's date, or guess its units.
        del value["createdDate"]
    return encoded(value)


class InactiveImport:
    """Owner-local file transaction, guarded by mandatory inactive/reference checks.

    A probe must return {id: {inactive: True, unreferenced: True,
    administrative_intent: 'stopped'}} from validated local management state.
    Strict mode requires authoritative evidence. Explicit new-ID maintenance mode
    uses reviewed passive checks and reports administrative intent as unknown.
    """

    def __init__(self, directory, state_probe, *, clock=time.time, legacy_readable_userpass_source=None, provider_features=False, maintenance_window=None, observational_new_ids=False, destination_mode="0600"):
        need(maintenance_window is None or isinstance(maintenance_window, dict) and set(maintenance_window) == {"nonce", "expires"}
             and isinstance(maintenance_window["nonce"], str) and re.fullmatch(r"[a-f0-9]{32}", maintenance_window["nonce"])
             and type(maintenance_window["expires"]) is int and clock() < maintenance_window["expires"] <= clock() + 600,
             "Invalid maintenance window")
        need(type(observational_new_ids) is bool and (not observational_new_ids or maintenance_window is not None),
             "Observational mode requires explicit maintenance window")
        need(destination_mode in ("0600", "0644"), "Unsupported destination mode")
        self.destination_mode = destination_mode
        self.observational_new_ids = observational_new_ids
        self.maintenance_window = dict(maintenance_window) if maintenance_window else None
        need(type(provider_features) is bool, "Invalid provider compatibility option")
        self.provider_features = provider_features
        need(callable(state_probe), "Reviewed state probe required")
        self.legacy_source = profile_id(legacy_readable_userpass_source) if legacy_readable_userpass_source is not None else None
        self.directory = os.path.abspath(directory)
        # Reject symlink ancestors as well as a symlink final directory.
        current = "/"
        for part in self.directory.split("/")[1:]:
            current = os.path.join(current, part)
            need(not stat.S_ISLNK(os.lstat(current).st_mode), "Symlink directory rejected")
        self.root = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(self.root)
        need(st.st_uid == os.getuid() and not st.st_mode & 0o022, "Unsafe profile directory ownership or permissions")
        self.probe, self.clock = state_probe, clock
        try:
            os.mkdir(".mcp-import", 0o700, dir_fd=self.root)
        except FileExistsError:
            pass
        self.stage = os.open(".mcp-import", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.root)
        st = os.fstat(self.stage)
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, "Unsafe journal directory")

    def close(self):
        os.close(self.stage)
        os.close(self.root)

    @contextmanager
    def locked(self):
        fd = os.open("lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=self.stage)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, "Unsafe lock file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise ImportBlocked("Another import transaction is active") from None
        finally:
            os.close(fd)

    def read(self, name, *, stage=False, secret=False, public_destination=False):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.stage if stage else self.root)
        except FileNotFoundError:
            raise
        except OSError:
            raise ImportBlocked("File cannot be read safely") from None
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_size <= 131072, "Unsafe or oversized file")
            ordinary = not st.st_mode & (0o077 if secret else 0o022)
            exception = secret and not stage and self.legacy_source is not None and name == self.legacy_source + ".userpass"
            readable_destination = public_destination and not stage and stat.S_IMODE(st.st_mode) == 0o644
            need(ordinary or readable_destination or exception and legacy_userpass_allowed(self.directory, self.legacy_source,
                 opened_stat=st, root_stat=os.fstat(self.root)), "Unsafe file permissions")
            data = os.read(fd, 131073)
            need(len(data) <= 131072, "File grew beyond limit")
            return data, {"sha256": digest(data), "dev": st.st_dev, "ino": st.st_ino, "size": len(data)}
        finally:
            os.close(fd)

    def write_stage(self, name, data):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.stage)
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            os.fsync(self.stage)
        except BaseException:
            self.remove_owned_stage(name, created.st_dev, created.st_ino, len(data))
            raise
        finally:
            os.close(fd)

    def save(self, tx, journal):
        temp = tx + ".new-" + secrets.token_hex(8)
        self.write_stage(temp, encoded(journal))
        info = os.stat(temp, dir_fd=self.stage, follow_symlinks=False)
        try:
            os.rename(temp, tx + ".json", src_dir_fd=self.stage, dst_dir_fd=self.stage)
            os.fsync(self.stage)
        finally:
            self.remove_owned_stage(temp, info.st_dev, info.st_ino, info.st_size)

    def remove_owned_stage(self, name, device, inode, max_size, *, allow_readable=False):
        """Exact known inode only; never glob transaction prefixes or delete replacements."""
        try:
            info = os.stat(name, dir_fd=self.stage, follow_symlinks=False)
        except FileNotFoundError:
            return
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
             and stat.S_IMODE(info.st_mode) in ((0o600, 0o644) if allow_readable else (0o600,)) and info.st_nlink == 1
             and (info.st_dev, info.st_ino) == (device, inode) and info.st_size <= max_size,
             "Staged file ownership changed; cleanup requires review")
        os.unlink(name, dir_fd=self.stage)
        os.fsync(self.stage)

    def stage_entry(self, tx, journal, name, data):
        """Persist ownership of an empty inode BEFORE writing any credential bytes."""
        staged = tx + "-" + name
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.stage)
        info = os.fstat(fd)
        fingerprint = {"sha256": digest(data), "dev": info.st_dev, "ino": info.st_ino, "size": len(data)}
        try:
            os.fsync(fd)
            os.fsync(self.stage)
            journal["entries"].append({"name": name, "staged": staged, "fingerprint": fingerprint})
            self.save(tx, journal)
            # If this process dies now, the durable journal owns even a partial copy.
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            _, actual = self.read(staged, stage=True, secret=True)
            need(actual == fingerprint, "Staged file changed before publication")
        except BaseException:
            # No target link exists yet. Preserve foreign replacements for review.
            self.remove_owned_stage(staged, info.st_dev, info.st_ino, len(data))
            raise
        finally:
            os.close(fd)
        return staged

    def load(self, tx):
        need(isinstance(tx, str) and re.fullmatch(r"[a-f0-9]{32}", tx), "Invalid transaction ID")
        data, _ = self.read(tx + ".json", stage=True, secret=True)
        journal = json.loads(data)
        need(journal["public"]["transaction"] == tx, "Journal identity mismatch")
        profile_id(journal["public"]["source"])
        for target in journal["public"]["targets"]:
            profile_id(target["id"])
        names = {t["id"] + "." + ext for t in journal["public"]["targets"] for ext in ("ovpn", "settings", "userpass", "password")}
        need(set(journal["source_files"]) <= {"ovpn", "settings", "userpass", "password"}, "Invalid journal source names")
        for entry in journal["entries"]:
            need(entry["name"] in names and entry["staged"] == tx + "-" + entry["name"], "Invalid journal target names")
        return journal

    def maintenance_policy(self):
        if self.maintenance_window is None:
            return None
        return {**self.maintenance_window, "scope": "new_nonce_ids_only",
                "owner_condition": "no concurrent VPN/profile/policy edits until completion",
                "atomic_guarantee": False, "automatic_cleanup_on_state_change": False,
                "observational_new_ids": self.observational_new_ids,
                "administrative_state_guarantee": "unknown; passive checks only" if self.observational_new_ids else "observed stopped/not instantiated"}

    def check_mode(self, journal):
        need(journal["public"].get("maintenance") == self.maintenance_policy(), "Maintenance policy changed")
        need(journal["public"].get("destination_mode", "0600") == self.destination_mode, "Destination permission policy changed")

    def guard(self, targets):
        if self.maintenance_window is not None:
            need(self.clock() < self.maintenance_window["expires"], "Maintenance window expired")
            need(all(re.fullmatch(r"[a-f0-9]{10}", t) for t in targets), "Maintenance requires fresh nonce IDs")
        try:
            result = self.probe(tuple(targets))
        except Exception:
            raise ImportBlocked("State evidence unavailable") from None
        if self.observational_new_ids:
            expected = {"unreferenced": True, "reference_enumeration_complete": True,
                        "runtime_observation": "no_interface_inactive_unit_cache_not_true",
                        "administrative_intent": "unknown"}
            need(isinstance(result, dict) and set(result)==set(targets)
                 and all(result[t]==expected for t in targets), "Fresh-ID passive checks failed or incomplete")
            return
        need(isinstance(result, dict) and set(result) == set(targets) and all(
            result[t] in [{"inactive": True, "unreferenced": True, "administrative_intent": intent}
                          for intent in (("stopped", "not_instantiated") if self.maintenance_window else ("stopped",))]
            for t in targets), "Targets are active, referenced, or administrative intent is unknown")

    def absent(self, target):
        need(not any(n == target or n.startswith(target + ".") for n in os.listdir(self.root)), "Target filename collision")

    def plan(self, source, targets):
        """targets: id, display_name, content(bytes), sha256, endpoint; at most three."""
        source = profile_id(source)
        need(isinstance(targets, list) and 1 <= len(targets) <= 3, "One to three targets required")
        ids = [profile_id(t["id"]) for t in targets]
        need(len(set(ids)) == len(ids) and source not in ids, "Source/target identity collision")
        with self.locked():
            self.guard(ids)
            for target in ids:
                self.absent(target)
            # Only four source files are examined; no API, Redis dump or runtime files.
            sources = {}
            absent_source_files = []
            source_settings = None
            for suffix in ("ovpn", "settings", "userpass", "password"):
                name = source + "." + suffix
                try:
                    data, fingerprint = self.read(name, secret=suffix in ("userpass", "password"))
                except FileNotFoundError:
                    need(suffix == "password", "Required source file absent")
                    absent_source_files.append(suffix)
                    continue
                need(os.stat(name, dir_fd=self.root, follow_symlinks=False).st_nlink == 1, "Hardlinked source rejected")
                if suffix == "settings":
                    source_settings = data
                if suffix == "userpass":
                    parts = data.split(b"\n")
                    need(len(parts) in (2, 3) and bool(parts[0]) and bool(parts[1]) and (len(parts) == 2 or parts[2] == b""), "Unsupported local credential format")
                sources[suffix] = fingerprint
            tx = secrets.token_hex(16)
            public = {"transaction": tx, "source": source, "targets": [], "action": "create_inactive_profiles",
                      "copy_files": sorted(set(sources) - {"ovpn"}), "expires": int(self.clock()) + 600}
            public["source_permission_exception"] = self.permission_exception(source)
            public["provider_features"] = self.provider_features
            public["destination_mode"] = self.destination_mode
            public["credential_readability"] = "other local users can read destination credentials if directory traversal permits" if self.destination_mode == "0644" else "owner-only destination files"
            public["maintenance"] = self.maintenance_policy()
            if self.maintenance_window:
                public["expires"] = min(public["expires"], self.maintenance_window["expires"])
            payloads = {}
            for target in targets:
                validated = validate_profile(target["content"], target["sha256"], target["endpoint"], provider_features=self.provider_features)
                settings = settings_copy(source_settings, target["display_name"], target["endpoint"])
                public["targets"].append({"id": target["id"], "display_name": target["display_name"], **validated})
                payloads[target["id"]] = {"ovpn": base64.b64encode(target["content"]).decode(), "settings": base64.b64encode(settings).decode()}
            public["settings_metadata_changes"] = {"displayName": "target label", "serverDDNS_if_present": "verified target endpoint",
                                                   "serverVPNPort_if_present": 1194, "createdDate_if_present": "omitted", "subtype_if_present": "preserved"}
            approval = digest(encoded(public))
            journal = encoded({"public": public, "approval_digest": approval,
                "source_files": sources, "absent_source_files": absent_source_files, "payloads": payloads, "entries": [], "phase": "planned"})
            need(len(journal) <= 110000, "Combined import payload exceeds journal budget")
            self.write_stage(tx + ".json", journal)
            return {**public, "approval_digest": approval, "state": "preview_only"}

    def permission_exception(self, source):
        if self.legacy_source == source:
            return {"profile": source, "suffix": "userpass", "mode": "0644", "owner_uid": os.getuid(),
                    "source_unchanged": True, "destination_mode": self.destination_mode}
        return None

    def approval(self, tx, journal, operation):
        name = tx + ".approval"
        raw, before = self.read(name, stage=True, secret=True)
        try:
            approved = json.loads(raw)
        except ValueError:
            raise ImportBlocked("Invalid approval") from None
        need(approved == {"transaction": tx, "operation": operation, "digest": journal["approval_digest"]}, "Approval does not match plan")
        need(self.clock() <= journal["public"]["expires"], "Approval expired")
        _, after = self.read(name, stage=True, secret=True)
        need(before == after, "Approval changed")
        os.unlink(name, dir_fd=self.stage)
        os.fsync(self.stage)

    def verify_entries(self, journal):
        expected = {entry["name"] for entry in journal["entries"]}
        ids = [t["id"] for t in journal["public"]["targets"]]
        for name in os.listdir(self.root):
            if any(name == target or name.startswith(target + ".") for target in ids):
                need(name in expected, "New target files appeared; rollback unsafe")
        for entry in journal["entries"]:
            try:
                _, actual = self.read(entry["name"], secret=True, public_destination=journal["public"].get("destination_mode")=="0644")
            except FileNotFoundError:
                need(journal["phase"] != "committed", "Committed target disappeared")
                continue
            need(actual == entry["fingerprint"], "Target changed; automatic recovery forbidden")
            if journal["phase"] == "committed":
                need(stat.S_IMODE(os.stat(entry["name"],dir_fd=self.root,follow_symlinks=False).st_mode)==int(journal["public"].get("destination_mode","0600"),8), "Target permissions changed")

    def apply(self, tx):
        with self.locked():
            journal = self.load(tx)
            self.check_mode(journal)
            ids = [t["id"] for t in journal["public"]["targets"]]
            self.guard(ids)
            if journal["phase"] == "committed":
                self.verify_entries(journal)
                return {"transaction": tx, "state": "already_imported", "profiles": ids}
            need(journal["phase"] == "planned", "Partial transaction requires explicit recovery")
            need(journal["approval_digest"] == digest(encoded(journal["public"])), "Preview digest changed")
            need(journal["public"].get("source_permission_exception") == self.permission_exception(journal["public"]["source"]),
                 "Source permission policy changed after preview")
            need(journal["public"].get("provider_features", False) == self.provider_features, "Provider compatibility policy changed")
            for target in ids:
                self.absent(target)
            source = journal["public"]["source"]
            need(journal.get("absent_source_files") == ([] if "password" in journal["source_files"] else ["password"]),
                 "Source absence evidence missing")
            for suffix in journal["absent_source_files"]:
                try:
                    os.stat(source + "." + suffix, dir_fd=self.root, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ImportBlocked("Previously absent source file appeared")
            local = {}
            for suffix, expected in journal["source_files"].items():
                data, actual = self.read(source + "." + suffix, secret=suffix in ("userpass", "password"))
                need(actual == expected, "Source changed after preview")
                if suffix in ("userpass", "password"):
                    local[suffix] = data
                if suffix == "settings":
                    local_settings = data
            for target in journal["public"]["targets"]:
                payload = journal["payloads"][target["id"]]
                validate_profile(base64.b64decode(payload["ovpn"]), target["sha256"], target["endpoint"], provider_features=self.provider_features)
                need(base64.b64decode(payload["settings"]) == settings_copy(local_settings, target["display_name"], target["endpoint"]), "Planned settings changed")
            self.approval(tx, journal, "apply")
            journal["phase"] = "applying"
            self.save(tx, journal)
            try:
                # All ancillary files first; discovery markers last. Not multi-file atomic.
                for suffix in ("userpass", "password", "settings", "ovpn"):
                    for target in ids:
                        if suffix == "password" and suffix not in local:
                            continue
                        self.guard(ids)
                        data = local[suffix] if suffix in local else base64.b64decode(journal["payloads"][target][suffix])
                        name = target + "." + suffix
                        staged = self.stage_entry(tx, journal, name, data)
                        os.link(staged, name, src_dir_fd=self.stage, dst_dir_fd=self.root, follow_symlinks=False)
                        os.fsync(self.root)
                self.guard(ids)
                self.verify_entries(journal)
                for entry in journal["entries"]:
                    fd=os.open(entry["name"],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.root)
                    try:
                        info=os.fstat(fd)
                        need((info.st_dev,info.st_ino)==(entry["fingerprint"]["dev"],entry["fingerprint"]["ino"]),"Target changed before permission update")
                        os.fchmod(fd,int(self.destination_mode,8));os.fsync(fd)
                    finally:os.close(fd)
                journal["phase"] = "committed"
                self.verify_entries(journal)
                self.save(tx, journal)
            except Exception:
                raise ImportBlocked("Import interrupted; private journal requires reviewed recovery") from None
            return {"transaction": tx, "state": "imported_unassigned_passive_checks" if self.observational_new_ids else "imported_inactive", "profiles": ids,
                    "enforcement": "not tested; no start, API call or policy change performed"}

    def rollback_plan(self, tx):
        with self.locked():
            journal = self.load(tx)
            self.check_mode(journal)
            need(journal["phase"] in ("applying", "committed", "rolling_back"), "Nothing eligible for rollback")
            self.guard([t["id"] for t in journal["public"]["targets"]])
            self.verify_entries(journal)
            journal["public"]["expires"] = int(self.clock()) + 600
            journal["approval_digest"] = digest(encoded({"transaction": tx, "operation": "rollback", "nonce": secrets.token_hex(32)}))
            journal["rollback_prepared"] = True
            self.save(tx, journal)
            return {"transaction": tx, "operation": "rollback", "approval_digest": journal["approval_digest"], "expires": journal["public"]["expires"]}

    def rollback(self, tx):
        with self.locked():
            journal = self.load(tx)
            self.check_mode(journal)
            if journal["phase"] == "rolled_back":
                return {"transaction": tx, "state": "already_rolled_back"}
            need(journal["phase"] in ("applying", "committed", "rolling_back"), "Invalid rollback phase")
            need(journal.get("rollback_prepared") is True, "A separate rollback preview is required")
            self.guard([t["id"] for t in journal["public"]["targets"]])
            self.verify_entries(journal)
            self.approval(tx, journal, "rollback")
            journal["phase"] = "rolling_back"
            self.save(tx, journal)
            # Remove discovery markers before credentials/settings; never delete a foreign inode.
            for entry in sorted(journal["entries"], key=lambda item: not item["name"].endswith(".ovpn")):
                self.guard([t["id"] for t in journal["public"]["targets"]])
                try:
                    _, actual = self.read(entry["name"], secret=True, public_destination=journal["public"].get("destination_mode")=="0644")
                    need(actual == entry["fingerprint"], "Target changed during rollback")
                    os.unlink(entry["name"], dir_fd=self.root)
                except FileNotFoundError:
                    pass
                fingerprint = entry["fingerprint"]
                self.remove_owned_stage(entry["staged"], fingerprint["dev"], fingerprint["ino"], fingerprint["size"],
                                        allow_readable=journal["public"].get("destination_mode")=="0644")
                os.fsync(self.root)
                os.fsync(self.stage)
            journal["phase"] = "rolled_back"
            self.save(tx, journal)
            return {"transaction": tx, "state": "rolled_back"}
