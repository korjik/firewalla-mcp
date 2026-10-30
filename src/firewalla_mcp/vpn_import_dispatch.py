"""Router-local import dispatcher for a separately approved forced-command key.

Only opaque registered archive IDs cross MCP. No credentials/config bytes leave
this process. The CLI has fixed paths; injected paths/runners below are test seams.
"""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from .vpn_archive import read_profile_archive
from .vpn_import import InactiveImport, need, digest, encoded, profile_id
from .vpn_new_id_guard import NewIdObservation
from .remote import run, vpn_source_guard


def private_read(path, maximum):
    path = Path(path)
    # Every ancestor must be a real directory. The immediate directory is private.
    for parent in path.parents:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode), "Symlink or non-directory ancestor")
    parent = path.parent.stat()
    need(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
         "Private registry directory required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= maximum, "Unsafe registry file")
        data = os.read(fd, maximum + 1)
        need(len(data) == info.st_size and len(data) <= maximum, "Registry changed or oversized")
        return data
    finally: os.close(fd)


class ImportDispatcher:
    def __init__(self, profile_directory, policy_file, runner=run, observer=NewIdObservation, clock=time.time):
        self.root = Path(profile_directory)
        self.policy_file = Path(policy_file)
        self.runner, self.observer, self.clock = runner, observer, clock

    def policy(self):
        raw = private_read(self.policy_file, 8192)
        policy = json.loads(raw)
        base = {"revision", "sources", "archives", "destination_modes", "provider_features"}
        dynamic = policy.get("target_policy") == "approval_bound"
        need(set(policy) == (base | {"target_policy", "source_permission_modes"} if dynamic else base), "Invalid import policy")
        if dynamic:
            need(isinstance(policy["source_permission_modes"],list) and bool(policy["source_permission_modes"])
                 and set(policy["source_permission_modes"]) <= {"owner_only","existing_0644"}, "Invalid source permission policy")
        need(re.fullmatch(r"[a-f0-9]{40}", policy["revision"]), "Reviewed revision required")
        need(isinstance(policy["sources"], dict) and (0 if dynamic else 1) <= len(policy["sources"]) <= 32, "Invalid source allowlist")
        for source, legacy in policy["sources"].items():
            profile_id(source); need(type(legacy) is bool, "Invalid source permission policy")
        need(isinstance(policy["archives"], list) and (0 if dynamic else 1) <= len(policy["archives"]) <= 32
             and all(isinstance(v,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",v) for v in policy["archives"]), "Invalid archive allowlist")
        need(isinstance(policy["destination_modes"], list) and bool(policy["destination_modes"])
             and set(policy["destination_modes"]) <= {"0600", "0644"}, "Invalid mode allowlist")
        need(type(policy["provider_features"]) is bool, "Invalid provider option")
        source_tree = str(Path.home() / "firewalla")
        vpn_source_guard(policy["revision"], source_tree, self.runner)
        return policy, digest(raw)

    def inputs(self, archive):
        need(isinstance(archive,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",archive), "Invalid registered archive ID")
        directory = self.root / ".mcp-import-inputs"
        manifest_raw = private_read(directory / (archive + ".json"), 8192)
        manifest = json.loads(manifest_raw)
        need(set(manifest) == {"sha256", "profiles"}, "Invalid registered manifest")
        data = private_read(directory / (archive + ".zip"), 524288)
        need(digest(data) == manifest["sha256"], "Registered archive changed")
        files = read_profile_archive(data, allow_macos_metadata=True)
        need(isinstance(manifest["profiles"], list) and 1 <= len(manifest["profiles"]) <= 3, "Invalid profile count")
        need(len(manifest["profiles"]) == len(files) and {v["filename"] for v in manifest["profiles"]} == set(files), "Manifest/archive mismatch")
        targets = []
        for row in manifest["profiles"]:
            need(set(row) == {"filename", "display_name", "endpoint", "sha256"}, "Unexpected manifest fields")
            targets.append({"id":secrets.token_hex(5), "display_name":row["display_name"],
                "endpoint":row["endpoint"], "sha256":row["sha256"], "content":files[row["filename"]]})
        return targets, digest(manifest_raw), digest(data)

    def importer(self, source, policy, window, mode, ids, observational=True, source_permission=None):
        observer = self.observer(ids, self.runner)
        tool = InactiveImport(self.root, observer, clock=self.clock,
            legacy_readable_userpass_source=source if (source_permission == "existing_0644" if source_permission is not None else policy["sources"].get(source,False)) else None,
            provider_features=policy["provider_features"], maintenance_window=window,
            observational_new_ids=observational, destination_mode=mode)
        return tool, observer

    def journal_public(self, transaction):
        need(isinstance(transaction,str) and re.fullmatch(r"[a-f0-9]{32}",transaction), "Invalid transaction")
        raw = private_read(self.root / ".mcp-import" / (transaction + ".json"), 131072)
        journal = json.loads(raw)
        need(journal["public"]["transaction"] == transaction, "Journal identity changed")
        return journal["public"]

    def target_check(self, policy, source, archive, mode, source_permission):
        profile_id(source)
        need(isinstance(archive,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",archive), "Invalid registered archive ID")
        need(source_permission in ("owner_only","existing_0644"), "Invalid source permission option")
        need(mode in policy["destination_modes"], "Destination mode outside policy")
        if policy.get("target_policy") == "approval_bound":
            need(source_permission in policy["source_permission_modes"], "Source permission option outside operator policy")
        else:
            need(source in policy["sources"] and archive in policy["archives"], "Outside import policy")
            need(source_permission != "existing_0644" or policy["sources"][source], "Readable source exception not allowed")

    def execute(self, request):
        need(isinstance(request, dict), "Invalid request")
        policy, policy_hash = self.policy()
        operation = request.get("operation")
        if operation == "preview":
            need(set(request) - {"target_policy","source_permission"} == {"operation", "source", "archive", "destination_mode", "maintenance_until"}, "Invalid preview")
            need(request.get("target_policy","allowlist") == policy.get("target_policy","allowlist"), "Host/router target policy mismatch")
            source, archive, mode = request["source"], request["archive"], request["destination_mode"]
            source_permission=request.get("source_permission", "existing_0644" if policy["sources"].get(source) else "owner_only")
            self.target_check(policy,source,archive,mode,source_permission)
            stage = self.root / ".mcp-import"
            if stage.exists():
                need(not stage.is_symlink(), "Journal directory symlink")
                total = 0
                with os.scandir(stage) as entries:
                    for index, entry in enumerate(entries):
                        need(index < 4096, "Journal entry quota; operator review required")
                        total += entry.stat(follow_symlinks=False).st_size
                        need(total <= 16777216, "Journal byte quota; operator review required")
            targets, manifest_hash, archive_hash = self.inputs(archive)
            ids = [v["id"] for v in targets]
            window = {"nonce":secrets.token_hex(16), "expires":request["maintenance_until"]}
            tool, observer = self.importer(source, policy, window, mode, ids, source_permission=source_permission)
            try:
                observer.collision_check(self.root.parent)
                plan = tool.plan(source, targets)
                with tool.locked():
                    journal = tool.load(plan["transaction"])
                    journal["public"]["source_permission"] = source_permission
                    journal["public"]["target_policy"] = policy.get("target_policy","allowlist")
                    journal["public"]["registry"] = dict(archive=archive, manifest_hash=manifest_hash,
                        archive_hash=archive_hash, policy_hash=policy_hash)
                    journal["approval_digest"] = digest(encoded(journal["public"]))
                    tool.save(plan["transaction"], journal)
                return {"status":"ok", "data":{**journal["public"], "approval_digest":journal["approval_digest"], "state":"preview_only"}}
            finally: tool.close()
        need(operation in ("apply", "verify"), "Unknown import operation")
        need(set(request) == ({"operation","transaction","approval_digest"} if operation == "apply" else {"operation","transaction"}), "Invalid transaction request")
        tx = request["transaction"]; public = self.journal_public(tx)
        source, mode = public["source"], public["destination_mode"]
        source_permission=public.get("source_permission", "existing_0644" if policy["sources"].get(source) else "owner_only")
        self.target_check(policy,source,public["registry"]["archive"],mode,source_permission)
        need(public["registry"]["policy_hash"] == policy_hash, "Import policy changed")
        ids = [v["id"] for v in public["targets"]]
        window = {k:public["maintenance"][k] for k in ("nonce","expires")} if operation == "apply" else None
        tool, observer = self.importer(source, policy, window, mode, ids, operation == "apply", source_permission=source_permission)
        try:
            if operation == "verify":
                with tool.locked():
                    journal = tool.load(tx); tool.verify_entries(journal)
                    need(journal["phase"] == "committed", "Import is not committed")
                    observations = observer(tuple(ids))
                return {"status":"ok", "data":{"transaction":tx, "state":"files_verified_passive_checks",
                    "profiles":ids, "destination_mode":mode, "observations":observations,
                    "administrative_intent":"unknown", "observed_at":int(self.clock())}}
            _, manifest_hash, archive_hash = self.inputs(public["registry"]["archive"])
            need((manifest_hash,archive_hash) == (public["registry"]["manifest_hash"],public["registry"]["archive_hash"]), "Registered input changed")
            with tool.locked():
                journal = tool.load(tx)
                need(journal["approval_digest"] == request["approval_digest"], "Approval digest mismatch")
                need(journal["phase"] == "planned", "Already attempted; inspect instead of retry")
                # Host approval was consumed by the MCP manager. SSH forced command is
                # the operator-approved authority to create this exact router approval.
                tool.write_stage(tx + ".approval", encoded({"transaction":tx,"operation":"apply","digest":request["approval_digest"]}))
            return {"status":"ok", "data":tool.apply(tx)}
        finally: tool.close()


def main():
    try:
        raw = sys.stdin.buffer.read(8193)
        need(len(raw) <= 8192, "Request bound")
        home = Path.home()
        dispatcher = ImportDispatcher(home / ".firewalla/run/ovpn_profile", home / ".ssh/firewalla-mcp-vpn-import-policy.json")
        result = dispatcher.execute(json.loads(raw))
    except Exception:
        # No exception details: malformed JSON or credential parsers may include input.
        result = {"status":"blocked", "reason":"Import validation failed; inspect private journal locally. No automatic retry; partial state is possible."}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__": main()
