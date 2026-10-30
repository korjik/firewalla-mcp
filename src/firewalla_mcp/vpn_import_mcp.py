"""Host-approved import plans; no tool can approve itself or upload a file."""
import re
import copy
import secrets
import time
from .writes import WriteManager, digest
from .vpn_import_rpc import ImportTransport


class ImportManager(WriteManager):
    def __init__(self, config, transport=None):
        super().__init__(config.model_copy(update={"writes_enabled": config.vpn_writes_enabled}), None)
        self.rpc = transport or ImportTransport()

    def host_confirmed(self):
        return self.config.vpn_confirmation_mode == "host_confirmed"

    def approval_bound_targets(self):
        return self.config.vpn_target_policy == "approval_bound"

    def site(self, box, source=None, archive=None):
        self.enabled()
        box = self.config.resolve(box)
        if box not in self.config.sites:
            raise ValueError("Unknown box")
        site = self.config.sites[box]
        if source is not None:
            from .vpn_import import profile_id
            profile_id(source)
        if archive is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",archive):
            raise ValueError("Invalid registered archive identifier")
        if not self.approval_bound_targets() and source is not None and source not in site.vpn_import_sources:
            raise ValueError("Import source outside allowlist")
        if not self.approval_bound_targets() and archive is not None and archive not in site.vpn_import_archives:
            raise ValueError("Import archive outside allowlist")
        return box, site.model_copy(deep=True)

    async def preview_import(self, box, source, archive, destination_mode, maintenance_until, source_permission="owner_only"):
        box, site = self.site(box, source, archive)
        binding=self.site_binding(box)
        if source_permission not in ("owner_only","existing_0644"):
            raise ValueError("Invalid source permission option")
        if destination_mode not in ("0600", "0644"):
            raise ValueError("Unsupported destination mode")
        now = int(time.time())
        if type(maintenance_until) is not int or not now < maintenance_until <= now + 600:
            raise ValueError("Explicit maintenance deadline must be within ten minutes")
        async with self.locks[box]:
            self.plans = {k:v for k,v in self.plans.items() if v["expires_at"] > now}
            if len(self.plans) >= 128:
                raise ValueError("Import plan limit")
            self.audit("preview", "import_preview_requested", box)
            result = await self.rpc.request(site, dict(operation="preview", source=source, archive=archive,
                destination_mode=destination_mode, maintenance_until=maintenance_until,
                target_policy=self.config.vpn_target_policy, source_permission=source_permission))
            if result.get("status") != "ok": return result
            if self.site_binding(box)!=binding: raise ValueError("Box configuration changed during import preview")
            public = result["data"]
            tx, remote_digest = public["transaction"], public["approval_digest"]
            if not re.fullmatch(r"[a-f0-9]{32}", tx) or not re.fullmatch(r"[a-f0-9]{64}", remote_digest):
                raise ValueError("Invalid import preview identity")
            plan = dict(plan_id=secrets.token_hex(16), box=box, source=source, archive=archive,
                destination_mode=destination_mode, expires_at=min(maintenance_until, public["expires"]),
                transaction=tx, remote_digest=remote_digest, preview=copy.deepcopy(public),
                site_binding=self.site_binding(box), target_authorization="trusted_mcp_host_confirmation")
            plan["digest"] = digest(plan); plan["status"] = "pending"
            self.plans[plan["plan_id"]] = plan
            return {**copy.deepcopy(plan), "next_step":self.approval_next_step(plan) if self.approval_bound_targets() else None,
                "warning":"Owner must avoid concurrent VPN/profile/policy edits until completion. Passive checks do not establish authoritative stopped intent. Follow the advertised confirmation mode."}

    async def apply_import(self, plan_id):
        self.enabled()
        if plan_id not in self.plans: raise ValueError("Unknown import plan")
        plan = self.plans[plan_id]
        async with self.locks[plan["box"]]:
            if plan["status"] != "pending":
                return {"status":plan["status"], "replayed":True, "result":plan.get("result")}
            if time.time() >= plan["expires_at"]: raise ValueError("Import plan expired")
            self.check_plan(plan)
            _, site = self.site(plan["box"], plan["source"], plan["archive"])
            self.consume_approval(plan)
            self.audit(plan_id, "import_host_requested_attempt", plan["box"])
            plan["status"] = "uncertain"
            result = await self.rpc.request(site, dict(operation="apply", transaction=plan["transaction"],
                approval_digest=plan["remote_digest"]))
            plan["result"] = result
            if result.get("status") == "ok" and result.get("data",{}).get("state") in ("imported_unassigned_passive_checks", "already_imported"):
                plan["status"] = "imported"
            try: self.audit(plan_id, plan["status"], plan["box"])
            except OSError: result = {**result, "audit_warning":"Completion audit failed; do not retry"}
            return result

    async def verify_import(self, box, transaction):
        _, site = self.site(box)
        if not re.fullmatch(r"[a-f0-9]{32}", transaction): raise ValueError("Invalid transaction")
        return await self.rpc.request(site, dict(operation="verify", transaction=transaction))
