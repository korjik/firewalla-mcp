"""Host-approved, temporary kernel changes. No MCP tool can issue an approval."""
import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from ipaddress import IPv4Address, IPv4Network


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()


class WriteManager:
    def __init__(self,config,transport):
        self.config=config
        self.transport=transport
        self.plans={}
        self.locks={name:asyncio.Lock() for name in config.sites}

    def approval_bound_targets(self):
        return self.host_confirmed()

    def host_confirmed(self):
        return self.config.write_confirmation_mode == "host_confirmed"

    def apply_tool_name(self):
        return "apply_change"

    def site_binding(self, box):
        return digest({"site":self.config.sites[box].model_dump(),
                       "target_policy":self.config.vpn_target_policy,
                       "confirmation_mode":self.config.vpn_confirmation_mode,
                       "general_confirmation_mode":self.config.write_confirmation_mode,
                       "approval_consumed_directory":self.config.approval_consumed_directory,
                       "audit_file":self.config.audit_file})

    def check_plan(self, plan):
        material={k:v for k,v in plan.items() if k not in ("digest","status","result")}
        if digest(material)!=plan["digest"]:
            raise ValueError("Plan changed; obtain a new preview and approval")
        if plan.get("site_binding")!=self.site_binding(plan["box"]):
            raise ValueError("Box/configuration binding changed; preview again")

    def enabled(self):
        if not self.config.writes_enabled:
            raise ValueError("Writes disabled. Operator must enable writes and configure host approvals.")
        if not self.host_confirmed():
            raise ValueError("Writes require explicit host_confirmed migration; file-based approval is unsupported")
        from .host_confirmation import validate_ledger
        if not self.approval_bound_targets():raise ValueError("Host-confirmed VPN mode requires approval-bound targets")
        if not self.config.audit_file or not Path(self.config.audit_file).is_absolute():raise ValueError("Absolute audit path required")
        validate_ledger(self.config)

    def validate(self,box_name,spec):
        self.enabled()
        if box_name not in self.config.sites:
            raise ValueError("Unknown box")
        site=self.config.sites[box_name]
        kind=spec["kind"]
        if kind.startswith("managed_"):
            from .remote import validate_managed, MANAGEMENT_REVISION, VPN_MANAGEMENT_REVISIONS, POLICY_FEATURES
            validate_managed(spec)
            if site.management_revision != MANAGEMENT_REVISION and not (kind in ("managed_lifecycle","managed_vpn","managed_forward","managed_forward_batch","managed_feature","managed_rule","managed_scoped") and site.management_revision in VPN_MANAGEMENT_REVISIONS):
                raise ValueError("Explicit reviewed management revision required")
            if site.management_revision in VPN_MANAGEMENT_REVISIONS and kind in ("managed_feature","managed_scoped") and spec["feature"] not in POLICY_FEATURES:
                raise ValueError("Feature implementation not reviewed for installed revision")
            if kind == "managed_scoped":
                from .remote import managed_target
                if not self.approval_bound_targets() and managed_target(spec) not in site.managed_scopes:raise ValueError("Scope outside managed allowlist")
                return site
            if kind in ("managed_forward","managed_forward_batch"):
                if not self.host_confirmed():raise ValueError("Persistent forward requires explicit host-confirmed mode")
                if site.management_revision not in VPN_MANAGEMENT_REVISIONS:raise ValueError("Persistent forward requires reviewed installed revision")
                return site
            if kind == "managed_lifecycle":
                if not self.approval_bound_targets() and spec["profile"] not in site.managed_vpn_profiles:raise ValueError("VPN profile outside managed allowlist")
                return site
            if not self.approval_bound_targets() and spec["device"] not in [v.upper() for v in site.managed_devices]:
                raise ValueError("Device outside managed allowlist")
            if kind == "managed_vpn" and not self.approval_bound_targets() and any(spec[k] not in site.managed_vpn_profiles for k in ("expected_profile","destination_profile")):
                raise ValueError("VPN profile outside managed allowlist")
            return site
        if kind=="route":
            if type(spec["table"]) is not int or spec["table"] not in site.allowed_route_tables or spec["table"] in (253,254,255):
                raise ValueError("Route table not permitted; reserved tables are excluded")
            spec["destination"]=str(IPv4Network(spec["destination"],strict=True))
            if spec["route_type"]=="unicast":
                spec["gateway"]=str(IPv4Address(spec["gateway"]))
                if not spec.get("interface"):
                    raise ValueError("Unicast route requires interface")
            elif spec["route_type"]!="blackhole" or spec.get("gateway") or spec.get("interface"):
                raise ValueError("Invalid route arguments")
        else:
            allowed=site.allowed_filter_chains if kind=="filter_rule" else site.allowed_nat_chains
            if spec["chain"] not in allowed or not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,27}",spec["chain"]):
                raise ValueError("Chain not permitted")
            if kind=="filter_rule":
                spec["source"]=str(IPv4Network(spec["source"],strict=True))
                spec["destination"]=str(IPv4Network(spec["destination"],strict=True))
                if spec["action"] not in ("ACCEPT","DROP","REJECT"):
                    raise ValueError("Invalid action")
            elif kind=="dnat":
                for key in ("public_address","destination_address"):
                    spec[key]=str(IPv4Address(spec[key]))
            else:
                raise ValueError("Unknown write adapter")
            if spec["protocol"] not in ("tcp","udp"):
                raise ValueError("Invalid protocol")
            for key in ("destination_port","external_port"):
                if key in spec and (type(spec[key]) is not int or not 1<=spec[key]<=65535):
                    raise ValueError("Invalid port")
        if spec.get("interface") and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}",spec["interface"]):
            raise ValueError("Invalid interface")
        return site

    def audit(self,plan_id,event,box):
        # Audit before mutation must succeed. Never record addresses, arguments or credentials.
        fd=os.open(self.config.audit_file,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
        try:
            os.write(fd,(json.dumps({"time":int(time.time()),"plan_id":plan_id,"box":box,"event":event})+"\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def new_plan(self,box,spec,state,mode,context=None):
        # Bound memory and expiry. Only pending plans are pruned; completed entries support rollback.
        now=int(time.time())
        self.plans={k:v for k,v in self.plans.items() if v["expires_at"]>now}
        if len(self.plans)>=128:
            raise ValueError("Plan capacity reached")
        spec=copy.deepcopy(spec)
        context=copy.deepcopy(context)
        plan_id=secrets.token_hex(16)
        plan={"apply_tool":self.apply_tool_name(),"plan_id":plan_id,"box":box,"spec":spec,"expected":state["fingerprint"],
              "mode":mode,"expires_at":now+600,"scope":"vpn_runtime_lifecycle" if spec["kind"]=="managed_lifecycle" else "persistent_managed" if spec["kind"].startswith("managed_") else "temporary_kernel_only"}
        if context is not None:
            plan["context"]=context
        plan["site_binding"]=self.site_binding(box)
        plan["target_authorization"]="trusted_mcp_host_confirmation"
        plan["digest"]=digest(plan)
        plan["status"]="pending"
        self.plans[plan_id]=plan
        return {**copy.deepcopy(plan),"next_step":self.approval_next_step(plan) if self.approval_bound_targets() else None,"rollback":state.get("rollback","separate approved rollback preview"),"impact":state.get("scope","selected target only; inherited effects may apply"),
                "diff":{"operation":"apply" if mode=="apply" else "restore_exact_prior_state","object":copy.deepcopy(spec),"before":copy.deepcopy(state.get("field"))},
                "warning":"Confirm the exact preview using the configured confirmation mode. Kernel changes may be overwritten. Managed state acknowledgment does not prove asynchronous enforcement. No automatic approval or retry. Concurrent external writers cannot be made atomic."}

    async def remote_write(self,site,spec,mode,expected=None,context=None,expires_at=None):
        managed=spec["kind"].startswith("managed_")
        args={"mode":mode,"spec":spec}
        if expected is not None: args["expected"]=expected
        if context is not None: args["context"]=context
        if expires_at is not None: args["expires_at"]=expires_at
        if managed: args["revision"]=site.management_revision
        return await self.transport.run(site,"managed_write" if managed else "write",args)

    async def preview(self,box,spec):
        box=self.config.resolve(box)
        spec=copy.deepcopy(spec)
        site=self.validate(box,spec).model_copy(deep=True)
        binding=self.site_binding(box)
        async with self.locks[box]:
            result=await self.remote_write(site,spec,"preview")
            if result.get("status")!="ok":
                return result
            if self.site_binding(box)!=binding:
                raise ValueError("Box configuration changed during preview")
            state=result["data"]
            if state["present"]:
                return {"status":"no_change","reason":"Desired state or potentially duplicate rule already exists; no replacement is permitted."}
            return self.new_plan(box,spec,state,"apply")

    def approval_next_step(self, plan=None):
        from .approval_guidance import approval_guidance
        return approval_guidance(self.config, plan)

    def consume_approval(self,plan):
        self.enabled()
        from .host_confirmation import claim
        return claim(self.config, plan)

    async def apply(self,plan_id):
        self.enabled()
        if not re.fullmatch(r"[a-f0-9]{32}",plan_id) or plan_id not in self.plans:
            raise ValueError("Unknown plan")
        plan=self.plans[plan_id]
        async with self.locks[plan["box"]]:
            if plan["status"]!="pending":
                return {"status":plan["status"],"result":plan.get("result"),"replayed":True}
            if plan["expires_at"]<=time.time():
                raise ValueError("Plan expired; preview again")
            self.check_plan(plan)
            site=self.validate(plan["box"],plan["spec"]).model_copy(deep=True)
            self.consume_approval(plan)
            self.audit(plan_id,"host_requested_attempt",plan["box"])
            plan["status"]="uncertain" # Cancellation/transport failure never permits automatic retry.
            result=await self.remote_write(site,plan["spec"],plan["mode"],plan["expected"],plan.get("context"),plan["expires_at"])
            plan["result"]=result
            outcome=result.get("data",{}).get("outcome","uncertain")
            plan["status"]=outcome
            try:
                self.audit(plan_id,outcome,plan["box"])
            except OSError:
                result={**result,"audit_warning":"After-state audit failed; do not retry mutation"}
                plan["result"]=result
            return result

    async def rollback_preview(self,plan_id):
        self.enabled()
        if plan_id not in self.plans:
            raise ValueError("Unknown plan")
        plan=self.plans[plan_id]
        if plan["spec"]["kind"] in ("managed_lifecycle","managed_forward_batch"):
            raise ValueError("Lifecycle changes have no exact rollback; preview a separate compensating operation after inspection")
        if plan["status"]!="applied" or plan["mode"]!="apply":
            raise ValueError("No verified applied change to roll back")
        if plan["expires_at"]<=time.time():
            raise ValueError("Rollback window expired; inspect manually")
        self.check_plan(plan)
        site=self.validate(plan["box"],plan["spec"]).model_copy(deep=True)
        async with self.locks[plan["box"]]:
            current=await self.remote_write(site,plan["spec"],"preview",context=plan["result"]["data"].get("context"))
            expected=plan["result"]["data"]["state"]["fingerprint"]
            if current.get("status")!="ok" or current["data"]["fingerprint"]!=expected:
                return {"status":"stale","reason":"State changed since application. No automatic rollback."}
            return self.new_plan(plan["box"],plan["spec"],current["data"],"rollback",plan["result"]["data"].get("context"))
