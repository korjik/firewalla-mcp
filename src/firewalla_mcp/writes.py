"""Host-approved, temporary kernel changes. No MCP tool can issue an approval."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
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

    def enabled(self):
        if not self.config.writes_enabled:
            raise ValueError("Writes disabled. Operator must enable writes and configure host approvals.")
        if not self.config.approval_directory or not self.config.audit_file:
            raise ValueError("Approval directory and audit file required")
        directory=Path(self.config.approval_directory)
        if not directory.is_absolute() or not Path(self.config.audit_file).is_absolute():
            raise ValueError("Absolute approval/audit paths required")
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError("Approval directory must not be a symlink or group/world writable")

    def validate(self,box_name,spec):
        self.enabled()
        if box_name not in self.config.sites:
            raise ValueError("Unknown box")
        site=self.config.sites[box_name]
        kind=spec["kind"]
        if kind.startswith("managed_"):
            from .remote import validate_managed, MANAGEMENT_REVISION
            validate_managed(spec)
            if site.management_revision != MANAGEMENT_REVISION:
                raise ValueError("Explicit reviewed management revision required")
            if spec["device"] not in [v.upper() for v in site.managed_devices]:
                raise ValueError("Device outside managed allowlist")
            if kind == "managed_vpn" and any(spec[k] not in site.managed_vpn_profiles for k in ("expected_profile","destination_profile")):
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
        plan_id=secrets.token_hex(16)
        plan={"plan_id":plan_id,"box":box,"spec":spec,"expected":state["fingerprint"],
              "mode":mode,"expires_at":now+600,"scope":"persistent_managed" if spec["kind"].startswith("managed_") else "temporary_kernel_only"}
        if context is not None:
            plan["context"]=context
        plan["digest"]=digest(plan)
        plan["status"]="pending"
        self.plans[plan_id]=plan
        return {**plan,"approval_file":str(Path(self.config.approval_directory)/(plan_id+".json")),
                "approval_document":{"plan_id":plan_id,"digest":plan["digest"],"expires_at":plan["expires_at"],"approved":True},
                "diff":{"operation":"apply" if mode=="apply" else "restore_exact_prior_state","object":spec,"before":state.get("field")},
                "warning":"Review out of band. Kernel changes may be overwritten. Managed state acknowledgment does not prove asynchronous enforcement. No automatic approval or retry. Concurrent external writers cannot be made atomic."}

    async def remote_write(self,site,spec,mode,expected=None,context=None):
        managed=spec["kind"].startswith("managed_")
        args={"mode":mode,"spec":spec}
        if expected is not None: args["expected"]=expected
        if context is not None: args["context"]=context
        if managed: args["revision"]=site.management_revision
        return await self.transport.run(site,"managed_write" if managed else "write",args)

    async def preview(self,box,spec):
        site=self.validate(box,spec)
        async with self.locks[box]:
            result=await self.remote_write(site,spec,"preview")
            if result.get("status")!="ok":
                return result
            state=result["data"]
            if state["present"]:
                return {"status":"no_change","reason":"Desired state or potentially duplicate rule already exists; no replacement is permitted."}
            return self.new_plan(box,spec,state,"apply")

    def consume_approval(self,plan):
        path=Path(self.config.approval_directory)/(plan["plan_id"]+".json")
        # Atomically claim one approval before reading; concurrent invocations cannot reuse it.
        claimed=path.with_suffix(".used")
        if claimed.exists():
            raise ValueError("Approval already consumed")
        try:
            os.link(path,claimed,follow_symlinks=False)
            path.unlink()
            fd=os.open(claimed,os.O_RDONLY|os.O_NOFOLLOW)
        except OSError:
            raise ValueError("Missing or invalid operator approval") from None
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size>4096:
                raise ValueError("Unsafe approval file")
            approval=json.loads(os.read(fd,4097))
        finally:
            os.close(fd)
        if approval!={"plan_id":plan["plan_id"],"digest":plan["digest"],"expires_at":plan["expires_at"],"approved":True}:
            raise ValueError("Approval does not match preview")

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
            site=self.validate(plan["box"],plan["spec"])
            self.consume_approval(plan)
            self.audit(plan_id,"approved_attempt",plan["box"])
            plan["status"]="uncertain" # Cancellation/transport failure never permits automatic retry.
            result=await self.remote_write(site,plan["spec"],plan["mode"],plan["expected"],plan.get("context"))
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
        if plan["status"]!="applied" or plan["mode"]!="apply":
            raise ValueError("No verified applied change to roll back")
        if plan["expires_at"]<=time.time():
            raise ValueError("Rollback window expired; inspect manually")
        site=self.validate(plan["box"],plan["spec"])
        async with self.locks[plan["box"]]:
            current=await self.remote_write(site,plan["spec"],"preview",context=plan["result"]["data"].get("context"))
            expected=plan["result"]["data"]["state"]["fingerprint"]
            if current.get("status")!="ok" or current["data"]["fingerprint"]!=expected:
                return {"status":"stale","reason":"State changed since application. No automatic rollback."}
            return self.new_plan(plan["box"],plan["spec"],current["data"],"rollback",plan["result"]["data"].get("context"))
