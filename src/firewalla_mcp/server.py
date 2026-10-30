import json
import os
from pathlib import Path
from typing import Literal, Any
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import TypeAdapter
from .models import Config, Name, BoxName, Port, Mac, ForwardAction
from .transport import SSHTransport
from .writes import WriteManager
from .analysis import summarize_page
from .presentation import describe_rule, describe_vpn_inventory
from .membership import membership_directory, person_devices

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def build_server(config: Config, transport=None, readonly_catalog=False, vpn_write_catalog=False, import_transport=None):
    if vpn_write_catalog and (readonly_catalog or config.writes_enabled or not config.vpn_writes_enabled):
        raise ValueError("VPN-only catalog requires vpn_writes_enabled=true, writes_enabled=false and no read-only flag")
    if readonly_catalog and (config.writes_enabled or config.vpn_writes_enabled):
        raise ValueError("Read-only catalog requires writes_enabled=false")
    transport = transport or SSHTransport()
    mcp = FastMCP("Unofficial Firewalla diagnostics", stateless_http=True, json_response=True, max_request_body_size=65536)
    writes = WriteManager(config, transport)
    from .workflows import VPNWorkflowManager
    workflows = VPNWorkflowManager(config, transport)
    if vpn_write_catalog:
        from .vpn_writes import VPNWriteManager
        from .vpn_import_mcp import ImportManager
        writes = VPNWriteManager(config, transport)
        imports = ImportManager(config, import_transport)
        if config.vpn_target_policy == "approval_bound":
            writes.enabled()  # Verify the separate operator trust boundary before advertising writes.

    if not vpn_write_catalog and config.writes_enabled and config.vpn_writes_enabled:
        from .vpn_import_mcp import ImportManager
        imports = ImportManager(config, import_transport)

    if config.capture_enabled:
        from .capture import CaptureManager
        captures = CaptureManager(config)
        captures.enabled()

        @mcp.tool(annotations=READ)
        def preview_capture(box_name: BoxName, interface: str, protocol: Literal["tcp","udp","icmp"],
                            address: str | None = None, device: Mac | None = None, port: Port | None = None,
                            duration: int = 10, packets: int = 50) -> dict[str, Any]:
            """Preview exact privacy scope for 1–15s, 1–100packet header-only capture.
            Select one IP or MAC and an explicit interface (not any). Confirm before
            start_capture. SSH is internal; no raw packet payload or PCAP export.
            """
            return captures.preview(box_name,dict(interface=interface,protocol=protocol,address=address,device=device,port=port,duration=duration,packets=packets))

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False,destructiveHint=False,idempotentHint=False,openWorldHint=True))
        async def start_capture(plan_id: str) -> dict[str, Any]:
            """Start only after the host confirms the exact capture scope; return ready/status.
            No external probe sent. Wait for ready before a separately authorized probe.
            No arbitrary tcpdump arguments, files or shell. Poll capture_status for results.
            """
            return await captures.start(plan_id)

        @mcp.tool(annotations=READ)
        def capture_status(plan_id: str) -> dict[str, Any]:
            """Read bounded header metadata, counters and completeness. Zero is not no traffic."""
            return captures.status(plan_id)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False,destructiveHint=False,idempotentHint=True,openWorldHint=False))
        def cancel_capture(plan_id: str) -> dict[str, Any]:
            """Request termination of this capture; poll completion, bounded remote timeout remains."""
            return captures.cancel(plan_id)

    def box(name):
        TypeAdapter(BoxName).validate_python(name)
        name = config.resolve(name)
        if name not in config.sites:
            raise ValueError("unknown box")
        return config.sites[name]

    async def read(name, operation, **arguments):
        return await transport.run(box(name), operation, arguments)

    @mcp.tool(annotations=READ)
    def list_boxes() -> dict[str, Any]:
        """List configured box labels without addresses or credential paths."""
        return {"boxes": list(config.sites), "aliases": dict(config.aliases)}

    @mcp.tool(annotations=READ)
    async def service_status(box_name: BoxName) -> dict[str, Any]:
        """Read known systemd unit states including an OpenVPN server unit; no logs."""
        return await read(box_name, "services")

    @mcp.tool(annotations=READ)
    async def device_inventory(box_name: BoxName, cursor: str = "0") -> dict[str, Any]:
        """Read one bounded SCAN page of device MACs. Follow cursor until zero."""
        import re
        if not re.fullmatch(r"[0-9]{1,20}", cursor):
            raise ValueError("invalid cursor")
        return await read(box_name, "inventory", cursor=cursor)

    @mcp.tool(annotations=READ)
    async def people_and_devices(box_name: BoxName, person: str | None = None) -> dict[str, Any]:
        """Read explicit People/group membership and names, including empty groups.
        Optional exact person name or ID. No ownership inference from device names.
        Bounded 256 tags/1024 devices; incomplete scans report unknown counts.
        """
        if person is not None and (not isinstance(person,str) or not 1 <= len(person) <= 256):
            raise ValueError("invalid person selector")
        result=await read(box_name,"membership_snapshot")
        if result.get("status") != "ok": return result
        directory=membership_directory(result["data"])
        data=person_devices(directory,person) if person is not None else directory
        if len(json.dumps(data).encode())>120000:
            return {"status":"unsupported","reason":"Membership result limit; select an exact person to narrow output."}
        return {"status":"ok","data":data}

    @mcp.tool(annotations=READ)
    async def saved_vpn_profiles(box_name: BoxName) -> dict[str, Any]:
        """Read saved OpenVPN/WireGuard names, IDs and configured server endpoints.
        Includes disconnected profiles. Ports/transports are configured observations,
        not active endpoint, resolver DNS, connection health or routing proof.
        """
        from datetime import datetime, timezone
        result=await read(box_name,"saved_vpn_profiles")
        if result.get("status")=="ok":
            result={**result,"data":describe_vpn_inventory(result["data"],datetime.now(timezone.utc).isoformat())}
        return result

    @mcp.tool(annotations=READ)
    async def device_vpn_policy(box_name: BoxName, mac: Mac) -> dict[str, Any]:
        """Read explicit device VPN selection only; inherited/effective path unknown."""
        TypeAdapter(Mac).validate_python(mac)
        return await read(box_name, "device_policy", mac=mac)

    @mcp.tool(annotations=READ)
    async def vpn_interfaces(box_name: BoxName) -> dict[str, Any]:
        """List interface-name VPN candidates; not stored VPN profiles."""
        return await read(box_name, "vpn_interfaces")

    @mcp.tool(annotations=READ)
    async def interface_traffic(box_name: BoxName) -> dict[str, Any]:
        """Read bounded cumulative kernel byte/packet/error/drop counters."""
        return await read(box_name, "traffic")

    @mcp.tool(annotations=READ)
    async def active_alarm_count(box_name: BoxName, seconds: int = 3600) -> dict[str, Any]:
        """Count active-index alarms over 60 seconds to 7 days; no alarm content."""
        if type(seconds) is not int or not 60 <= seconds <= 604800:
            raise ValueError("invalid time window")
        return await read(box_name, "alarm_count", seconds=seconds)

    @mcp.tool(annotations=READ)
    async def dns_configuration(box_name: BoxName) -> dict[str, Any]:
        """Read system resolver IPs, omitting search domains and full configs."""
        return await read(box_name, "dns_config")

    @mcp.tool(annotations=READ)
    async def connection_metadata(box_name: BoxName, source_address: str) -> dict[str, Any]:
        """Read bounded conntrack address/port tuples for an allowlisted source IP."""
        box(box_name)
        address=config.target(box_name, source_address)
        return await read(box_name, "conntrack", address=address)

    @mcp.tool(annotations=READ)
    async def capabilities(box_name: BoxName) -> dict[str, Any]:
        """Probe utility presence; each data adapter additionally checks its schema."""
        return await read(box_name, "capabilities")

    @mcp.tool(annotations=READ)
    async def system_health(box_name: BoxName) -> dict[str, Any]:
        """Read uptime, load average and memory counters."""
        return await read(box_name, "health")

    @mcp.tool(annotations=READ)
    async def network_state(box_name: BoxName, kind: Literal["interfaces", "addresses", "routes", "rules", "neighbors"]) -> dict[str, Any]:
        """Read bounded network metadata, including VLAN IDs and routing rules."""
        return await read(box_name, "network", kind=kind)

    @mcp.tool(annotations=READ)
    async def device_lookup(box_name: BoxName, mac: Mac) -> dict[str, Any]:
        """Read a known device's IPv4 address; omit device names and other hash fields."""
        TypeAdapter(Mac).validate_python(mac)
        return await read(box_name, "device", mac=mac)

    @mcp.tool(annotations=READ)
    async def vpn_interface_status(box_name: BoxName, interface: Name) -> dict[str, Any]:
        """Inspect a selected VPN interface; not a provider-health or device-policy verdict."""
        TypeAdapter(Name).validate_python(interface)
        return await read(box_name, "vpn", interface=interface)

    @mcp.tool(annotations=READ)
    async def port_forward_mappings(box_name: BoxName) -> dict[str, Any]:
        """Read sanitized configured forwarding intent; not effective kernel mappings."""
        return await read(box_name, "mappings")

    @mcp.tool(annotations=READ)
    async def firewall_counters(box_name: BoxName, table: Literal["filter", "nat", "mangle"] = "filter") -> dict[str, Any]:
        """Read IPv4 rule counters with match details omitted; incomplete policy view."""
        return await read(box_name, "firewall", table=table)

    @mcp.tool(annotations=READ)
    async def ipset_names(box_name: BoxName) -> dict[str, Any]:
        """Read bounded ipset names without members."""
        return await read(box_name, "ipsets")

    @mcp.tool(annotations=READ)
    async def connection_summary(box_name: BoxName) -> dict[str, Any]:
        """Read router-local socket count; forwarded NAT sessions are unsupported."""
        return await read(box_name, "connections")

    @mcp.tool(annotations=READ)
    async def dns_lookup(box_name: BoxName, name: str) -> dict[str, Any]:
        """Resolve a DNS name with the router resolver; generates DNS traffic."""
        if not isinstance(name, str) or len(name)>253:
            raise ValueError("invalid DNS name")
        # Helper validates every label before invoking getent; no shell interpolation.
        return await read(box_name, "dns", name=name)

    @mcp.tool(annotations=READ)
    async def tcp_probe(box_name: BoxName, address: str, port: Port) -> dict[str, Any]:
        """Attempt one TCP handshake to a configured allowed IP; no payload sent."""
        box(box_name)
        TypeAdapter(Port).validate_python(port)
        address = config.target(box_name, address)
        return await read(box_name, "tcp", address=address, port=port)

    @mcp.tool(annotations=READ)
    async def diagnose_port_forward(box_name: BoxName, device_address: str, service_port: Port,
                                    vpn_interface: Name, provider_port: Port, public_address: str,
                                    external_box: BoxName | None = None) -> dict[str, Any]:
        """Separate service reachability, VPN interface, provider claim, mapping intent,
        and independent TCP reachability. Never infer global closure from a timeout.
        Provider assignment and interface selection are supplied claims, not discoveries.
        """
        box(box_name)
        TypeAdapter(Name).validate_python(vpn_interface)
        TypeAdapter(Port).validate_python(service_port)
        TypeAdapter(Port).validate_python(provider_port)
        config.target(box_name, device_address)
        config.target(box_name, public_address)
        if external_box:
            external = box(external_box)
            if external.vantage_group == box(box_name).vantage_group:
                raise ValueError("external box must have a different configured vantage group")
            config.target(external_box, public_address)
        service = await tcp_probe(box_name, device_address, service_port)
        vpn = await vpn_interface_status(box_name, vpn_interface)
        mappings = await port_forward_mappings(box_name)
        local = await tcp_probe(box_name, public_address, provider_port)
        outside = await tcp_probe(external_box, public_address, provider_port) if external_box else {"status":"not_tested"}
        connected = outside.get("data", {}).get("outcome") == "connected"
        return {"service_tcp": service, "selected_vpn_interface": vpn,
                "device_vpn_routing": {"status":"unsupported", "reason":"Policy inheritance and marks not validated"},
                "provider_assignment": {"status":"user_supplied", "port":provider_port},
                "configured_mappings": mappings,
                "effective_mapping": {"status":"unsupported", "reason":"Kernel NAT match and translation evaluation not implemented"},
                "same_site_probe": local, "independent_probe": outside,
                "verdict": "reachable_from_independent_vantage" if connected else "inconclusive",
                "limitations": "TCP only. Different vantage groups are operator assertions. A successful handshake does not verify application identity; timeout does not prove global closure. No changes performed."}

    @mcp.tool(annotations=READ)
    async def alarm_summaries(box_name: BoxName, limit: int = 5) -> dict[str, Any]:
        """Read 1–10 active-index alarm type/timestamp summaries; no descriptions or devices."""
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("limit must be 1 to 10")
        return await read(box_name, "alarm_summaries", limit=limit)

    @mcp.tool(annotations=READ)
    async def managed_rule_summaries(box_name: BoxName, limit: int = 5, cursor: str = "0",
                                     enabled: bool | None = None, action: Literal["allow","block","route","match","alarm","qos","snat"] | None = None,
                                     device: Mac | None = None, category: Name | None = None,
                                     all_pages: bool = False, max_records: int = 200) -> dict[str, Any]:
        """Read rule targets, named scopes, ports and schedules; configured state, not enforcement.
        limit 1–50 scanned entries/page. Follow next_cursor while has_more (even empty pages).
        total counts the unfiltered index, not filtered matches. Device filter is explicit MAC scope.
        all_pages traverses at most 10 pages/max_records 1–200; inspect has_more for continuation.
        """
        if type(limit) is not int or not 1 <= limit <= 50 or type(max_records) is not int or not 1 <= max_records <= 200:
            raise ValueError("invalid page bounds")
        if type(all_pages) is not bool or enabled is not None and type(enabled) is not bool:
            raise ValueError("invalid boolean filter")
        import re, hashlib
        if cursor!="0":
            if not re.fullmatch(r"[0-9]{1,4}:[a-f0-9]{40}:[a-f0-9]{16}",cursor):
                raise ValueError("invalid rule cursor; use next_cursor from this filtered query")
            offset,_,bound=cursor.split(":")
            signature=hashlib.sha256(json.dumps([enabled,action,device.upper() if device else None,category],separators=(",",":")).encode()).hexdigest()[:16]
            if int(offset)>2000 or bound!=signature:raise ValueError("cursor does not match filters")
        collected=[]; scanned=0; initial_cursor=cursor; previous_data=None
        for _ in range(10 if all_pages else 1):
            response=await read(box_name, "policy_summaries", limit=min(limit,max_records-len(collected)),
                                cursor=cursor,enabled=enabled,action=action,device=device,category=category)
            if response.get("status")!="ok":
                if collected or scanned:
                    return {"status":"partial","data":{**(previous_data or {}),"records":collected,"returned":len(collected),
                            "scanned":scanned,"cursor":cursor,"next_cursor":cursor,"has_more":True,"traversal_complete":False},
                            "reason":"Traversal interrupted; collected rows retained. Resume cursor or restart if index changed."}
                return response
            data=response["data"]
            data["records"]=[describe_rule(row) for row in data["records"]]
            if data.get("restart_required"):return response
            if len(json.dumps(collected+data["records"]).encode())>100000:
                data.update(records=collected,returned=len(collected),scanned=scanned,has_more=True,
                            may_have_more=True,next_cursor=cursor,cursor=cursor,traversal_complete=False,
                            output_limit_reached=True)
                return response
            collected.extend(data["records"]); scanned+=data.get("scanned",0)
            cursor=data.get("next_cursor"); previous_data=dict(data)
            if not all_pages or not data.get("has_more") or len(collected)>=max_records:break
        data.update(records=collected,returned=len(collected),scanned=scanned,
                    traversal_complete=not data.get("has_more",False),
                    matched_total=len(collected) if initial_cursor=="0" and not data.get("has_more",False) else None)
        return response

    @mcp.tool(annotations=READ)
    async def flow_sample_summary(box_name: BoxName, limit: int = 20) -> dict[str, Any]:
        """Aggregate 1–100 latest system flow records on router; no endpoints or payload returned.
        Sampled bytes are not historical usage or a billing total.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1 to 100")
        return await read(box_name, "flow_sample", limit=limit)

    @mcp.tool(annotations=READ)
    async def device_controls(box_name: BoxName, target_kind: Literal["device", "group"], target: str) -> dict[str, Any]:
        """Read explicit and global feature controls. Device target is a MAC; group is numeric ID.
        Scoped false means inherit, null explicit disable for Adblock/Safe Search/Unbound.
        Effective inherited behavior remains unknown; category/Internet controls are rules.
        """
        return await read(box_name,"control_state",target_kind=target_kind,target=target)

    @mcp.tool(annotations=READ)
    async def app_catalog(box_name: BoxName) -> dict[str, Any]:
        """Discover locally cached app feature flags; no cloud login or full init response.
        Blockable (acl) and usage-tracked (timeUsage) capabilities are distinct.
        """
        return await read(box_name,"app_catalog")

    @mcp.tool(annotations=READ)
    async def control_rule_page(box_name: BoxName, target_kind: Literal["device", "group"], target: str,
                                offset: int = 0, limit: int = 10) -> dict[str, Any]:
        """Read a filtered page of device/group/global candidate category/app/Internet rules.
        Exposes declared schedules only; does not resolve effective precedence or timers.
        """
        if type(offset) is not int or not 0<=offset<=10000 or type(limit) is not int or not 1<=limit<=20:
            raise ValueError("invalid page")
        return await read(box_name,"control_rules",target_kind=target_kind,target=target,offset=offset,limit=limit)

    @mcp.tool(annotations=READ)
    async def list_device_flows(box_name: BoxName, mac: Mac, start: int, end: int,
                                verdict: Literal["connections", "blocked", "all"] = "connections",
                                direction: Literal["all", "inbound", "outbound"] = "all",
                                offset: int = 0, limit: int = 20,
                                include_categories: list[Name] | None = None,
                                exclude_categories: list[Name] | None = None) -> dict[str, Any]:
        """Read a bounded device flow page in an explicit UTC epoch interval (max 7 days).
        Up to 25 records per source, 75 total; mutable-index pagination is not lossless.
        Domains are observed metadata, not browsing intent. Category IDs include games/av.
        """
        TypeAdapter(Mac).validate_python(mac)
        if any(type(x) is not int for x in (start,end,offset,limit)) or not 0<=start<end<=4102444800 or end-start>604800 or not 0<=offset<=10000 or not 1<=limit<=25:
            raise ValueError("invalid bounded interval/page")
        include_categories=include_categories or [];exclude_categories=exclude_categories or []
        if len(include_categories)+len(exclude_categories)>16:raise ValueError("too many filters")
        for value in include_categories+exclude_categories:TypeAdapter(Name).validate_python(value)
        return await read(box_name,"device_flows",mac=mac,start=start,end=end,offset=offset,limit=limit,
                          verdict=verdict,direction=direction,include_categories=include_categories,exclude_categories=exclude_categories)

    @mcp.tool(annotations=READ)
    async def analyze_device_flows(box_name: BoxName, mac: Mac, start: int, end: int,
                                   verdict: Literal["connections", "blocked", "all"] = "all",
                                   offset: int = 0, limit: int = 20) -> dict[str, Any]:
        """Summarize one bounded page: top destinations, known bytes, UTC hours and repeats.
        No anomaly verdict without a baseline; no sensitive behavioral inference.
        """
        result=await list_device_flows(box_name,mac,start,end,verdict=verdict,offset=offset,limit=limit)
        if result.get("status")!="ok":return result
        return {"status":"ok","data":summarize_page(result["data"])}

    @mcp.tool(annotations=READ)
    async def stage_device_control(box_name: BoxName, target_kind: Literal["device", "group"], target: str,
                                    control: Literal["internet","gaming","social","video","porn","safe_search","ad_block","unbound","app"],
                                    desired: Literal["enable","disable","inherit"], app_id: Name | None = None) -> dict[str, Any]:
        """Prepare a NON-EXECUTABLE control proposal with current observations.
        Persistent management and effective inheritance are not validated; no apply token issued.
        For category/app/Internet controls enable means enable blocking, not launch an app.
        """
        current=await device_controls(box_name,target_kind,target)
        target_id={"gaming":"games","social":"social","video":"av","porn":"porn"}.get(control)
        if control=="app":
            if not app_id:raise ValueError("app_id required")
            TypeAdapter(Name).validate_python(app_id)
            catalog=await app_catalog(box_name)
            entries=catalog.get("data",{}).get("apps",[])
            match=next((r for r in entries if r["id"]==app_id and r["ordinary_block_target"]),None)
            if not match:return {"status":"unsupported","reason":"App is not declared ACL-capable in observed catalog"}
            target_id=match["ordinary_block_target"]
        return {"status":"unsupported_write","executable":False,"current":current,
                "proposal":{"target_kind":target_kind,"target":target,"control":control,"desired":desired,"rule_target":target_id},
                "reason":"Persistent management path and effective inheritance not safely validated. No approval/apply token, rule, quota or setting created. Disabling a scoped override does not prove a global block is bypassed. User time limits are not device quotas."}

    @mcp.tool(annotations=READ)
    async def stage_vpn_switch(box_name: BoxName, mac: Mac, expected_profile: Name, destination_profile: Name) -> dict[str, Any]:
        """Stage a NON-EXECUTABLE device VPN M-to-N proposal; check explicit current M.
        Destination profile, strict/DNS preservation and effective routing cannot yet be validated.
        No configs, credentials, management requests, connection changes or apply token.
        """
        TypeAdapter(Name).validate_python(expected_profile);TypeAdapter(Name).validate_python(destination_profile)
        current=await device_vpn_policy(box_name,mac)
        observed=current.get("data",{}).get("explicit_policy") or {}
        if observed.get("state") is not True or observed.get("profile_id")!=expected_profile:
            return {"status":"stale_or_unresolved","current":current,"executable":False}
        return {"status":"unsupported_write","executable":False,"current":current,
                "proposal":{"mac":mac,"from":expected_profile,"to":destination_profile,"preserve":["strict VPN/kill switch","DNS behavior","all other profile and device policy fields"]},
                "required_validation":["destination profile exists and is compatible","secret-free strict/DNS settings fingerprint","supported persistent management path","effective device routing and return path","verified rollback to original profile"],
                "reason":"Profile catalog read approval and management/effective-path validation are outstanding. VPN profile import and group switching remain unsupported; existing-profile lifecycle has a separate executable preview; no credentials accepted by this tool."}

    @mcp.tool(annotations=READ)
    async def service_feature_status(box_name: BoxName, feature: Literal["all","doh","unbound","ntp","radius","custom_dns"] = "all") -> dict[str, Any]:
        """Read selected DNS service fields, NTP cached status and RADIUS feature flag only.
        No credentials, RADIUS config, DNS stamps/URLs, VPN profiles or full init response.
        Missing dynamic flags do not establish effective enablement; custom DNS is unsupported.
        """
        return await read(box_name,"service_features",feature=feature)

    @mcp.tool(annotations=READ)
    async def stage_service_change(box_name: BoxName, feature: Literal["doh","unbound","ntp","radius","custom_dns"],
                                    desired: Literal["enable","disable","inherit"],
                                    target_kind: Literal["device","group","network","global"], target: str) -> dict[str, Any]:
        """Produce a NON-EXECUTABLE service-scope proposal; no apply token or mutation.
        DNS overrides/CRUD, providers, clock changes and RADIUS enrollment/config are unsupported.
        """
        if target_kind=="device":TypeAdapter(Mac).validate_python(target)
        elif target_kind=="group":
            if not target.isdigit() or len(target)>20:raise ValueError("group ID")
        elif target_kind=="network":TypeAdapter(Name).validate_python(target)
        elif target!="global":raise ValueError("global target must be literal global")
        current=await service_feature_status(box_name,feature)
        return {"status":"unsupported_write","executable":False,"current":current,
                "proposal":{"feature":feature,"desired":desired,"target_kind":target_kind,"target":target},
                "reason":"Service management/scopes and effective behavior are not validated. No settings changed. RADIUS credentials/enrollment require separate explicit approval; NTP interception is not clock spoofing permission."}

    @mcp.tool(annotations=READ)
    def write_capabilities() -> dict[str, Any]:
        """Describe configured write gates and unsupported persistent management paths."""
        from .support import configured_contracts
        contracts = configured_contracts(config)
        if vpn_write_catalog:
            return {"configured_contracts":contracts,"enabled":True,"catalog_mode":"vpn_only","executable_write_tools_exposed":True,
                "live_writes_available":None,"deployment_validation":"Configured VPN-only mode; live availability requires a successful firmware/scope/SSH/state preview and exact approval. No live mutation validation claimed",
                "capabilities":["profile import preview/apply/verify", "existing profile start/stop", "device VPN switch with expected source"],
                "target_policy":config.vpn_target_policy,
                "confirmation_channel":"Authenticated MCP host enforces exact user confirmation; server executes internal SSH" if writes.host_confirmed() else "Exact user confirmation followed by authorized external SSH issuer invocation",
                "confirmation_mode":config.vpn_confirmation_mode,
                "approval_workflow":writes.approval_next_step(),
                "approval":"Single-use exact plan; confirmation enforcement follows confirmation_mode. Import also requires an explicit maintenance window",
                "unsupported":["unrestricted writes", "arbitrary files or shell", "unvalidated firmware", "authoritative inactive intent from link state"],
                "management_revisions_supported":list(__import__("firewalla_mcp.remote",fromlist=["VPN_MANAGEMENT_REVISIONS"]).VPN_MANAGEMENT_REVISIONS)}
        return {"configured_contracts":contracts,"enabled": config.writes_enabled and not readonly_catalog,
                "catalog_mode":"read_only" if readonly_catalog else "full",
                "confirmation_mode":config.write_confirmation_mode,
                "approval_workflow":writes.approval_next_step() if config.writes_enabled else None,
                "executable_write_tools_exposed":not readonly_catalog,
                "live_writes_available":None if config.writes_enabled and not readonly_catalog else False,
                "stage_tools":"Non-executable proposals only; never issue apply tokens",
                "implemented_in_source_not_deployment_validation": ["temporary IPv4 route addition in allowed nonreserved tables", "temporary IPv4 filter rule append in allowed existing chains", "temporary IPv4 DNAT append in allowed existing chains", "approved rollback of verified additions", "persistent IPv4 VPN NAT single mapping or 2–4 ordered same-target mappings; current source pins, mock-tested only", "revision-pinned device/group/network tri-state controls, scheduled app/category blocks, DNS answer rules, device VPN switches and profile lifecycle"],
                "approval": "Source write adapters require separate opt-in, version/scope checks and one-time approval; their presence does not establish live compatibility or availability",
                "deployment_validation":"Read-only tools tested; no live write enforcement or rollback validation claimed",
                "unsupported": ["persistent Firewalla routes; IPv6/general WAN/DMZ forwarding; arbitrary mixed/cross-plugin plans", "global policies, arbitrary existing rule updates, user time quotas", "profile import without its dedicated opt-in and registered input", "service restart/reboot/update", "arbitrary shell", "development HTTP routes"]}

    @mcp.tool(annotations=READ)
    async def preview_scheduled_block_rule(box_name: BoxName,device: Mac,
            rule_type: Literal["category","app"],target: str,hour: int,minute: int,
            days: list[int],duration_seconds: int,expected_timezone: str) -> dict[str, Any]:
        """Preview recurring device category/app block in router's verified configured timezone.
        days: unique 0=Sunday through 6=Saturday; duration 60..79200 seconds, no raw cron.
        DST follows Firewalla's scheduler. Rollback deletes only the created scheduled rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type=rule_type,target=target,
            schedule=dict(hour=hour,minute=minute,days=days,duration=duration_seconds,timezone=expected_timezone)))

    @mcp.tool(annotations=READ)
    async def preview_dns_override(box_name: BoxName,device: Mac,domain: str,address: str) -> dict[str, Any]:
        """Preview new persistent domain-and-subdomain DNS address rule for one device.
        Literal IPv4/IPv6 answer, IP-only response behavior. Not an upstream resolver setting.
        No existing override replacement; approved rollback deletes only this created rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type="dns_override",target=domain,address=address))

    @mcp.tool(annotations=READ)
    async def preview_scoped_service_control(box_name: BoxName,scope: Literal["group","network"],target: str,
            feature: Literal["adblock","safeSearch","unbound","doh","ntp_redirect"],
            desired: Literal["enable","disable","inherit"]) -> dict[str, Any]:
        """Preview a persistent group/network tri-state override with exact prior-value rollback.
        Target is numeric group ID or canonical network UUID, explicitly allowlisted in config.
        NTP only supports networks and requires already-enabled healthy NTP; no daemon/clock changes.
        Inherited/effective behavior remains unverified. Existing explicit recognized value required.
        """
        return await writes.preview(box_name,dict(kind="managed_scoped",scope=scope,target=target,feature=feature,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_vpn_lifecycle(box_name: BoxName,profile: Name,vpn_type: Literal["openvpn","wireguard"],
            desired: Literal["connect","disconnect"]) -> dict[str, Any]:
        """Preview profile-wide management start/stop for one existing VPN in the configured box.
        Target allowlists apply in legacy mode; approval-bound mode requires exact operator confirmation.
        Requires consistent cached/interface state; an absent cache with no interface is unknown,
        not already stopped. OpenVPN unit must already be disabled.
        May affect every device using profile; native start may restart its unit and stop disables it.
        No persistent system VPN policy is changed; no exact rollback. An inverse is a new approved change.
        Management may take 80 seconds; unknown outcomes never retry automatically.
        """
        return await writes.preview(box_name,dict(kind="managed_lifecycle",profile=profile,vpn_type=vpn_type,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_managed_device_control(box_name: BoxName, device: Mac,
            feature: Literal["adblock","safeSearch","unbound","doh"],
            desired: Literal["enable","disable","inherit"]) -> dict[str, Any]:
        """Preview persistent device policy through existing Firewalla management logic.
        Requires pinned clean source, allowlisted device, existing explicit policy and host approval.
        true=enable, false=inherit, null=explicit disable. Stored state is not enforcement proof.
        """
        return await writes.preview(box_name,dict(kind="managed_feature",device=device.upper(),feature=feature,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_managed_block_rule(box_name: BoxName, device: Mac,
            rule_type: Literal["internet","category","app","ip","dns"],target: str) -> dict[str, Any]:
        """Preview persistent outbound block for one device using policy:create.
        Categories: games/social/av/porn/vpn. Apps require dynamic ACL declaration.
        No schedules/allow rules/broad scope. Rollback deletes only this newly created rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type=rule_type,target=target))

    @mcp.tool(annotations=READ)
    async def preview_managed_vpn_switch(box_name: BoxName, device: Mac,
            expected_profile: Name,destination_profile: Name) -> dict[str, Any]:
        """Preview persistent device VPN policy switch between existing profiles in the configured box.
        Exact device/profile IDs and current source are bound to operator approval; no name inference.
        Requires explicit enabled source policy, matching selected safety/DNS settings, existing
        OpenVPN/WireGuard profiles. No profile credentials read/imported or settings changed.
        Selected settings are inspected locally; live validation requires separate approval.
        Effective device routing remains unverified until independent traffic checks.
        """
        return await writes.preview(box_name,dict(kind="managed_vpn",device=device.upper(),expected_profile=expected_profile,destination_profile=destination_profile))

    @mcp.tool(annotations=READ)
    async def preview_network_plan(box_name: BoxName, device: Mac, destination_ip: str,
            expected_profile: Name, destination_profile: Name, vpn_type: Literal["openvpn","wireguard"],
            forwards: list[ForwardAction], maintenance_until: int) -> dict[str, Any]:
        """Preview one bounded ordered plan: start VPN, switch device, add 1–2 forwards.
        One exact host confirmation covers all declared steps and dependencies.
        No external SSH/issuer; partial failure stops without automatic rollback.
        Requires no concurrent VPN/profile/policy/mapping edits. Preserves reviewed
        safety/DNS settings. Peer reachability and effective return routing unproved.
        Other plugins' actions are outside this executable plan.
        """
        import secrets
        return await workflows.preview_workflow(box_name,dict(kind="vpn_workflow",
            device=device.upper(),destination_ip=destination_ip,expected_profile=expected_profile,
            destination_profile=destination_profile,vpn_type=vpn_type,maintenance_until=maintenance_until,
            forwards=[{**v.model_dump(),"owner_token":secrets.token_hex(16)} for v in forwards]))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False,destructiveHint=True,idempotentHint=False,openWorldHint=True))
    async def apply_network_plan(plan_id: str) -> dict[str, Any]:
        """Apply an immutable network plan only after the host confirms every step.
        The host enforces human confirmation; server checks exact state transitions,
        expiry and single use. SSH is internal. Stops on uncertainty; no blind resume.
        """
        return await workflows.apply_workflow(plan_id)

    @mcp.tool(annotations=READ)
    async def preview_forward_plan(box_name: BoxName, device: Mac, destination_ip: str,
            profile: Name, actions: list[ForwardAction], maintenance_until: int) -> dict[str, Any]:
        """Preview 2–4 ordered persistent mappings for one device/VPN, one confirmation.
        Each exact protocol/port action is bound in one immutable plan. Not atomic:
        stop on an unverified step; no blind rollback or resume. Earlier verified
        mapping additions are accounted for without accepting unrelated state drift.
        VPN start/switch and external-app steps are not part of this bounded plan.
        Confirm the entire plan then apply_change; SSH stays internal.
        """
        import time,secrets
        if not 2<=len(actions)<=4 or type(maintenance_until) is not int or not time.time()<maintenance_until<=time.time()+600:
            raise ValueError("Bounded actions and maintenance window required")
        steps=[dict(kind="managed_forward",device=device.upper(),destination_ip=destination_ip,
                    profile=profile,**action.model_dump(),maintenance_until=maintenance_until,
                    owner_token=secrets.token_hex(16)) for action in actions]
        return await writes.preview(config.resolve(box_name),dict(kind="managed_forward_batch",steps=steps))

    @mcp.tool(annotations=READ)
    async def preview_persistent_vpn_forward(box_name: BoxName, device: Mac, destination_ip: str,
            profile: Name, protocol: Literal["tcp","udp"], external_port: Port,
            destination_port: Port, maintenance_until: int) -> dict[str, Any]:
        """Preview a persistent IPv4 FireMain mapping on one existing VPN profile.
        Requires an explicit matching device VPN policy, no conflicting mapping,
        and no concurrent mapping edits during the stated ten-minute window.
        One protocol per plan. Does not create firewall allows, obtain a provider
        port, change routing or flush connections. Stored config is not reachability.
        Confirm this exact preview then apply_change; SSH remains internal.
        """
        import time, secrets
        if type(maintenance_until) is not int or not time.time()<maintenance_until<=time.time()+600:
            raise ValueError("Explicit maintenance deadline within ten minutes required")
        return await writes.preview(config.resolve(box_name),dict(kind="managed_forward",
            device=device.upper(),destination_ip=destination_ip,profile=profile,protocol=protocol,
            external_port=external_port,destination_port=destination_port,
            maintenance_until=maintenance_until,owner_token=secrets.token_hex(16)))

    @mcp.tool(annotations=READ)
    async def preview_route_change(box_name: BoxName, destination: str, table: int,
                                   route_type: Literal["blackhole", "unicast"] = "blackhole",
                                   gateway: str | None = None, interface: Name | None = None) -> dict[str, Any]:
        """Preview adding a temporary IPv4 kernel route. Reserved/main tables excluded.
        No existing route replacement, policy rules or persistent Firewalla config changes.
        """
        return await writes.preview(box_name, {"kind":"route", "destination":destination,
            "table":table, "route_type":route_type,"gateway":gateway,"interface":interface})

    @mcp.tool(annotations=READ)
    async def preview_firewall_rule(box_name: BoxName, chain: Name, source: str, destination: str,
                                    protocol: Literal["tcp", "udp"], destination_port: Port,
                                    action: Literal["ACCEPT", "DROP", "REJECT"]) -> dict[str, Any]:
        """Preview one temporary IPv4 filter rule appended to an allowed existing chain.
        This is kernel state, not a Firewalla app rule. May affect connectivity.
        """
        return await writes.preview(box_name,{"kind":"filter_rule","chain":chain,"source":source,
            "destination":destination,"protocol":protocol,"destination_port":destination_port,"action":action})

    @mcp.tool(annotations=READ)
    async def preview_port_forward(box_name: BoxName, chain: Name, public_address: str,
                                    interface: Name, protocol: Literal["tcp", "udp"], external_port: Port,
                                    destination_address: str, destination_port: Port) -> dict[str, Any]:
        """Preview one temporary IPv4 DNAT rule in an allowed existing NAT chain.
        Does not add filter acceptance, SNAT, policy routing or a persistent Firewalla mapping.
        """
        return await writes.preview(box_name,{"kind":"dnat","chain":chain,"public_address":public_address,
            "interface":interface,"protocol":protocol,"external_port":external_port,
            "destination_address":destination_address,"destination_port":destination_port})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    async def apply_change(plan_id: str) -> dict[str, Any]:
        """Apply or roll back an exact preview after its configured confirmation workflow.
        In host_confirmed mode obtain exact user confirmation in the authenticated
        MCP host, then call this tool directly. SSH remains internal; no issuer file.
        Approval is single-use, expires after 10 minutes, and must match the preview digest.
        Stale/uncertain states are never automatically retried. May disrupt networking.
        """
        return await writes.apply(plan_id)

    @mcp.tool(annotations=READ)
    async def preview_rollback(plan_id: str) -> dict[str, Any]:
        """Preview removal of a verified addition while its complete snapshot is unchanged.
        Requires a new operator approval and apply_change call. Not a generic undo tool.
        """
        return await writes.rollback_preview(plan_id)

    if vpn_write_catalog or (config.writes_enabled and config.vpn_writes_enabled):
        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True))
        async def preview_vpn_import(box_name: BoxName, source_profile: Name, archive_id: Name,
                maintenance_until: int, destination_mode: Literal["0600","0644"] = "0644",
                source_permission: Literal["owner_only","existing_0644"] = "owner_only") -> dict[str, Any]:
            """Preview up to three new inactive/unassigned OpenVPN profiles from a registered router-local archive.
            Reads source credentials only on router and creates a private journal. No upload/config/password argument.
            maintenance_until is UTC epoch seconds within ten minutes: owner must avoid concurrent VPN/policy edits.
            0644 permits other local users to read files; TLS-auth/compression require registered operator opt-in.
            source_permission selects owner-only or the bounded existing0644 source exception; it is not consent.
            Passive checks cannot atomically prevent another actor starting a profile. No automatic approval.
            """
            return await imports.preview_import(box_name,source_profile,archive_id,destination_mode,maintenance_until,source_permission)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
        async def apply_vpn_import(plan_id: str) -> dict[str, Any]:
            """Apply an exact import preview after single-use host approval. Never starts/assigns a VPN.
            Follow preview.next_step. In host_confirmed mode obtain exact user
            confirmation in the MCP host, then call this tool directly; SSH stays
            internal. Legacy operator mode requires its configured issuer. Stop on
            host denial; never manufacture consent or approval files.
            Uncertain outcomes require inspection; never retry automatically. Credentials remain router-local.
            """
            return await imports.apply_import(plan_id)

        @mcp.tool(annotations=READ)
        async def verify_vpn_import(box_name: BoxName, transaction: str) -> dict[str, Any]:
            """Verify owned imported files and current references/passive state, without returning secrets.
            A profile started/assigned by another actor makes inactive verification fail; never undo it.
            """
            return await imports.verify_import(box_name,transaction)

        @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True))
        async def apply_vpn_change(plan_id: str) -> dict[str, Any]:
            """Apply the exact VPN plan after confirmation using preview.next_step.
            In host_confirmed mode the authenticated MCP host must obtain explicit
            user confirmation, then call this tool directly. SSH is internal; no
            external SSH or file issuance is needed. The server does not attest consent.
            Legacy operator mode uses authorized SSH issuance described in next_step.
            Never bypass host denial or treat model-generated consent as confirmation.
            """
            if plan_id in writes.plans and writes.plans[plan_id]["spec"]["kind"] not in ("managed_vpn","managed_lifecycle"):
                raise ValueError("VPN apply only accepts VPN lifecycle/device plans")
            return await writes.apply(plan_id)

        @mcp.tool(annotations=READ)
        async def preview_vpn_change_rollback(plan_id: str) -> dict[str, Any]:
            """Preview restoring a verified device policy switch if unchanged. Start/stop has no exact rollback."""
            if plan_id in writes.plans and writes.plans[plan_id]["spec"]["kind"]!="managed_vpn":
                raise ValueError("VPN rollback only accepts a device VPN plan")
            return await writes.rollback_preview(plan_id)

    if readonly_catalog or vpn_write_catalog:
        for name in ("preview_network_plan","apply_network_plan","preview_forward_plan","preview_persistent_vpn_forward","apply_change","preview_route_change","preview_firewall_rule","preview_port_forward","preview_rollback","preview_managed_device_control","preview_managed_block_rule","preview_managed_vpn_switch","preview_scheduled_block_rule","preview_dns_override","preview_scoped_service_control","preview_vpn_lifecycle"):
            if vpn_write_catalog and name in ("preview_vpn_lifecycle","preview_managed_vpn_switch"):
                continue
            mcp.remove_tool(name)
    return mcp


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Unofficial SSH-backed Firewalla MCP")
    parser.add_argument("--transport",choices=("stdio","streamable-http"),default="stdio")
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8000)
    catalogs=parser.add_mutually_exclusive_group()
    catalogs.add_argument("--allow-write-catalog",action="store_true")
    catalogs.add_argument("--vpn-write-catalog",action="store_true")
    args=parser.parse_args()
    path = os.environ.get("FIREWALLA_MCP_CONFIG", "/config/config.json")
    config = Config.model_validate_json(Path(path).read_text())
    if args.transport=="stdio":
        build_server(config, readonly_catalog=not(args.allow_write_catalog or args.vpn_write_catalog),
                     vpn_write_catalog=args.vpn_write_catalog).run(transport="stdio")
        return
    if not 1<=args.port<=65535:parser.error("invalid port")
    token_file=os.environ.get("FIREWALLA_MCP_HTTP_TOKEN_FILE")
    if not token_file:parser.error("FIREWALLA_MCP_HTTP_TOKEN_FILE required for HTTP")
    hosts=[v.strip() for v in os.environ.get("FIREWALLA_MCP_HTTP_ALLOWED_HOSTS", "").split(",") if v.strip()]
    if not hosts:
        if args.host not in ("127.0.0.1","localhost"):parser.error("Non-loopback bind requires explicit HTTP Host allowlist")
        hosts=["127.0.0.1:"+str(args.port),"localhost:"+str(args.port)]
    if args.allow_write_catalog and not config.writes_enabled:parser.error("Write catalog requires explicit writes_enabled=true")
    server=build_server(config,readonly_catalog=not(args.allow_write_catalog or args.vpn_write_catalog),
                        vpn_write_catalog=args.vpn_write_catalog)
    from .http import http_app
    import uvicorn
    uvicorn.run(http_app(server,token_file,hosts),host=args.host,port=args.port,access_log=False,log_level="warning")

if __name__ == "__main__":
    main()
