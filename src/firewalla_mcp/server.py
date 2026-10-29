import json
import os
from pathlib import Path
from typing import Literal
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import TypeAdapter
from .models import Config, Name, Port, Mac
from .transport import SSHTransport
from .writes import WriteManager
from .analysis import summarize_page

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def build_server(config: Config, transport=None, readonly_catalog=False):
    if readonly_catalog and config.writes_enabled:
        raise ValueError("Read-only catalog requires writes_enabled=false")
    transport = transport or SSHTransport()
    mcp = FastMCP("Unofficial Firewalla diagnostics", stateless_http=True, json_response=True, max_request_body_size=65536)
    writes = WriteManager(config, transport)

    def box(name):
        TypeAdapter(Name).validate_python(name)
        if name not in config.sites:
            raise ValueError("unknown box")
        return config.sites[name]

    async def read(name, operation, **arguments):
        return await transport.run(box(name), operation, arguments)

    @mcp.tool(annotations=READ)
    def list_boxes() -> dict:
        """List configured box labels without addresses or credential paths."""
        return {"boxes": list(config.sites)}

    @mcp.tool(annotations=READ)
    async def service_status(box_name: Name) -> dict:
        """Read known systemd unit states including an OpenVPN server unit; no logs."""
        return await read(box_name, "services")

    @mcp.tool(annotations=READ)
    async def device_inventory(box_name: Name, cursor: str = "0") -> dict:
        """Read one bounded SCAN page of device MACs. Follow cursor until zero."""
        import re
        if not re.fullmatch(r"[0-9]{1,20}", cursor):
            raise ValueError("invalid cursor")
        return await read(box_name, "inventory", cursor=cursor)

    @mcp.tool(annotations=READ)
    async def device_vpn_policy(box_name: Name, mac: Mac) -> dict:
        """Read explicit device VPN selection only; inherited/effective path unknown."""
        TypeAdapter(Mac).validate_python(mac)
        return await read(box_name, "device_policy", mac=mac)

    @mcp.tool(annotations=READ)
    async def vpn_interfaces(box_name: Name) -> dict:
        """List interface-name VPN candidates; not stored VPN profiles."""
        return await read(box_name, "vpn_interfaces")

    @mcp.tool(annotations=READ)
    async def interface_traffic(box_name: Name) -> dict:
        """Read bounded cumulative kernel byte/packet/error/drop counters."""
        return await read(box_name, "traffic")

    @mcp.tool(annotations=READ)
    async def active_alarm_count(box_name: Name, seconds: int = 3600) -> dict:
        """Count active-index alarms over 60 seconds to 7 days; no alarm content."""
        if type(seconds) is not int or not 60 <= seconds <= 604800:
            raise ValueError("invalid time window")
        return await read(box_name, "alarm_count", seconds=seconds)

    @mcp.tool(annotations=READ)
    async def dns_configuration(box_name: Name) -> dict:
        """Read system resolver IPs, omitting search domains and full configs."""
        return await read(box_name, "dns_config")

    @mcp.tool(annotations=READ)
    async def connection_metadata(box_name: Name, source_address: str) -> dict:
        """Read bounded conntrack address/port tuples for an allowlisted source IP."""
        box(box_name)
        address=config.target(box_name, source_address)
        return await read(box_name, "conntrack", address=address)

    @mcp.tool(annotations=READ)
    async def capabilities(box_name: Name) -> dict:
        """Probe utility presence; each data adapter additionally checks its schema."""
        return await read(box_name, "capabilities")

    @mcp.tool(annotations=READ)
    async def system_health(box_name: Name) -> dict:
        """Read uptime, load average and memory counters."""
        return await read(box_name, "health")

    @mcp.tool(annotations=READ)
    async def network_state(box_name: Name, kind: Literal["interfaces", "addresses", "routes", "rules", "neighbors"]) -> dict:
        """Read bounded network metadata, including VLAN IDs and routing rules."""
        return await read(box_name, "network", kind=kind)

    @mcp.tool(annotations=READ)
    async def device_lookup(box_name: Name, mac: Mac) -> dict:
        """Read a known device's IPv4 address; omit device names and other hash fields."""
        TypeAdapter(Mac).validate_python(mac)
        return await read(box_name, "device", mac=mac)

    @mcp.tool(annotations=READ)
    async def vpn_interface_status(box_name: Name, interface: Name) -> dict:
        """Inspect a selected VPN interface; not a provider-health or device-policy verdict."""
        TypeAdapter(Name).validate_python(interface)
        return await read(box_name, "vpn", interface=interface)

    @mcp.tool(annotations=READ)
    async def port_forward_mappings(box_name: Name) -> dict:
        """Read sanitized configured forwarding intent; not effective kernel mappings."""
        return await read(box_name, "mappings")

    @mcp.tool(annotations=READ)
    async def firewall_counters(box_name: Name, table: Literal["filter", "nat", "mangle"] = "filter") -> dict:
        """Read IPv4 rule counters with match details omitted; incomplete policy view."""
        return await read(box_name, "firewall", table=table)

    @mcp.tool(annotations=READ)
    async def ipset_names(box_name: Name) -> dict:
        """Read bounded ipset names without members."""
        return await read(box_name, "ipsets")

    @mcp.tool(annotations=READ)
    async def connection_summary(box_name: Name) -> dict:
        """Read router-local socket count; forwarded NAT sessions are unsupported."""
        return await read(box_name, "connections")

    @mcp.tool(annotations=READ)
    async def dns_lookup(box_name: Name, name: str) -> dict:
        """Resolve a DNS name with the router resolver; generates DNS traffic."""
        if not isinstance(name, str) or len(name)>253:
            raise ValueError("invalid DNS name")
        # Helper validates every label before invoking getent; no shell interpolation.
        return await read(box_name, "dns", name=name)

    @mcp.tool(annotations=READ)
    async def tcp_probe(box_name: Name, address: str, port: Port) -> dict:
        """Attempt one TCP handshake to a configured allowed IP; no payload sent."""
        box(box_name)
        TypeAdapter(Port).validate_python(port)
        address = config.target(box_name, address)
        return await read(box_name, "tcp", address=address, port=port)

    @mcp.tool(annotations=READ)
    async def diagnose_port_forward(box_name: Name, device_address: str, service_port: Port,
                                    vpn_interface: Name, provider_port: Port, public_address: str,
                                    external_box: Name | None = None) -> dict:
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
    async def alarm_summaries(box_name: Name, limit: int = 5) -> dict:
        """Read 1–10 active-index alarm type/timestamp summaries; no descriptions or devices."""
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("limit must be 1 to 10")
        return await read(box_name, "alarm_summaries", limit=limit)

    @mcp.tool(annotations=READ)
    async def managed_rule_summaries(box_name: Name, limit: int = 5) -> dict:
        """Read 1–10 managed rule type/action/state summaries; no targets or enforcement claim."""
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError("limit must be 1 to 10")
        return await read(box_name, "policy_summaries", limit=limit)

    @mcp.tool(annotations=READ)
    async def flow_sample_summary(box_name: Name, limit: int = 20) -> dict:
        """Aggregate 1–100 latest system flow records on router; no endpoints or payload returned.
        Sampled bytes are not historical usage or a billing total.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1 to 100")
        return await read(box_name, "flow_sample", limit=limit)

    @mcp.tool(annotations=READ)
    async def device_controls(box_name: Name, target_kind: Literal["device", "group"], target: str) -> dict:
        """Read explicit and global feature controls. Device target is a MAC; group is numeric ID.
        Scoped false means inherit, null explicit disable for Adblock/Safe Search/Unbound.
        Effective inherited behavior remains unknown; category/Internet controls are rules.
        """
        return await read(box_name,"control_state",target_kind=target_kind,target=target)

    @mcp.tool(annotations=READ)
    async def app_catalog(box_name: Name) -> dict:
        """Discover locally cached app feature flags; no cloud login or full init response.
        Blockable (acl) and usage-tracked (timeUsage) capabilities are distinct.
        """
        return await read(box_name,"app_catalog")

    @mcp.tool(annotations=READ)
    async def control_rule_page(box_name: Name, target_kind: Literal["device", "group"], target: str,
                                offset: int = 0, limit: int = 10) -> dict:
        """Read a filtered page of device/group/global candidate category/app/Internet rules.
        Exposes declared schedules only; does not resolve effective precedence or timers.
        """
        if type(offset) is not int or not 0<=offset<=10000 or type(limit) is not int or not 1<=limit<=20:
            raise ValueError("invalid page")
        return await read(box_name,"control_rules",target_kind=target_kind,target=target,offset=offset,limit=limit)

    @mcp.tool(annotations=READ)
    async def list_device_flows(box_name: Name, mac: Mac, start: int, end: int,
                                verdict: Literal["connections", "blocked", "all"] = "connections",
                                direction: Literal["all", "inbound", "outbound"] = "all",
                                offset: int = 0, limit: int = 20,
                                include_categories: list[Name] | None = None,
                                exclude_categories: list[Name] | None = None) -> dict:
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
    async def analyze_device_flows(box_name: Name, mac: Mac, start: int, end: int,
                                   verdict: Literal["connections", "blocked", "all"] = "all",
                                   offset: int = 0, limit: int = 20) -> dict:
        """Summarize one bounded page: top destinations, known bytes, UTC hours and repeats.
        No anomaly verdict without a baseline; no sensitive behavioral inference.
        """
        result=await list_device_flows(box_name,mac,start,end,verdict=verdict,offset=offset,limit=limit)
        if result.get("status")!="ok":return result
        return {"status":"ok","data":summarize_page(result["data"])}

    @mcp.tool(annotations=READ)
    async def stage_device_control(box_name: Name, target_kind: Literal["device", "group"], target: str,
                                    control: Literal["internet","gaming","social","video","porn","safe_search","ad_block","unbound","app"],
                                    desired: Literal["enable","disable","inherit"], app_id: Name | None = None) -> dict:
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
    async def stage_vpn_switch(box_name: Name, mac: Mac, expected_profile: Name, destination_profile: Name) -> dict:
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
    async def service_feature_status(box_name: Name, feature: Literal["all","doh","unbound","ntp","radius","custom_dns"] = "all") -> dict:
        """Read selected DNS service fields, NTP cached status and RADIUS feature flag only.
        No credentials, RADIUS config, DNS stamps/URLs, VPN profiles or full init response.
        Missing dynamic flags do not establish effective enablement; custom DNS is unsupported.
        """
        return await read(box_name,"service_features",feature=feature)

    @mcp.tool(annotations=READ)
    async def stage_service_change(box_name: Name, feature: Literal["doh","unbound","ntp","radius","custom_dns"],
                                    desired: Literal["enable","disable","inherit"],
                                    target_kind: Literal["device","group","network","global"], target: str) -> dict:
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
    def write_capabilities() -> dict:
        """Describe configured write gates and unsupported persistent management paths."""
        return {"enabled": config.writes_enabled,
                "implemented": ["temporary IPv4 route addition in allowed nonreserved tables", "temporary IPv4 filter rule append in allowed existing chains", "temporary IPv4 DNAT append in allowed existing chains", "approved rollback of verified additions", "revision-pinned device/group/network tri-state controls, scheduled app/category blocks, DNS answer rules, device VPN switches and profile lifecycle"],
                "approval": "Operator-created one-time approval file bound to preview digest; no MCP approval tool",
                "unsupported": ["persistent Firewalla routes/port forwards", "global policies, arbitrary existing rule updates, user time quotas", "VPN profile import", "service restart/reboot/update", "arbitrary shell", "development HTTP routes"]}

    @mcp.tool(annotations=READ)
    async def preview_scheduled_block_rule(box_name: Name,device: Mac,
            rule_type: Literal["category","app"],target: str,hour: int,minute: int,
            days: list[int],duration_seconds: int,expected_timezone: str) -> dict:
        """Preview recurring device category/app block in router's verified configured timezone.
        days: unique 0=Sunday through 6=Saturday; duration 60..79200 seconds, no raw cron.
        DST follows Firewalla's scheduler. Rollback deletes only the created scheduled rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type=rule_type,target=target,
            schedule=dict(hour=hour,minute=minute,days=days,duration=duration_seconds,timezone=expected_timezone)))

    @mcp.tool(annotations=READ)
    async def preview_dns_override(box_name: Name,device: Mac,domain: str,address: str) -> dict:
        """Preview new persistent domain-and-subdomain DNS address rule for one device.
        Literal IPv4/IPv6 answer, IP-only response behavior. Not an upstream resolver setting.
        No existing override replacement; approved rollback deletes only this created rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type="dns_override",target=domain,address=address))

    @mcp.tool(annotations=READ)
    async def preview_scoped_service_control(box_name: Name,scope: Literal["group","network"],target: str,
            feature: Literal["adblock","safeSearch","unbound","doh","ntp_redirect"],
            desired: Literal["enable","disable","inherit"]) -> dict:
        """Preview a persistent group/network tri-state override with exact prior-value rollback.
        Target is numeric group ID or canonical network UUID, explicitly allowlisted in config.
        NTP only supports networks and requires already-enabled healthy NTP; no daemon/clock changes.
        Inherited/effective behavior remains unverified. Existing explicit recognized value required.
        """
        return await writes.preview(box_name,dict(kind="managed_scoped",scope=scope,target=target,feature=feature,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_vpn_lifecycle(box_name: Name,profile: Name,vpn_type: Literal["openvpn","wireguard"],
            desired: Literal["connect","disconnect"]) -> dict:
        """Preview profile-wide management start/stop for one existing allowlisted VPN.
        Requires consistent cached/interface state; OpenVPN unit must already be disabled.
        May affect every device using profile; no exact rollback. An inverse is a new approved change.
        Management may take 80 seconds; unknown outcomes never retry automatically.
        """
        return await writes.preview(box_name,dict(kind="managed_lifecycle",profile=profile,vpn_type=vpn_type,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_managed_device_control(box_name: Name, device: Mac,
            feature: Literal["adblock","safeSearch","unbound","doh"],
            desired: Literal["enable","disable","inherit"]) -> dict:
        """Preview persistent device policy through existing Firewalla management logic.
        Requires pinned clean source, allowlisted device, existing explicit policy and host approval.
        true=enable, false=inherit, null=explicit disable. Stored state is not enforcement proof.
        """
        return await writes.preview(box_name,dict(kind="managed_feature",device=device.upper(),feature=feature,desired=desired))

    @mcp.tool(annotations=READ)
    async def preview_managed_block_rule(box_name: Name, device: Mac,
            rule_type: Literal["internet","category","app","ip","dns"],target: str) -> dict:
        """Preview persistent outbound block for one device using policy:create.
        Categories: games/social/av/porn/vpn. Apps require dynamic ACL declaration.
        No schedules/allow rules/broad scope. Rollback deletes only this newly created rule.
        """
        return await writes.preview(box_name,dict(kind="managed_rule",device=device.upper(),rule_type=rule_type,target=target))

    @mcp.tool(annotations=READ)
    async def preview_managed_vpn_switch(box_name: Name, device: Mac,
            expected_profile: Name,destination_profile: Name) -> dict:
        """Preview persistent device VPN policy switch between existing allowlisted profiles.
        Requires explicit enabled source policy, matching selected safety/DNS settings, existing
        OpenVPN/WireGuard profiles. No profile credentials read/imported or settings changed.
        Selected settings are inspected locally; live validation requires separate approval.
        Effective device routing remains unverified until independent traffic checks.
        """
        return await writes.preview(box_name,dict(kind="managed_vpn",device=device.upper(),expected_profile=expected_profile,destination_profile=destination_profile))

    @mcp.tool(annotations=READ)
    async def preview_route_change(box_name: Name, destination: str, table: int,
                                   route_type: Literal["blackhole", "unicast"] = "blackhole",
                                   gateway: str | None = None, interface: Name | None = None) -> dict:
        """Preview adding a temporary IPv4 kernel route. Reserved/main tables excluded.
        No existing route replacement, policy rules or persistent Firewalla config changes.
        """
        return await writes.preview(box_name, {"kind":"route", "destination":destination,
            "table":table, "route_type":route_type,"gateway":gateway,"interface":interface})

    @mcp.tool(annotations=READ)
    async def preview_firewall_rule(box_name: Name, chain: Name, source: str, destination: str,
                                    protocol: Literal["tcp", "udp"], destination_port: Port,
                                    action: Literal["ACCEPT", "DROP", "REJECT"]) -> dict:
        """Preview one temporary IPv4 filter rule appended to an allowed existing chain.
        This is kernel state, not a Firewalla app rule. May affect connectivity.
        """
        return await writes.preview(box_name,{"kind":"filter_rule","chain":chain,"source":source,
            "destination":destination,"protocol":protocol,"destination_port":destination_port,"action":action})

    @mcp.tool(annotations=READ)
    async def preview_port_forward(box_name: Name, chain: Name, public_address: str,
                                    interface: Name, protocol: Literal["tcp", "udp"], external_port: Port,
                                    destination_address: str, destination_port: Port) -> dict:
        """Preview one temporary IPv4 DNAT rule in an allowed existing NAT chain.
        Does not add filter acceptance, SNAT, policy routing or a persistent Firewalla mapping.
        """
        return await writes.preview(box_name,{"kind":"dnat","chain":chain,"public_address":public_address,
            "interface":interface,"protocol":protocol,"external_port":external_port,
            "destination_address":destination_address,"destination_port":destination_port})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True))
    async def apply_change(plan_id: str) -> dict:
        """Apply or roll back an exact preview ONLY after out-of-band host approval.
        Approval is single-use, expires after 10 minutes, and must match the preview digest.
        Stale/uncertain states are never automatically retried. May disrupt networking.
        """
        return await writes.apply(plan_id)

    @mcp.tool(annotations=READ)
    async def preview_rollback(plan_id: str) -> dict:
        """Preview removal of a verified addition while its complete snapshot is unchanged.
        Requires a new operator approval and apply_change call. Not a generic undo tool.
        """
        return await writes.rollback_preview(plan_id)

    if readonly_catalog:
        for name in ("apply_change","preview_route_change","preview_firewall_rule","preview_port_forward","preview_rollback","preview_managed_device_control","preview_managed_block_rule","preview_managed_vpn_switch","preview_scheduled_block_rule","preview_dns_override","preview_scoped_service_control","preview_vpn_lifecycle"):
            mcp.remove_tool(name)
    return mcp


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Unofficial SSH-backed Firewalla MCP")
    parser.add_argument("--transport",choices=("stdio","streamable-http"),default="stdio")
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8000)
    parser.add_argument("--allow-write-catalog",action="store_true")
    args=parser.parse_args()
    path = os.environ.get("FIREWALLA_MCP_CONFIG", "/config/config.json")
    config = Config.model_validate_json(Path(path).read_text())
    if args.transport=="stdio":
        build_server(config).run(transport="stdio")
        return
    if not 1<=args.port<=65535:parser.error("invalid port")
    token_file=os.environ.get("FIREWALLA_MCP_HTTP_TOKEN_FILE")
    if not token_file:parser.error("FIREWALLA_MCP_HTTP_TOKEN_FILE required for HTTP")
    hosts=[v.strip() for v in os.environ.get("FIREWALLA_MCP_HTTP_ALLOWED_HOSTS", "").split(",") if v.strip()]
    if not hosts:
        if args.host not in ("127.0.0.1","localhost"):parser.error("Non-loopback bind requires explicit HTTP Host allowlist")
        hosts=["127.0.0.1:"+str(args.port),"localhost:"+str(args.port)]
    if args.allow_write_catalog and not config.writes_enabled:parser.error("Write catalog requires explicit writes_enabled=true")
    server=build_server(config,readonly_catalog=not args.allow_write_catalog)
    from .http import http_app
    import uvicorn
    uvicorn.run(http_app(server,token_file,hosts),host=args.host,port=args.port,access_log=False,log_level="warning")

if __name__ == "__main__":
    main()
