import json
import os
from pathlib import Path
from typing import Literal
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import TypeAdapter
from .models import Config, Name, Port, Mac
from .transport import SSHTransport

READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def build_server(config: Config, transport=None):
    transport = transport or SSHTransport()
    mcp = FastMCP("Unofficial Firewalla diagnostics")

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

    return mcp


def main():
    path = os.environ.get("FIREWALLA_MCP_CONFIG", "/config/config.json")
    config = Config.model_validate_json(Path(path).read_text())
    build_server(config).run(transport="stdio")

if __name__ == "__main__":
    main()
