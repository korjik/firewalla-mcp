from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Name = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", strict=True)]
BoxName = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_. -]{0,63}$", strict=True)]
Port = Annotated[int, Field(ge=1, le=65535, strict=True)]
Mac = Annotated[str, Field(pattern=r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", strict=True)]

class Site(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    port: Port = 22
    user: Name = "pi"
    identity_file: str
    known_hosts_file: str
    probe_networks: list[str] = []
    allowed_route_tables: list[int] = []
    allowed_filter_chains: list[Name] = []
    allowed_nat_chains: list[Name] = []
    management_revision: str | None = None
    managed_scopes: list[str] = []
    managed_devices: list[Mac] = []
    managed_vpn_profiles: list[Name] = []
    vpn_import_sources: list[Name] = []
    vpn_import_archives: list[Name] = []
    vantage_group: Name

    @field_validator("host")
    @classmethod
    def literal_host(cls, value):
        return str(ip_address(value))

    @field_validator("identity_file", "known_hosts_file")
    @classmethod
    def absolute_file(cls, value):
        if not Path(value).is_absolute() or any(c in value for c in "\n\r\x00"):
            raise ValueError("absolute path required")
        return value

    @field_validator("probe_networks")
    @classmethod
    def networks(cls, value):
        return [str(ip_network(x)) for x in value]

class ForwardAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["tcp","udp"]
    external_port: Port
    destination_port: Port

class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sites: dict[Name, Site]
    aliases: dict[BoxName, Name] = {}

    @model_validator(mode="after")
    def valid_aliases(self):
        if any(v not in self.sites or k in self.sites for k,v in self.aliases.items()):
            raise ValueError("Alias must resolve to an existing box and not shadow one")
        return self

    def resolve(self, name):
        return self.aliases.get(name, name)
    write_confirmation_mode: Literal["host_confirmed"] | None = None
    capture_enabled: bool = False
    writes_enabled: bool = False
    vpn_writes_enabled: bool = False
    vpn_confirmation_mode: Literal["host_confirmed"] | None = None
    vpn_target_policy: Literal["allowlist", "approval_bound"] = "allowlist"
    approval_consumed_directory: str | None = None
    audit_file: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_approval(cls, value):
        if isinstance(value, dict):
            removed = {"approval_directory", "approval_issuer", "trusted_approval_uid"}
            if removed.intersection(value) or any(value.get(k) == "operator" for k in ("write_confirmation_mode", "vpn_confirmation_mode")):
                raise ValueError("File-based/operator approval was removed. Migrate explicitly to host_confirmed with a trusted MCP host and persistent execution ledger; remove legacy issuer/inbox fields. No automatic migration.")
            for flag, mode in (("writes_enabled", "write_confirmation_mode"), ("vpn_writes_enabled", "vpn_confirmation_mode")):
                if value.get(flag) is True and value.get(mode) != "host_confirmed":
                    raise ValueError("Writes require explicit host_confirmed opt-in; review the migration guide before enabling.")
        return value

    @model_validator(mode="after")
    def explicit_host_mode(self):
        if (self.writes_enabled and self.write_confirmation_mode != "host_confirmed") or (self.vpn_writes_enabled and self.vpn_confirmation_mode != "host_confirmed"):
            raise ValueError("Writes require explicit host_confirmed migration; no automatic trust-model switch")
        return self

    def target(self, site: str, address: str):
        site = self.resolve(site)
        address = str(ip_address(address))
        if not any(ip_address(address) in ip_network(n) for n in self.sites[site].probe_networks):
            raise ValueError("target is outside configured probe networks")
        return address
