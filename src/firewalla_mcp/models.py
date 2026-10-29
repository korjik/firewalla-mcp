from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated
from pydantic import BaseModel, ConfigDict, Field, field_validator

Name = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", strict=True)]
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

class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sites: dict[Name, Site]
    writes_enabled: bool = False
    approval_directory: str | None = None
    audit_file: str | None = None

    def target(self, site: str, address: str):
        address = str(ip_address(address))
        if not any(ip_address(address) in ip_network(n) for n in self.sites[site].probe_networks):
            raise ValueError("target is outside configured probe networks")
        return address
