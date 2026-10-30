"""VPN-only capability boundary. No route/firewall/general management plans."""
from .writes import WriteManager


class VPNWriteManager(WriteManager):
    def __init__(self, config, transport):
        super().__init__(config.model_copy(update={"writes_enabled": config.vpn_writes_enabled}), transport)

    def apply_tool_name(self):
        return "apply_vpn_change"

    def host_confirmed(self):
        return self.config.vpn_confirmation_mode == "host_confirmed"

    def approval_bound_targets(self):
        return self.config.vpn_target_policy == "approval_bound"

    def validate(self, box_name, spec):
        if spec.get("kind") not in ("managed_lifecycle", "managed_vpn"):
            raise ValueError("Operation outside VPN-only capability")
        return super().validate(box_name, spec)

    async def preview(self, box, spec):
        return await super().preview(self.config.resolve(box), spec)
