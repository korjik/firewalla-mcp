"""Internal pinned SSH transport for the opt-in IPv6 policy-only adapter."""
import copy
from .forward_transport import LifecycleSSH
from .ipv6_adapter import IPv6Adapter


class IPv6SSH(LifecycleSSH):
    def __init__(self,site,template,owned):
        super().__init__(site,template)
        self.owned=IPv6Adapter(site.management_revision,template,owned).owned

    async def request(self,operation,arguments):
        return await super().request(operation,{**arguments,'ipv6_owned':copy.deepcopy(self.owned)})

    async def mutate(self,step,expected,expires_at):
        result=await self.request('mutate',{'step':step,'expected':expected,'expires_at':expires_at})
        record=result.get('allocated_instance')
        if record is not None:
            if record.get('key')!=step['key'] or step['after'] is None or record.get('value')!=step['after']['value']:
                raise ValueError('Unexpected IPv6 allocation scope')
            checked=IPv6Adapter(self.site.management_revision,self.template,self.owned)
            checked.add_owned(record);self.owned=checked.owned
        return result
