from firewalla_mcp.models import Config,Site
from firewalla_mcp.remote import MANAGEMENT_REVISION,VPN_MANAGEMENT_REVISIONS
from firewalla_mcp.support import configured_contracts


def test_revision_matrix_does_not_claim_live_availability():
    sites={str(i):Site(host='192.0.2.1',identity_file='/key',known_hosts_file='/known',vantage_group='a',management_revision=r) for i,r in enumerate([None,MANAGEMENT_REVISION,*VPN_MANAGEMENT_REVISIONS])}
    rows=configured_contracts(Config(sites=sites))
    assert rows['0']['vpn_lifecycle_and_device_switch']=='blocked_revision'
    assert rows['1']['device_app_dns_scoped_controls']=='legacy_contract_only'
    for i in range(2,len(sites)):
        assert rows[str(i)]['device_app_dns_scoped_controls']=='candidate_adblock_safeSearch_unbound_rules_dns'
        assert rows[str(i)]['persistent_vpn_forwarding']=='candidate'
        assert 'Configured revision only' in rows[str(i)]['evidence']
    assert all(r['permanent_routes']=='unsupported' for r in rows.values())
