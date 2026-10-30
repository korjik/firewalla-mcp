"""Configured contract compatibility, never a substitute for live validation."""
from .remote import MANAGEMENT_REVISION, VPN_MANAGEMENT_REVISIONS


def configured_contracts(config):
    result = {}
    for name, site in config.sites.items():
        old = site.management_revision == MANAGEMENT_REVISION
        vpn = site.management_revision in VPN_MANAGEMENT_REVISIONS
        result[name] = {
            'evidence': 'Configured revision only; each preview must verify installed source, SSH permissions and state',
            'vpn_lifecycle_and_device_switch': 'candidate' if old or vpn else 'blocked_revision',
            'persistent_vpn_forwarding': 'candidate' if vpn else 'blocked_revision',
            'device_app_dns_scoped_controls': 'candidate_adblock_safeSearch_unbound_rules_dns' if vpn else 'legacy_contract_only' if old else 'blocked_revision',
            'doh_ntp_service_writes': 'legacy_contract_only' if old else 'blocked_revision',
            'permanent_routes': 'unsupported',
            'temporary_kernel_operations': 'requires_explicit_table_chain_scope',
        }
    return result
