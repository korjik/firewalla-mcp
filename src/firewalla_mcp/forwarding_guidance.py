"""Evidence levels for forwarding; presentation never substitutes for a probe."""

KINDS = {'managed_forward', 'managed_interface_forward', 'managed_forward_batch', 'dnat'}


def guidance(spec=None, result=None, *, phase='preview'):
    spec = spec or {}
    data = (result or {}).get('data', {})
    evidence = data.get('evidence', {})
    stored = 'not_checked'
    if phase == 'inventory':
        stored = 'configured_intent_only'
    elif phase == 'existing':
        stored = 'exact_enabled_mapping_observed'
    elif data.get('verification') == 'stored_mapping_verified':
        stored = {'rolled_back': 'removal_verified', 'applied': 'mapping_verified'}.get(data.get('outcome'), 'stored_state_verified')
    nat = evidence.get('nat_rule_observed')
    return {
        'operation_scope': 'temporary_kernel_nat_only' if spec.get('kind') == 'dnat' else 'persistent_nat_mapping_only',
        'service_ready': 'unknown',
        'verification_levels': {
            'stored_mapping': stored,
            'kernel_nat': 'observed' if nat is True else 'not_observed' if nat is False else 'not_checked',
            'firewall_allow_policy': 'not_evaluated_or_changed',
            'effective_packet_path': 'not_verified',
            'service_listener': 'not_tested',
            'independent_external_reachability': 'not_tested',
        },
        'prerequisites': [
            {'name': 'inbound_policy_permission', 'status': 'unknown',
             'action': 'Inspect applicable device/group/network/global rules and precedence. A separate narrowly scoped allow may be required; do not infer absence from one filtered page.'},
            {'name': 'listener_and_return_path', 'status': 'unknown',
             'action': 'Check the destination service, host firewall and reply routing.'},
        ],
        'next_steps': [
            'Report NAT configuration separately from firewall permission. A firewall allow does not create a NAT mapping, and a NAT mapping does not prove permission.',
            'If a policy change is needed, preview the exact inbound scope and obtain confirmation through a supported policy operation. This plan does not authorize or create that policy.',
            'Use an authorized independent external probe for a new connection; report its vantage and timestamp. A timeout alone does not identify the failed layer.',
        ],
        'completion_rule': 'An applied outcome means only the requested mapping operation was verified to its reported level; never describe the service as open or reachable without independent evidence.',
        'batch_note': 'For batches inspect each step evidence and partial outcome; no aggregate end-to-end success is implied.',
    }
