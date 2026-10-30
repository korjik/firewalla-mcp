"""Nonsecret instructions for the external authorized issuer; never issues approval."""
import shlex


def approval_guidance(config, plan=None):
    if config.vpn_confirmation_mode == 'host_confirmed':
        result = {'status':'host_confirmation_required', 'mechanism':'trusted_mcp_host',
                  'requires_exact_user_confirmation':True,
                  'instructions':[
                      'Show the exact action, box, resolved targets, expected prior state, settings and expiry from this preview.',
                      'The authenticated MCP host must obtain explicit user confirmation of this exact plan before calling apply. Do not substitute a model-generated consent assertion.',
                      'After confirmation call the indicated Firewalla MCP apply tool. SSH is internal to the server; do not use an external SSH connector or approval file.',
                      'Stop on host denial. Expired or changed plans require a fresh preview and confirmation; inspect uncertain outcomes before retrying.'],
                  'trust_boundary':'The server trusts the authenticated MCP host to enforce human confirmation. It does not independently verify human consent; annotations alone do not enforce it.'}
        if plan:result.update(plan_id=plan['plan_id'],digest=plan['digest'],expires_at=plan['expires_at'],
                              apply_tool=plan.get('apply_tool', 'apply_vpn_import' if 'transaction' in plan else 'apply_vpn_change'),
                              apply_arguments={'plan_id':plan['plan_id']})
        return result
    issuer = config.approval_issuer
    result = {
        'status': 'external_approval_required' if issuer else 'issuer_not_configured',
        'mechanism': 'authorized_ssh_issuer',
        'requires_exact_user_confirmation': True,
        'instructions': [
            'Show the exact preview action, box, resolved targets, expected state, settings and expiry.',
            'After explicit confirmation of this exact still-valid plan, use the authorized SSH tool to invoke the configured issuer. Reuse that confirmation; do not ask the owner to edit files.',
            'The SSH action must be authorized independently of MCP. Stop if denied or unavailable; never fabricate an approval file or treat a consent boolean as authority.',
            'After successful issuance, call the indicated Firewalla MCP apply tool with the same plan ID. Inspect uncertain outcomes before retrying. Changed or expired plans require a new preview and confirmation.',
        ],
        'trust_boundary': 'Authorized privileged SSH action; these instructions are not permission or an approval artifact.',
    }
    if issuer:
        result['ssh_host'] = issuer.ssh_host
    else:
        result['blocked_reason'] = 'Operator must configure the nonsecret issuer host and executable paths; do not guess deployment details.'
    if plan:
        result.update(plan_id=plan['plan_id'], digest=plan['digest'], expires_at=plan['expires_at'],
                      apply_tool=plan.get('apply_tool', 'apply_vpn_import' if 'transaction' in plan else 'apply_vpn_change'),
                      apply_arguments={'plan_id':plan['plan_id']})
        if issuer:
            argv=['sudo','-n',issuer.python,'-I',issuer.script,'--plan-id',plan['plan_id'],
                  '--digest',plan['digest'],'--expires-at',str(plan['expires_at'])]
            result['ssh_command']=shlex.join(argv)
    return result
