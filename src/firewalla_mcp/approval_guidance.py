"""Instructions for exact confirmation by the trusted authenticated MCP host."""


def approval_guidance(config, plan=None):
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
